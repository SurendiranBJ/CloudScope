from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from app.config import settings
from app.main import app
from app.services.aws import session as aws_session
from app.services.scanner.snapshot_store import snapshot_store
from app.services.project_context import set_project_id, reset_project_id


settings.DEV_AUTH_MODE = True


def client(role="ADMINISTRATOR", subject="projects-test-owner"):
    return TestClient(app, headers={"X-Dev-Role": role, "X-Dev-Subject": subject})


def test_project_create_list_archive_and_owner_isolation():
    owner = client(subject="projects-owner-a")
    other = client(subject="projects-owner-b")
    payload = {
        "name": "Production account",
        "description": "Primary AWS environment",
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/CloudScopeReadOnly",
    }

    created = owner.post("/api/v1/projects", json=payload)
    assert created.status_code == 201
    project = created.json()["data"]
    assert project["name"] == payload["name"]
    assert project["account_id"] == payload["account_id"]

    assert owner.get("/api/v1/projects").json()["data"][0]["project_id"] == project["project_id"]
    assert other.get("/api/v1/projects").json()["data"] == []
    assert other.delete(f"/api/v1/projects/{project['project_id']}").status_code == 404

    duplicate = owner.post("/api/v1/projects", json=payload)
    assert duplicate.status_code == 409
    assert owner.patch(f"/api/v1/projects/{project['project_id']}", json={"account_id": "999999999999"}).status_code == 422

    archived = owner.delete(f"/api/v1/projects/{project['project_id']}")
    assert archived.status_code == 200
    assert owner.get("/api/v1/projects").json()["data"] == []
    # Archived account IDs can be registered again.
    assert owner.post("/api/v1/projects", json=payload).status_code == 201


def test_project_validation_and_admin_only_mutation():
    admin = client(subject="projects-validation")
    viewer = client(role="VIEWER", subject="projects-viewer")
    # CloudScope's shared request-validation contract maps validation failures to 400.
    assert admin.post("/api/v1/projects", json={"name": "Invalid", "account_id": "123"}).status_code == 400
    assert viewer.post("/api/v1/projects", json={"name": "Not allowed"}).status_code == 403


def test_project_role_verification_uses_external_id_and_stores_no_credentials(monkeypatch):
    admin = client(subject="projects-role-check")
    created = admin.post("/api/v1/projects", json={
        "name": "Verified account",
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/CloudScopeReadOnly",
    }).json()["data"]

    source_sts = MagicMock()
    source_sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "temporary-access-key",
        "SecretAccessKey": "temporary-secret-key",
        "SessionToken": "temporary-session-token",
    }}
    target_sts = MagicMock()
    target_sts.get_caller_identity.return_value = {
        "Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/CloudScopeReadOnly/verify",
    }
    source_session = MagicMock()
    source_session.client.return_value = source_sts
    target_session = MagicMock()
    target_session.client.return_value = target_sts
    monkeypatch.setattr(aws_session, "get_aws_session", lambda: source_session)
    monkeypatch.setattr(aws_session, "get_boto_config", lambda **kwargs: None)
    monkeypatch.setattr("boto3.Session", lambda **kwargs: target_session)

    checked = admin.post(f"/api/v1/projects/{created['project_id']}/verify")
    assert checked.status_code == 200
    result = checked.json()["data"]
    assert result["connected"] is True
    assert result["verification_status"] == "CONNECTED"
    assert result["verified_account_id"] == "123456789012"
    assert result["external_id"] == created["external_id"]
    source_sts.assume_role.assert_called_once()
    assert source_sts.assume_role.call_args.kwargs["ExternalId"] == created["external_id"]
    assert "AccessKeyId" not in result and "SecretAccessKey" not in result and "SessionToken" not in result

    target_sts.get_caller_identity.return_value = {"Account": "999999999999", "Arn": "arn:aws:sts::999999999999:assumed-role/wrong"}
    mismatch = admin.post(f"/api/v1/projects/{created['project_id']}/verify").json()["data"]
    assert mismatch["connected"] is False
    assert mismatch["verification_status"] == "FAILED"


def test_project_scope_never_falls_back_to_global_graph_snapshot():
    admin = client(subject="project-snapshot-isolation")
    first = admin.post("/api/v1/projects", json={"name": "First account", "account_id": "111111111111"}).json()["data"]
    second = admin.post("/api/v1/projects", json={"name": "Second account", "account_id": "222222222222"}).json()["data"]
    snapshot_store.publish(
        snapshot_id="legacy-global-marker",
        status="SUCCESS",
        graph=[{"data": {"id": "global-only-resource"}}],
    )
    token = set_project_id(first["project_id"])
    try:
        snapshot_store.publish("first-account-snapshot", "SUCCESS", graph=[{"data": {"id": "first-account-resource"}}])
    finally:
        reset_project_id(token)
    token = set_project_id(second["project_id"])
    try:
        snapshot_store.publish("second-account-snapshot", "SUCCESS", graph=[{"data": {"id": "second-account-resource"}}])
    finally:
        reset_project_id(token)

    scoped = admin.get("/api/v1/graph", headers={"X-CloudScope-Project": first["project_id"]})
    assert scoped.status_code == 200
    assert [item["data"]["id"] for item in scoped.json()["data"]] == ["first-account-resource"]

    second_scoped = admin.get("/api/v1/graph", headers={"X-CloudScope-Project": second["project_id"]})
    assert [item["data"]["id"] for item in second_scoped.json()["data"]] == ["second-account-resource"]

    missing_selection = admin.get("/api/v1/graph")
    assert missing_selection.status_code == 409


def test_simulation_drafts_persist_and_are_isolated_by_project():
    admin = client(subject="project-simulation-drafts")
    first = admin.post("/api/v1/projects", json={"name": "Simulation first", "account_id": "333333333333"}).json()["data"]
    second = admin.post("/api/v1/projects", json={"name": "Simulation second", "account_id": "444444444444"}).json()["data"]
    headers_first = {"X-CloudScope-Project": first["project_id"]}
    headers_second = {"X-CloudScope-Project": second["project_id"]}
    payload = {
        "action": "ATTACH_POLICY",
        "principal_type": "ROLE",
        "principal_id": "ApplicationRole",
        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
    }

    added = admin.post("/api/v1/simulation/changes", json=payload, headers=headers_first)
    assert added.status_code == 200
    change_id = added.json()["data"]["change_id"]
    # A fresh API request reads the durable draft, and another selected project cannot see it.
    first_state = admin.get("/api/v1/simulation/state", headers=headers_first).json()["data"]
    second_state = admin.get("/api/v1/simulation/state", headers=headers_second).json()["data"]
    assert [change["change_id"] for change in first_state["changes"]] == [change_id]
    assert second_state["changes"] == []

    removed = admin.delete(f"/api/v1/simulation/changes/{change_id}", headers=headers_first)
    assert removed.status_code == 200


def test_project_scan_is_blocked_until_role_verification_succeeds():
    admin = client(subject="project-scan-readiness")
    project = admin.post("/api/v1/projects", json={
        "name": "Unverified account",
        "account_id": "333333333333",
        "role_arn": "arn:aws:iam::333333333333:role/CloudScopeReadOnly",
    }).json()["data"]

    response = admin.post("/api/v1/scan", headers={"X-CloudScope-Project": project["project_id"]})
    assert response.status_code == 503
    assert "Verify" in response.json()["detail"]
