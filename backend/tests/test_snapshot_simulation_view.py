from unittest.mock import patch

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services.scanner.inventory import AWSInventory
from app.services.scanner.snapshot_store import snapshot_store


client = TestClient(app)


def test_historical_snapshot_allows_read_only_simulation_preview(monkeypatch):
    monkeypatch.setattr(settings, "DEV_AUTH_MODE", True)
    snapshot_id = "snapshot-what-if-test"
    snapshot_store.publish(
        snapshot_id=snapshot_id,
        status="SUCCESS",
        users=[{"name": "sample-user", "policies": []}],
        resources=[],
    )
    headers = {
        "X-CloudScope-Snapshot-ID": snapshot_id,
        "X-Dev-Role": "ADMINISTRATOR",
        "X-Dev-Subject": "snapshot-test-user",
    }
    inventory = AWSInventory()
    mocked_analysis = {
        "simulation_active": True,
        "summary": "Historical snapshot preview",
        "new_reachable_resources": [],
        "removed_reachable_resources": [],
    }
    with patch("app.routers.simulation._get_current_inventory", return_value=inventory), \
         patch("app.routers.simulation.get_current_attack_paths", return_value=[]), \
         patch("app.routers.simulation.get_current_dashboard", return_value={"globalPosture": {}}), \
         patch("app.routers.simulation.build_policy_preview_analysis", return_value=mocked_analysis), \
         patch("app.routers.simulation.audit_service.log"):
        response = client.post(
            "/api/v1/simulation/preview",
            headers=headers,
            json={"action": "ATTACH_POLICY", "principal_type": "USER", "principal_id": "sample-user", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        )

    assert response.status_code == 200
    assert response.json()["data"]["summary"] == "Historical snapshot preview"


def test_historical_snapshot_still_blocks_saved_simulation_writes(monkeypatch):
    monkeypatch.setattr(settings, "DEV_AUTH_MODE", True)
    snapshot_id = "snapshot-read-only-test"
    snapshot_store.publish(snapshot_id=snapshot_id, status="SUCCESS", users=[{"name": "sample-user"}])
    response = client.post(
        "/api/v1/simulation/changes",
        headers={
            "X-CloudScope-Snapshot-ID": snapshot_id,
            "X-Dev-Role": "ADMINISTRATOR",
            "X-Dev-Subject": "snapshot-test-user",
        },
        json={"action": "ATTACH_POLICY", "principal_type": "USER", "principal_id": "sample-user", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    )

    assert response.status_code == 409
    assert "read-only" in response.json()["detail"].lower()
