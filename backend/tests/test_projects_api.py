from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


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
