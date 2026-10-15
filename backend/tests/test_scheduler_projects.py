from app.utils import scheduler


def test_startup_and_scheduled_runs_queue_connected_projects_serially(monkeypatch):
    projects = ["project-a", "project-b"]
    calls = []
    waited = []

    monkeypatch.setattr(scheduler, "_get_connected_project_ids", lambda: projects)
    monkeypatch.setattr(scheduler, "_wait_for_scan", lambda scan_id: waited.append(scan_id) or True)

    class Coordinator:
        def request_scan(self, **kwargs):
            calls.append(kwargs)
            return {"status": "STARTED", "scan_id": f"scan-{kwargs['project_id']}"}

    monkeypatch.setattr("app.services.scanner.scan_coordinator.scan_coordinator", Coordinator())
    scheduler._run_scheduled_scans("SCHEDULED")

    assert [call["project_id"] for call in calls] == projects
    assert [call["trigger_type"] for call in calls] == ["SCHEDULED", "SCHEDULED"]
    assert waited == ["scan-project-a", "scan-project-b"]


def test_scheduler_preserves_profile_scan_when_no_verified_projects(monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler, "_get_connected_project_ids", lambda: [])

    class Coordinator:
        def request_scan(self, **kwargs):
            calls.append(kwargs)
            return {"status": "STARTED", "scan_id": "profile-scan"}

    monkeypatch.setattr("app.services.scanner.scan_coordinator.scan_coordinator", Coordinator())
    scheduler._run_scheduled_scans("STARTUP")

    assert calls == [{
        "trigger_type": "STARTUP",
        "actor_id": "startup",
        "actor_role": "SYSTEM",
    }]


def test_scheduler_stops_project_queue_if_another_scan_is_already_running(monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler, "_get_connected_project_ids", lambda: ["project-a", "project-b"])

    class Coordinator:
        def request_scan(self, **kwargs):
            calls.append(kwargs)
            return {"status": "ALREADY_RUNNING", "scan_id": "active-scan"}

    monkeypatch.setattr("app.services.scanner.scan_coordinator.scan_coordinator", Coordinator())
    scheduler._run_scheduled_scans("SCHEDULED")

    assert len(calls) == 1
    assert calls[0]["project_id"] == "project-a"
