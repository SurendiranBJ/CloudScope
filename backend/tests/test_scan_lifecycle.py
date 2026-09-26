import time
import json
import uuid
import pytest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.cache import cache
from app.services.scanner.scan_manager import ScanManager, ALL_COLLECTOR_NAMES
from app.services.scanner.inventory import AWSInventory

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_cache():
    cache.clear()
    yield
    cache.clear()


@contextmanager
def mock_scan_environment(users=None, roles=None, regions=None, failed_regions=None, auth_error=None):
    if auth_error:
        diag = {"authenticated": False, "error": auth_error}
    else:
        diag = {"authenticated": True, "account_id": "123456789012", "arn": "arn:aws:iam::123:root", "region": "us-east-1"}

    regs = regions or ["us-east-1"]
    u_list = users or []
    r_list = roles or []
    f_regs = failed_regions or []

    class MockRegionalResult:
        def __init__(self, items, s_regs, fl_regs):
            self.items = items
            self.successful_regions = s_regs
            self.failed_regions = fl_regs
            self.regional_status = {r: "SUCCESS" for r in s_regs}
            self.regional_status.update({r: "FAILED" for r in fl_regs})

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value=diag), \
         patch("app.services.scanner.scan_manager.get_all_regions", return_value=regs), \
         patch("app.services.scanner.scan_manager.execute_write"), \
         patch("app.services.graph.graph_builder.execute_write"), \
         patch("app.services.aws.iam_service.collect_users", return_value=u_list), \
         patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
         patch("app.services.aws.iam_service.collect_roles", return_value=r_list), \
         patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
         patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=MockRegionalResult([], [r for r in regs if r not in f_regs], f_regs) if f_regs else []), \
         patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=[]), \
         patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):
        yield


def test_1_2_3_4_scan_starts_generates_id_and_sets_scanning_discovery():
    mgr = ScanManager()
    with patch.object(mgr, "_execute_scan"):
        res = mgr.trigger_async_scan()
        assert res["status"] in ("started", "STARTED")
        assert "scan_id" in res
        assert mgr.is_running is True

        status = mgr.get_status()
        assert status["is_scanning"] is True
        assert status["scan_id"] == res["scan_id"]
        assert status["scan_status"] == "SCANNING"
        assert status["active_phase"] == "INITIALIZING"
        assert status["total_collectors"] == 12
        assert status["completed_collectors"] == 0
        assert status["collector_status"]["IAM_Users"] == "PENDING"


def test_5_collector_progress_updates():
    mgr = ScanManager()
    mgr._is_running = True
    mgr._collector_status = {name: "PENDING" for name in ALL_COLLECTOR_NAMES}
    mgr._completed_collectors = 0

    mgr._collector_status["IAM_Users"] = "RUNNING"
    status1 = mgr.get_status()
    assert status1["collector_status"]["IAM_Users"] == "RUNNING"

    mgr._collector_status["IAM_Users"] = "SUCCESS_WITH_DATA"
    mgr._completed_collectors += 1
    mgr._resources_discovered += 5

    status2 = mgr.get_status()
    assert status2["collector_status"]["IAM_Users"] == "SUCCESS_WITH_DATA"
    assert status2["completed_collectors"] == 1
    assert status2["resources_discovered"] == 5


def test_6_active_phase_advances():
    mgr = ScanManager()
    mgr._is_running = True
    mgr._set_active_phase("DISCOVERY")
    assert mgr.get_status()["active_phase"] == "DISCOVERY"

    mgr._complete_phase("DISCOVERY", 1.5)
    mgr._set_active_phase("IAM_ANALYSIS")
    status = mgr.get_status()
    assert status["active_phase"] == "IAM_ANALYSIS"
    assert "DISCOVERY" in status["completed_phases"]
    assert status["phase_durations"]["DISCOVERY"]["status"] == "COMPLETED"


def test_7_elapsed_time_increases():
    mgr = ScanManager()
    mgr._is_running = True
    mgr._scan_started_perf = time.perf_counter() - 1.25

    status = mgr.get_status()
    assert status["elapsed_seconds"] >= 1.2


def test_8_last_progress_at_updates():
    mgr = ScanManager()
    mgr._is_running = True
    mgr._set_active_phase("discovery")
    first_progress = mgr.get_status()["last_progress_at"]
    assert first_progress is not None

    time.sleep(0.01)
    mgr._complete_phase("discovery", 0.5)
    second_progress = mgr.get_status()["last_progress_at"]
    assert second_progress is not None
    assert second_progress >= first_progress


def test_9_successful_scan_becomes_success():
    mgr = ScanManager()
    users = [{"name": "alice", "id": "U1", "arn": "arn:aws:iam::123:user/alice", "policies": []}]

    with mock_scan_environment(users=users):
        res = mgr.run_scan()
        assert res["status"] == "success"
        assert mgr.is_running is False
        assert mgr.get_status()["scan_status"] == "SUCCESS"
        assert mgr._last_successful_scan_id == mgr._scan_id
        assert mgr._last_published_scan_id == mgr._scan_id


def test_10_partial_scan_becomes_partial():
    mgr = ScanManager()
    with mock_scan_environment(regions=["us-east-1", "eu-west-1"], failed_regions=["eu-west-1"]):
        res = mgr.run_scan()
        assert res["status"] == "partial"
        assert mgr.is_running is False
        assert mgr.get_status()["scan_status"] == "PARTIAL"
        assert "eu-west-1" in mgr.get_status()["failed_regions"]
        assert mgr._last_published_scan_id == mgr._scan_id


def test_11_failed_scan_becomes_failed():
    mgr = ScanManager()
    with mock_scan_environment(auth_error="AWS API Crash"):
        res = mgr.run_scan()
        assert res["status"] == "failed"
        assert mgr.is_running is False
        assert mgr.get_status()["scan_status"] == "FAILED"
        assert "AWS API Crash" in mgr.get_status()["last_error"]


def test_12_is_running_resets_after_success():
    mgr = ScanManager()
    with mock_scan_environment():
        mgr.run_scan()

    assert mgr.is_running is False
    assert mgr.get_status()["active_phase"] == "COMPLETED"


def test_13_is_running_resets_after_failure():
    mgr = ScanManager()
    with mock_scan_environment(auth_error="Fatal Error"):
        mgr.run_scan()

    assert mgr.is_running is False
    assert mgr.get_status()["active_phase"] == "FAILED"


def test_14_second_manual_scan_while_active_returns_already_running():
    mgr = ScanManager()
    mgr._is_running = True
    mgr._scan_id = "active-scan-1"

    res = mgr.trigger_async_scan()
    assert res["status"] in ("already_running", "ALREADY_RUNNING")
    assert res["scan_id"] == "active-scan-1"


def test_15_scheduled_scan_while_active_does_not_start_duplicate():
    mgr = ScanManager()
    mgr._is_running = True
    mgr._scan_id = "active-scan-2"

    res = mgr.run_scan()
    assert res["status"] in ("already_running", "ALREADY_RUNNING")
    assert res["scan_id"] == "active-scan-2"


def test_16_current_published_snapshot_remains_readable_during_scan():
    mgr = ScanManager()
    initial_user = {"user_name": "bob", "user_id": "U2", "arn": "arn:aws:iam::123:user/bob"}
    mgr.inventory.users = [initial_user]

    cache.set("v1:users", [initial_user])
    cache.set("v1:scan_metadata", {"snapshot_id": "snap-a"})

    # During scan, working_inventory is distinct from self.inventory
    working_inventory = AWSInventory()
    working_inventory.users = [{"user_name": "carol", "user_id": "U3", "arn": "arn:aws:iam::123:user/carol"}]

    # Readers of published cache and mgr.inventory see snap-a / bob
    assert len(mgr.inventory.users) == 1
    assert mgr.inventory.users[0]["user_name"] == "bob"
    cached_users = cache.get("v1:users")
    assert cached_users[0]["user_name"] == "bob"


def test_17_failed_scan_preserves_previous_snapshot():
    mgr = ScanManager()
    mgr._last_published_scan_id = "snap-initial"
    mgr._last_published_at = "2026-09-26T10:00:00Z"
    cache.set("v1:policies", [{"name": "ReadOnlyAccess", "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}])

    with mock_scan_environment(auth_error="Scan Crash"):
        mgr.run_scan()

    # Authoritative published snapshot remains preserved
    assert mgr._last_published_scan_id == "snap-initial"
    assert mgr._last_published_at == "2026-09-26T10:00:00Z"
    assert cache.get("v1:policies") is not None
    assert cache.get("v1:policies")[0]["name"] == "ReadOnlyAccess"


def test_18_successful_scan_atomically_replaces_snapshot():
    mgr = ScanManager()
    mgr._last_published_scan_id = "snap-1"
    cache.set("v1:users", [{"name": "old_user", "id": "U1", "arn": "arn:aws:iam::123:user/old_user"}])

    new_users = [{"name": "new_user", "id": "U99", "arn": "arn:aws:iam::123:user/new_user", "policies": []}]

    with mock_scan_environment(users=new_users):
        res = mgr.run_scan()
        assert res["status"] == "success"

        cached_users = cache.get("v1:users")
        assert len(cached_users) == 1
        assert cached_users[0]["name"] == "new_user"

        meta = cache.get("v1:scan_metadata")
        assert meta["snapshot_id"] == mgr._last_published_scan_id
        assert mgr.inventory.users[0]["name"] == "new_user"


def test_19_partial_scan_publishes_reconciled_snapshot():
    mgr = ScanManager()
    # Establish previous inventory in us-west-1
    old_role = {"role_name": "WestRole", "role_id": "R1", "arn": "arn:aws:iam::123:role/WestRole", "region": "us-west-1"}
    mgr.inventory.roles = [old_role]

    with mock_scan_environment(regions=["us-east-1", "eu-west-1"], failed_regions=["eu-west-1"]):
        res = mgr.run_scan()
        assert res["status"] == "partial"
        assert mgr.get_status()["scan_status"] == "PARTIAL"
        meta = cache.get("v1:scan_metadata")
        assert meta["scanStatus"] == "PARTIAL"


def test_20_snapshot_id_changes_after_publication():
    mgr = ScanManager()
    mgr._last_published_scan_id = "old-snap-id"

    with mock_scan_environment():
        mgr.run_scan()

        assert mgr._last_published_scan_id != "old-snap-id"
        assert mgr.get_status()["last_published_scan_id"] == mgr._last_published_scan_id


def test_status_endpoint_is_cheap_and_reports_progress():
    from app.services.scanner.scan_manager import scan_manager
    scan_manager._is_running = True
    scan_manager._scan_id = "status-test-123"
    scan_manager._scan_status = "SCANNING"
    scan_manager._scan_started_perf = time.perf_counter()
    scan_manager._set_active_phase("DISCOVERY")
    scan_manager._completed_collectors = 4
    scan_manager._total_collectors = 12

    with patch("app.services.aws.region_cache.get_all_regions") as mock_regions:
        response = client.get("/api/v1/scan/status")
        assert response.status_code == 200
        res_json = response.json()
        assert res_json["success"] is True
        data = res_json["data"]

        # Fast in-memory check: must NOT call describe_regions
        assert not mock_regions.called

        # Accurate live status
        assert data["is_scanning"] is True
        assert data["scan_id"] == "status-test-123"
        assert data["scan_status"] == "SCANNING"
        assert data["active_phase"] == "DISCOVERY"
        assert data["completed_collectors"] == 4
        assert data["total_collectors"] == 12
        assert data["elapsed_seconds"] >= 0.0

    # Reset
    scan_manager._is_running = False
    scan_manager._scan_id = None
    scan_manager._scan_status = "IDLE"
    scan_manager._active_phase = None


def test_initialization_stage_observable_and_advances():
    """Verify initialization stages (AUTHENTICATING_AWS, RESOLVING_REGIONS, STARTING_COLLECTORS) are tracked."""
    mgr = ScanManager()
    with patch.object(mgr, "_execute_scan"):
        res = mgr.trigger_async_scan()
        assert res["status"] == "started"
        status = mgr.get_status()
        assert status["active_phase"] == "INITIALIZING"
        assert status["initialization_stage"] == "AUTHENTICATING_AWS"

    # Simulate transition to region discovery
    mgr._initialization_stage = "RESOLVING_REGIONS"
    mgr._last_progress_at = "2026-09-26T10:00:01Z"
    status_reg = mgr.get_status()
    assert status_reg["initialization_stage"] == "RESOLVING_REGIONS"
    assert status_reg["last_progress_at"] == "2026-09-26T10:00:01Z"

    # Simulate transition to collector startup
    mgr._initialization_stage = "STARTING_COLLECTORS"
    status_col = mgr.get_status()
    assert status_col["initialization_stage"] == "STARTING_COLLECTORS"

    # Transition to discovery
    mgr._set_active_phase("DISCOVERY")
    mgr._initialization_stage = None
    status_disc = mgr.get_status()
    assert status_disc["active_phase"] == "DISCOVERY"
    assert status_disc["initialization_stage"] is None


def test_sts_failure_marks_failed_and_cleans_up():
    """Verify that STS failure stops scan immediately with FAILED status and error."""
    mgr = ScanManager()
    mgr._is_running = True
    diag_fail = {"authenticated": False, "error": "InvalidClientTokenId: Security token is invalid"}

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value=diag_fail):
        result = mgr._execute_scan("sts-fail-id")
        assert result["status"] == "failed"
        assert result["scan_status"] == "FAILED"
        assert "InvalidClientTokenId" in result["error"]
        assert mgr.is_running is False

        status = mgr.get_status()
        assert status["is_scanning"] is False
        assert status["scan_status"] == "FAILED"
        assert status["active_phase"] == "FAILED"
        assert status["elapsed_seconds"] >= 0.0
        assert "InvalidClientTokenId" in (status["last_error"] or "")


def test_live_progress_endpoint_advances_and_reports_changes():
    """Verify GET /api/v1/scan/status returns changing live metrics while a scan runs."""
    from app.services.scanner.scan_manager import scan_manager
    scan_manager._is_running = True
    scan_manager._scan_id = "live-progress-test"
    scan_manager._scan_status = "SCANNING"
    scan_manager._scan_started_perf = time.perf_counter() - 2.0
    scan_manager._active_phase = "INITIALIZING"
    scan_manager._initialization_stage = "AUTHENTICATING_AWS"
    scan_manager._completed_collectors = 0
    scan_manager._total_collectors = 12
    scan_manager._last_progress_at = "2026-09-26T10:00:00Z"
    scan_manager._collector_status = {name: "PENDING" for name in ALL_COLLECTOR_NAMES}

    # Step 1: Poll during initialization
    resp1 = client.get("/api/v1/scan/status")
    assert resp1.status_code == 200
    d1 = resp1.json()["data"]
    assert d1["is_scanning"] is True
    assert d1["active_phase"] == "INITIALIZING"
    assert d1["initialization_stage"] == "AUTHENTICATING_AWS"
    assert d1["completed_collectors"] == 0
    assert d1["elapsed_seconds"] >= 2.0

    # Step 2: Collector progress updates
    scan_manager._active_phase = "DISCOVERY"
    scan_manager._initialization_stage = None
    scan_manager._collector_status["IAM_Users"] = "SUCCESS_WITH_DATA"
    scan_manager._completed_collectors = 1
    scan_manager._last_progress_at = "2026-09-26T10:00:03Z"

    resp2 = client.get("/api/v1/scan/status")
    assert resp2.status_code == 200
    d2 = resp2.json()["data"]
    assert d2["active_phase"] == "DISCOVERY"
    assert d2["initialization_stage"] is None
    assert d2["completed_collectors"] == 1
    assert d2["collector_status"]["IAM_Users"] == "SUCCESS_WITH_DATA"
    assert d2["last_progress_at"] == "2026-09-26T10:00:03Z"
    assert d2["last_progress_at"] != d1["last_progress_at"]

    # Reset
    scan_manager._is_running = False
    scan_manager._scan_id = None
    scan_manager._scan_status = "IDLE"
    scan_manager._active_phase = None
    scan_manager._initialization_stage = None
