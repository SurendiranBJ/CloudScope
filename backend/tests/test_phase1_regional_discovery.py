"""
Comprehensive Automated Unit Tests for Phase 1:
- Dynamic AWS region discovery
- Regional failure isolation (FAILED != EMPTY)
- Running-EC2 visibility and exact ID preservation
- Lambda regional discovery
- Failed-region data preservation and region-scoped reconciliation
- Scan observability (SUCCESS / PARTIAL / FAILED)
- API and graph integration
"""

import json
from unittest.mock import patch, MagicMock
import pytest

from app.config import settings
from app.services.aws.region_cache import (
    get_all_regions,
    clear_region_cache,
    set_scan_mode,
    get_scan_mode_state,
    get_resolved_scan_mode,
    RegionalCollectionResult
)
import app.services.aws.region_cache as region_cache_module
from app.services.aws.ec2_service import collect_ec2_instances, is_running_ec2
from app.services.aws.lambda_service import collect_lambda_functions
from app.services.scanner.inventory import AWSInventory
from app.services.scanner.scan_manager import ScanManager
from app.services.graph.graph_builder import build_graph_in_neo4j, get_node_id
from app.services.graph.graph_loader import build_local_graph
from app.cache import cache


@pytest.fixture(autouse=True)
def reset_region_cache_state(monkeypatch):
    region_cache_module._scan_mode = "auto"
    region_cache_module._selected_region = None
    clear_region_cache()
    yield
    region_cache_module._scan_mode = "auto"
    region_cache_module._selected_region = None
    clear_region_cache()


# 1. empty SCAN_REGIONS triggers dynamic DescribeRegions discovery
def test_1_empty_scan_regions_triggers_dynamic_discovery(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_REGIONS", "")
    mock_regions = ["us-east-1", "eu-west-1", "ap-south-1"]

    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": r} for r in mock_regions]
    }
    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_session.client.return_value = mock_ec2

    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        regions = get_all_regions()
        mode = get_resolved_scan_mode()

    assert mode == "global"
    assert set(regions) == set(mock_regions)
    assert mock_ec2.describe_regions.called


# 2. explicit SCAN_REGIONS overrides DescribeRegions discovery
def test_2_explicit_scan_regions_overrides_discovery(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_REGIONS", "ap-south-1, eu-north-1")

    mock_session = MagicMock()
    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        regions = get_all_regions()
        mode = get_resolved_scan_mode()

    assert mode == "configured"
    assert regions == ["ap-south-1", "eu-north-1"]
    # EC2 describe_regions should NOT be called when explicit configured regions exist
    assert not mock_session.client.called


# 3. runtime single-region mode works
def test_3_runtime_single_region_mode(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_REGIONS", "us-east-1,ap-south-1")
    set_scan_mode("single", "eu-central-1")

    regions = get_all_regions()
    mode = get_resolved_scan_mode()

    assert mode == "single"
    assert regions == ["eu-central-1"]


# 4. unusable/disabled regions are excluded
def test_4_unusable_disabled_regions_excluded(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_REGIONS", "")

    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "ap-south-1"},
            {"RegionName": "eu-north-1"},
        ]
    }
    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_session.client.return_value = mock_ec2

    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        get_all_regions()

    # Verify filter for opt-in-status was passed to DescribeRegions
    call_args = mock_ec2.describe_regions.call_args[1]
    assert "Filters" in call_args
    filters = call_args["Filters"]
    assert any(
        f.get("Name") == "opt-in-status" and "opt-in-not-required" in f.get("Values", [])
        for f in filters
    )


# 5. resolved regions are deterministic (e.g. sorted)
def test_5_resolved_regions_are_deterministic(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_REGIONS", "")
    unsorted_regions = ["us-west-2", "ap-south-1", "eu-north-1", "ca-central-1", "us-east-1"]

    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": r} for r in unsorted_regions]
    }
    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_session.client.return_value = mock_ec2

    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        regions = get_all_regions()

    assert regions == sorted(unsorted_regions)


# 6. DescribeRegions failure is surfaced correctly
def test_6_describe_regions_failure_falls_back_safety(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_REGIONS", "")

    mock_session = MagicMock()
    mock_session.region_name = "ap-south-1"
    mock_session.client.side_effect = Exception("AWS STS Token Expired")

    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        regions = get_all_regions()
        mode = get_resolved_scan_mode()

    assert regions == ["ap-south-1"]
    assert mode == "single"


# 7. regional collector returning zero resources produces SUCCESS_EMPTY
def test_7_regional_collector_zero_resources_produces_success_empty():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Reservations": []}]
    mock_client.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_client

    with patch("app.services.aws.ec2_service.get_account_id", return_value="123456789012"), \
         patch("app.services.aws.ec2_service.get_all_regions", return_value=["eu-north-1"]), \
         patch("app.services.aws.ec2_service.make_region_sessions", return_value={"eu-north-1": mock_session}):
        res = collect_ec2_instances()

    assert isinstance(res, RegionalCollectionResult)
    assert len(res.items) == 0
    assert res.regional_status.get("eu-north-1") == "SUCCESS_EMPTY"
    assert "eu-north-1" in res.successful_regions
    assert "eu-north-1" not in res.failed_regions


# 8. regional collector exception produces FAILED
def test_8_regional_collector_exception_produces_failed():
    mock_session = MagicMock()
    mock_session.client.side_effect = Exception("AuthFailure: AWS was not able to validate the provided access credentials")

    with patch("app.services.aws.ec2_service.get_account_id", return_value="123456789012"), \
         patch("app.services.aws.ec2_service.get_all_regions", return_value=["ap-south-1"]), \
         patch("app.services.aws.ec2_service.make_region_sessions", return_value={"ap-south-1": mock_session}):
        res = collect_ec2_instances()

    assert len(res.items) == 0
    assert "ap-south-1" in res.failed_regions
    assert res.regional_status["ap-south-1"].startswith("FAILED:")


# 9. FAILED is never converted to SUCCESS_EMPTY
def test_9_failed_is_never_converted_to_success_empty():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = Exception("AccessDenied: User is not authorized")
    mock_client.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_client

    with patch("app.services.aws.lambda_service.get_account_id", return_value="123456789012"), \
         patch("app.services.aws.lambda_service.get_all_regions", return_value=["eu-west-1"]), \
         patch("app.services.aws.lambda_service.make_region_sessions", return_value={"eu-west-1": mock_session}):
        res = collect_lambda_functions()

    assert res.regional_status["eu-west-1"].startswith("FAILED: AccessDenied")
    assert res.regional_status["eu-west-1"] != "SUCCESS_EMPTY"
    assert "eu-west-1" in res.failed_regions
    assert "eu-west-1" not in res.successful_regions


# 10. failed-region previous resources are preserved
def test_10_failed_region_previous_resources_preserved():
    sm = ScanManager()
    # Simulate previous scan having resources in eu-north-1
    prev_ec2 = [
        {"id": "i-prev1", "instance_id": "i-prev1", "name": "web-srv", "type": "EC2", "region": "eu-north-1", "state": "running", "status": "active", "arn": "arn:aws:ec2:eu-north-1:123:instance/i-prev1"}
    ]
    prev_lambda = [
        {"id": "fn-prev1", "name": "fn-prev1", "function_name": "fn-prev1", "type": "Lambda", "region": "eu-north-1", "arn": "arn:aws:lambda:eu-north-1:123:function:fn-prev1"}
    ]
    sm.inventory.ec2 = list(prev_ec2)
    sm.inventory.lambdas = list(prev_lambda)

    # In the current scan, eu-north-1 fails for EC2 and Lambda
    def mock_ec2_fail():
        return RegionalCollectionResult(
            items=[],
            regional_status={"eu-north-1": "FAILED: Timeout"},
            successful_regions=[],
            failed_regions=["eu-north-1"]
        )

    def mock_lambda_fail():
        return RegionalCollectionResult(
            items=[],
            regional_status={"eu-north-1": "FAILED: Timeout"},
            successful_regions=[],
            failed_regions=["eu-north-1"]
        )

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:user/scanner", "region": "us-east-1"}), \
         patch("app.services.scanner.scan_manager.get_all_regions", return_value=["eu-north-1"]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", side_effect=mock_ec2_fail), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", side_effect=mock_lambda_fail), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j"):
        result = sm.run_scan()

    assert result["scan_status"] == "PARTIAL"
    assert "eu-north-1" in result["failed_regions"]
    # Previous EC2 and Lambda resources must be preserved in inventory
    assert any(e["id"] == "i-prev1" for e in sm.inventory.ec2)
    assert any(l["name"] == "fn-prev1" for l in sm.inventory.lambdas)


# 11. successful-region old resources are reconciled
@patch("app.services.graph.graph_builder.execute_write")
@patch("app.services.graph.graph_builder.get_account_id", return_value="123456789012")
def test_11_successful_region_old_resources_reconciled(mock_acc_id, mock_execute_write):
    inv = AWSInventory()
    # Current scan found only i-new in us-east-1 (i-old was deleted in AWS)
    inv.ec2 = [
        {"id": "i-new", "instance_id": "i-new", "name": "new-srv", "type": "EC2", "region": "us-east-1", "state": "running", "arn": "arn:aws:ec2:us-east-1:123:instance/i-new"}
    ]

    build_graph_in_neo4j(inv, successful_regions=["us-east-1"])

    write_queries = [call.args[0] for call in mock_execute_write.call_args_list]
    write_params = [call.args[1] if len(call.args) > 1 else {} for call in mock_execute_write.call_args_list]

    # Verify reconciliation query for EC2 was executed targeting successful_regions
    ec2_prunes = [
        (q, p) for q, p in zip(write_queries, write_params)
        if "MATCH (n:EC2)" in q and "WHERE n.region IN $successful_regions" in q
    ]
    assert len(ec2_prunes) == 1
    query, params = ec2_prunes[0]
    assert params["successful_regions"] == ["us-east-1"]
    assert params["valid_ids"] == [get_node_id("EC2", "i-new")]


# 12. running EC2 appears
def test_12_running_ec2_appears():
    inst = {"state": "running", "status": "active"}
    assert is_running_ec2(inst) is True


# 13. stopped EC2 is excluded from security-view inventory
def test_13_stopped_ec2_excluded_from_security_view():
    inst = {"state": "stopped", "status": "stopped"}
    assert is_running_ec2(inst) is False


# 14. terminated EC2 is excluded from security-view inventory
def test_14_terminated_ec2_excluded_from_security_view():
    inst = {"state": "terminated", "status": "stopped"}
    assert is_running_ec2(inst) is False
    inst_stopping = {"state": "stopping", "status": "active"}
    assert is_running_ec2(inst_stopping) is False


# 15. EC2 uses exact instance ID
def test_15_ec2_uses_exact_instance_id():
    node_id = get_node_id("EC2", "i-0a1b2c3d4e5f")
    assert node_id == "aws:ec2:i-0a1b2c3d4e5f"


# 16. Lambda is discovered from every resolved region
def test_16_lambda_discovered_from_every_resolved_region():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Functions": [{
            "FunctionName": "process-order",
            "FunctionArn": "arn:aws:lambda:ap-south-1:123456789012:function:process-order",
            "Runtime": "python3.11",
            "Role": "arn:aws:iam::123456789012:role/OrderRole",
            "MemorySize": 256,
            "Timeout": 15,
            "Handler": "index.handler",
            "CodeSize": 1024,
            "LastModified": "2026-09-22T00:00:00.000+0000"
        }]
    }]
    mock_client.get_paginator.return_value = mock_paginator
    mock_client.list_tags.return_value = {"Tags": {}}
    mock_session.client.return_value = mock_client

    with patch("app.services.aws.lambda_service.get_account_id", return_value="123456789012"), \
         patch("app.services.aws.lambda_service.get_all_regions", return_value=["ap-south-1"]), \
         patch("app.services.aws.lambda_service.make_region_sessions", return_value={"ap-south-1": mock_session}):
        res = collect_lambda_functions()

    assert len(res.items) == 1
    fn = res.items[0]
    assert fn["function_name"] == "process-order"
    assert fn["function_arn"] == "arn:aws:lambda:ap-south-1:123456789012:function:process-order"
    assert fn["execution_role_name"] == "OrderRole"
    assert fn["runtime"] == "python3.11"
    assert fn["region"] == "ap-south-1"


# 17. Lambda regional failure is preserved as FAILED
def test_17_lambda_regional_failure_preserved_as_failed():
    mock_session = MagicMock()
    mock_session.client.side_effect = Exception("ThrottlingException: Rate exceeded")

    with patch("app.services.aws.lambda_service.get_account_id", return_value="123456789012"), \
         patch("app.services.aws.lambda_service.get_all_regions", return_value=["us-west-1"]), \
         patch("app.services.aws.lambda_service.make_region_sessions", return_value={"us-west-1": mock_session}):
        res = collect_lambda_functions()

    assert "us-west-1" in res.failed_regions
    assert res.regional_status["us-west-1"].startswith("FAILED: ThrottlingException")


# 18. overall scan becomes PARTIAL when appropriate
def test_18_overall_scan_becomes_partial_on_regional_failure():
    sm = ScanManager()
    def mock_ec2():
        return RegionalCollectionResult(
            items=[],
            regional_status={"eu-west-1": "FAILED: EndpointConnectionError"},
            successful_regions=[],
            failed_regions=["eu-west-1"]
        )

    with patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "123", "arn": "arn:aws:iam::123:user/scanner", "region": "us-east-1"}), \
         patch("app.services.scanner.scan_manager.get_all_regions", return_value=["eu-west-1"]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_users", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_groups", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_roles", return_value=[]), \
         patch("app.services.scanner.scan_manager.iam_service.collect_policies", return_value=[]), \
         patch("app.services.scanner.scan_manager.ec2_service.collect_ec2_instances", side_effect=mock_ec2), \
         patch("app.services.scanner.scan_manager.lambda_service.collect_lambda_functions", return_value=RegionalCollectionResult()), \
         patch("app.services.scanner.scan_manager.s3_service.collect_s3_buckets", return_value=[]), \
         patch("app.services.scanner.scan_manager.secrets_service.collect_secrets", return_value=[]), \
         patch("app.services.scanner.scan_manager.rds_service.collect_rds_instances", return_value=[]), \
         patch("app.services.scanner.scan_manager.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
         patch("app.services.scanner.scan_manager.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
         patch("app.services.scanner.scan_manager.cloudtrail_service.collect_recent_alerts", return_value=[]), \
         patch("app.services.scanner.scan_manager.graph_builder.build_graph_in_neo4j"):
        result = sm.run_scan()

    assert result["scan_status"] == "PARTIAL"
    assert sm.get_status()["scan_status"] == "PARTIAL"


# 19. failed_regions appear in scan status
def test_19_failed_regions_appear_in_scan_status():
    sm = ScanManager()
    sm._failed_regions = ["ap-northeast-1"]
    sm._successful_regions = ["us-east-1", "eu-west-1"]
    sm._scan_status = "PARTIAL"

    status = sm.get_status()
    assert "ap-northeast-1" in status["failed_regions"]
    assert "us-east-1" in status["successful_regions"]
    assert status["scan_status"] == "PARTIAL"


# 20. resources/graph APIs continue working with regional metadata
def test_20_graph_builder_and_local_graph_running_ec2_only():
    inv = AWSInventory()
    inv.ec2 = [
        {"id": "i-active", "instance_id": "i-active", "name": "ActiveEC2", "type": "EC2", "state": "running", "region": "ap-south-1", "arn": "arn:aws:ec2:ap-south-1:123:instance/i-active"},
        {"id": "i-stopped", "instance_id": "i-stopped", "name": "StoppedEC2", "type": "EC2", "state": "stopped", "region": "ap-south-1", "arn": "arn:aws:ec2:ap-south-1:123:instance/i-stopped"}
    ]
    inv.lambdas = [
        {"id": "fn1", "name": "fn1", "type": "Lambda", "region": "eu-north-1", "arn": "arn:aws:lambda:eu-north-1:123:function:fn1"}
    ]

    G = build_local_graph(inv)

    # Active EC2 should be present with stable ID
    assert G.has_node("aws:ec2:i-active")
    # Stopped EC2 must NOT be present in the security graph
    assert not G.has_node("aws:ec2:i-stopped")
    # Lambda should be present
    assert G.has_node("aws:lambda:fn1")
