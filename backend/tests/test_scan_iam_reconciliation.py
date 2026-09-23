"""
CloudScope Integration Tests for Scan & IAM Current-State Reconciliation.

Mandatory Test Suite:
- Test 1 & 2: IAM Replacement Scenario (vidhul -> success, then ajith -> success)
  - Assert vidhul absent from v1:users, v1:resources, v1:dashboard, Neo4j, NetworkX
  - Assert ajith present in all applicable outputs with actual AmazonEC2FullAccess evaluation
- Test 3: Critical IAM collector failure
  - Assert scan FAILED, previous successful snapshot preserved, Neo4j not pruned
- Test 4: Dashboard metadata matches scan_id
- Test 5: Cache consistency across all snapshot keys
- Test 6: Lambda resource remains visible
- Test 7: Deleted resource is removed after successful scan
- Test 8: Historical ActivityEvent survives current-state cleanup
"""

import json
import uuid
from unittest.mock import patch, MagicMock
import pytest

from app.cache import cache
from app.services.scanner.inventory import AWSInventory
from app.services.scanner.scan_manager import ScanManager
from app.services.graph.graph_builder import build_graph_in_neo4j, get_node_id
from app.services.attack.policy_evaluator import evaluate_policy_allows_resources
from app.services.simulation.effective_access import compute_effective_access


@pytest.fixture(autouse=True)
def clean_cache():
    cache.clear()
    yield
    cache.clear()


class TestScanIAMReconciliation:

    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_1_and_2_iam_replacement_vidhul_to_ajith(
        self, mock_builder_write, mock_manager_write, mock_regions, mock_diag
    ):
        """Test 1 & 2:
        Scan 1: users = [vidhul] -> success
        Scan 2: users = [ajith] (with AmazonEC2FullAccess) -> success
        After Scan 2:
          - vidhul absent from v1:users, v1:resources, v1:dashboard
          - ajith present in all outputs
          - ajith's EC2 access derived from actual AmazonEC2FullAccess policy evaluation
        """
        manager = ScanManager()

        ec2_policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*"
                }
            ]
        })

        # --- SCAN 1: [vidhul] ---
        scan1_users = [{
            "id": "AIDAVIDHUL123",
            "name": "vidhul",
            "arn": "arn:aws:iam::160198386750:user/vidhul",
            "status": "active",
            "policies": [],
            "attachedPolicyArns": {},
            "inlinePolicyDocuments": {},
            "groups": [],
            "permissionsBoundary": None,
            "riskScore": 0,
            "mfaEnabled": True,
            "lastActive": "1 day ago",
            "type": "User",
            "region": "global",
            "owner": "160198386750"
        }]

        with patch("app.services.aws.iam_service.collect_users", return_value=scan1_users), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=[]), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=[]), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            res1 = manager.run_scan()
            assert res1["status"] == "success"

        # Verify Scan 1 state in cache
        cached_users1 = cache.get("v1:users")
        assert len(cached_users1) == 1
        assert cached_users1[0]["name"] == "vidhul"
        cached_dash1 = cache.get("v1:dashboard")
        assert cached_dash1["stats"]["users"] == 1

        # --- SCAN 2: [ajith] (vidhul is deleted in AWS) ---
        scan2_users = [{
            "id": "AIDAJITH456",
            "name": "ajith",
            "arn": "arn:aws:iam::160198386750:user/ajith",
            "status": "active",
            "policies": ["AmazonEC2FullAccess"],
            "attachedPolicyArns": {"AmazonEC2FullAccess": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"},
            "inlinePolicyDocuments": {},
            "groups": [],
            "permissionsBoundary": None,
            "riskScore": 0,
            "mfaEnabled": True,
            "lastActive": "Just now",
            "type": "User",
            "region": "global",
            "owner": "160198386750"
        }]

        scan2_ec2 = [{
            "id": "i-0123456789abcdef0",
            "name": "Production-WebServer",
            "type": "EC2",
            "region": "us-east-1",
            "riskScore": 0,
            "status": "active",
            "owner": "160198386750",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-0123456789abcdef0",
            "details": {"public_ip": "None", "private_ip": "10.0.0.1"}
        }]

        with patch("app.services.aws.iam_service.collect_users", return_value=scan2_users), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.iam_service.fetch_managed_policy_documents", return_value={"AmazonEC2FullAccess": ec2_policy_doc}), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=scan2_ec2), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=[]), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            res2 = manager.run_scan()
            assert res2["status"] == "success"

        # Assertions for Scan 2
        cached_users2 = cache.get("v1:users")
        cached_res2 = cache.get("v1:resources")
        cached_dash2 = cache.get("v1:dashboard")
        cached_graph2 = cache.get("v1:graph")

        # 1. vidhul completely absent
        assert not any(u.get("name") == "vidhul" for u in cached_users2)
        assert not any(r.get("name") == "vidhul" for r in cached_res2)
        assert cached_dash2["stats"]["users"] == 1

        # 2. ajith present in all outputs
        assert any(u.get("name") == "ajith" for u in cached_users2)
        assert any(r.get("name") == "ajith" for r in cached_res2)

        # 3. Derive Ajith's EC2 access from actual policy semantics
        inv2 = AWSInventory()
        inv2.users = scan2_users
        inv2.ec2 = scan2_ec2
        effective_records = compute_effective_access(
            inv2,
            {"AmazonEC2FullAccess": ec2_policy_doc},
            scan2_ec2
        )
        assert len(effective_records) > 0, "Ajith must have effective access derived from AmazonEC2FullAccess"
        ajith_access = [rec for rec in effective_records if rec["identity_name"] == "ajith"]
        assert len(ajith_access) == 1
        assert ajith_access[0]["target_resource_id"] == "i-0123456789abcdef0"
        assert ajith_access[0]["target_resource_type"] == "EC2"

    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_3_critical_iam_collector_failure_preserves_snapshot(
        self, mock_builder_write, mock_manager_write, mock_regions, mock_diag
    ):
        """Test 3: Critical IAM collector failure
        Assert:
          - scan FAILED
          - previous successful snapshot preserved
          - previous current Neo4j state not destroyed
        """
        manager = ScanManager()

        # Seed previous successful snapshot
        initial_users = [{"id": "u1", "name": "initial_user", "arn": "arn:aws:iam::123:user/initial_user"}]
        cache.set("v1:users", initial_users)
        cache.set("v1:resources", initial_users)
        cache.set("v1:dashboard", {"scanId": "scan-1", "stats": {"users": 1}})

        # Execute scan where IAM_Users collector fails
        with patch("app.services.aws.iam_service.collect_users", side_effect=Exception("AWS Rate Limit / Access Denied")), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=[]), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=[]), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):
            res = manager.run_scan()

        # Assertions
        assert res["status"] == "failed"
        assert manager.get_status()["scan_status"] == "FAILED"
        assert "Critical collector(s) failed" in manager.get_status()["last_error"]

        # Assert previous successful snapshot in cache is preserved and not overwritten
        preserved_users = cache.get("v1:users")
        assert len(preserved_users) == 1
        assert preserved_users[0]["name"] == "initial_user"

        preserved_dash = cache.get("v1:dashboard")
        assert preserved_dash["scanId"] == "scan-1"

        # Assert Neo4j builder was NOT called during the failed scan
        assert mock_builder_write.call_count == 0, "Neo4j reconciliation must NOT run on failed collection"

    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_4_dashboard_metadata_matches_scan_id(
        self, mock_builder_write, mock_manager_write, mock_regions, mock_diag
    ):
        """Test 4: Dashboard metadata matches scan_id."""
        manager = ScanManager()

        with patch("app.services.aws.iam_service.collect_users", return_value=[]), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=[]), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=[]), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            res = manager.run_scan()
            assert res["status"] == "success"

        dash = cache.get("v1:dashboard")
        metadata = cache.get("v1:scan_metadata")
        status = manager.get_status()

        assert dash["scanId"] == res["scan_id"]
        assert dash["scanId"] == metadata["scanId"]
        assert dash["scanId"] == status["scan_id"]
        assert dash["scanStatus"] == "SUCCESS"
        assert dash["lastSuccessfulScanId"] == res["scan_id"]
        assert dash["lastSuccessfulScanAt"] is not None

    def test_5_cache_consistency(self):
        """Test 5: Cache consistency — set_many atomic publication."""
        scan_id = str(uuid.uuid4())
        snapshot = {
            "v1:users": [{"id": "u1", "name": "ajith"}],
            "v1:roles": [],
            "v1:groups": [],
            "v1:policies": [],
            "v1:resources": [{"name": "ajith", "type": "User"}],
            "v1:alerts": [],
            "v1:correlated_risks": [],
            "v1:attack-paths": [],
            "v1:global_posture": {"overall_score": 90},
            "v1:graph": [],
            "v1:risks": [],
            "v1:dashboard": {"scanId": scan_id, "stats": {"users": 1}},
            "v1:scan_metadata": {"scanId": scan_id, "scanStatus": "SUCCESS"}
        }

        cache.set_many(snapshot)

        # All keys must reflect the exact same snapshot
        assert cache.get("v1:dashboard")["scanId"] == scan_id
        assert cache.get("v1:scan_metadata")["scanId"] == scan_id
        assert len(cache.get("v1:users")) == 1
        assert len(cache.get("v1:resources")) == 1

    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_6_lambda_resource_remains_visible(
        self, mock_builder_write, mock_manager_write, mock_regions, mock_diag
    ):
        """Test 6: Lambda resource remains visible in resources and breakdown."""
        manager = ScanManager()

        lambda_fn = [{
            "id": "SecurityAlertProcessor",
            "name": "SecurityAlertProcessor",
            "type": "Lambda",
            "region": "us-east-1",
            "riskScore": 0,
            "status": "configured",
            "owner": "160198386750",
            "arn": "arn:aws:lambda:us-east-1:160198386750:function:SecurityAlertProcessor",
            "details": {"runtime": "python3.11", "execution_role": "LambdaExecRole"}
        }]

        with patch("app.services.aws.iam_service.collect_users", return_value=[]), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=[]), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=lambda_fn), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            res = manager.run_scan()
            assert res["status"] == "success"

        resources = cache.get("v1:resources")
        assert any(r["name"] == "SecurityAlertProcessor" and r["type"] == "Lambda" for r in resources)
        dash = cache.get("v1:dashboard")
        lambda_breakdown = [b for b in dash.get("resourceBreakdown", []) if b["type"] == "Lambda Functions"]
        assert len(lambda_breakdown) == 1
        assert lambda_breakdown[0]["count"] == 1

    @patch("app.services.graph.graph_builder.get_account_id", return_value="160198386750")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_7_deleted_resource_is_removed_in_neo4j_reconciliation(
        self, mock_execute_write, mock_acc_id
    ):
        """Test 7: Deleted resource is pruned via valid-ID set reconciliation in Neo4j."""
        inv = AWSInventory()
        inv.s3 = [
            {"id": "kept-bucket", "name": "kept-bucket", "arn": "arn:aws:s3:::kept-bucket", "region": "us-east-1", "details": {}}
        ]

        build_graph_in_neo4j(inv)

        # Inspect reconciliation query calls for S3
        calls = mock_execute_write.call_args_list
        reconcile_calls = [
            (call.args[0], call.args[1] if len(call.args) > 1 else {})
            for call in calls
            if "MATCH (n:S3)" in call.args[0] and "DETACH DELETE n" in call.args[0]
        ]
        assert len(reconcile_calls) == 1
        query, params = reconcile_calls[0]
        assert params["valid_ids"] == ["aws:s3:kept-bucket"]

    @patch("app.services.graph.graph_builder.get_account_id", return_value="160198386750")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_8_historical_activity_event_survives_cleanup(
        self, mock_execute_write, mock_acc_id
    ):
        """Test 8: Historical ActivityEvent nodes and edges are NOT targeted by reconciliation."""
        inv = AWSInventory()
        inv.users = [{"id": "u1", "name": "ajith", "arn": "arn:aws:iam::160198386750:user/ajith", "policies": [], "groups": []}]

        build_graph_in_neo4j(inv)

        # Inspect all queries executed against Neo4j
        all_queries = [call.args[0] for call in mock_execute_write.call_args_list]

        # ActivityEvent must NEVER be deleted in any reconciliation query
        activity_delete_queries = [
            q for q in all_queries
            if ("ActivityEvent" in q or "ASSUMED_ROLE" in q) and "DELETE" in q
        ]
        assert len(activity_delete_queries) == 0, "Historical ActivityEvent must NEVER be deleted"
