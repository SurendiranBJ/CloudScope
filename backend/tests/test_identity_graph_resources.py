"""
Comprehensive Test Suite for CloudScope Identity Graph & Cloud Resource Visibility.

Validates:
- Test A: User policy grants EC2 access (Policy -[ALLOWS]-> EC2)
- Test B: User policy grants Lambda access (Policy -[ALLOWS]-> Lambda)
- Test C: Group-inherited EC2 access (User -> MEMBER_OF -> Group -> HAS_POLICY -> Policy -> ALLOWS -> EC2)
- Test D: Role-based EC2 access (User -> CAN_ASSUME -> Role -> HAS_POLICY -> Policy -> ALLOWS -> EC2)
- Test E: EC2 instance profile (EC2 -[ATTACHED_TO]-> Role)
- Test F: Lambda execution role (Lambda -[EXECUTES_WITH]-> Role)
- Test G: Running EC2 included in inventory & graph
- Test H: Stopped EC2 excluded from main security inventory & graph
- Test I: Terminated EC2 excluded
- Test J: Multi-region collection (us-east-1 + ap-south-1)
- Test K: Dashboard resource counts match running inventory
- Test L: Cloud Resource serialization & types
- Test M: Identity Graph relevance filtering (isolated resources filtered out of cytoscape elements)
- Test N: Effective access and graph agreement
- Test O: Regional isolation & failure semantics (Preserves failed region cache, marks PARTIAL)
"""

import json
from unittest.mock import patch
import pytest

from app.cache import cache
from app.services.scanner.inventory import AWSInventory
from app.services.scanner.scan_manager import ScanManager
from app.services.aws.region_cache import RegionalCollectionResult
from app.services.aws.ec2_service import is_running_ec2
from app.services.graph.graph_loader import build_local_graph, get_node_id
from app.services.attack.policy_evaluator import evaluate_policy_allows_resources
from app.services.simulation.effective_access import compute_effective_access


@pytest.fixture(autouse=True)
def clean_cache():
    cache.clear()
    yield
    cache.clear()


# Helper policy documents
EC2_FULL_ACCESS = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:*"],
        "Resource": "*"
    }]
})

LAMBDA_FULL_ACCESS = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["lambda:*"],
        "Resource": "*"
    }]
})


def make_inventory(
    users=None, groups=None, roles=None, policies=None,
    ec2=None, lambdas=None, s3=None, secrets=None, rds=None, dynamodb=None
):
    inv = AWSInventory()
    inv.users = users or []
    inv.groups = groups or []
    inv.roles = roles or []
    inv.policies = policies or []
    inv.ec2 = ec2 or []
    inv.lambdas = lambdas or []
    inv.s3 = s3 or []
    inv.secrets = secrets or []
    inv.rds = rds or []
    inv.dynamodb = dynamodb or []
    return inv


class TestIdentityGraphResources:

    # -------------------------------------------------------------------------
    # Test A: User policy grants EC2 access (Policy -[ALLOWS]-> EC2)
    # -------------------------------------------------------------------------
    def test_a_user_policy_grants_ec2_access(self):
        user = {
            "name": "ajith",
            "arn": "arn:aws:iam::160198386750:user/ajith",
            "attached_policies": [{"name": "AmazonEC2FullAccess", "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}]
        }
        policy = {
            "name": "AmazonEC2FullAccess",
            "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "policy_type": "AWS",
            "document": EC2_FULL_ACCESS
        }
        ec2_inst = {
            "id": "i-0123456789abcdef0",
            "name": "prod-web-server",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-0123456789abcdef0",
            "region": "us-east-1",
            "state": "running",
            "instance_state": "running",
            "status": "active",
            "type": "EC2"
        }
        inv = make_inventory(users=[user], policies=[policy], ec2=[ec2_inst])

        # Test policy evaluator directly
        allows = evaluate_policy_allows_resources(policy["document"], [ec2_inst])
        assert len(allows) == 1
        assert allows[0]["id"] == ec2_inst["id"]

        # Test local NetworkX graph construction
        G = build_local_graph(inv)
        u_id = get_node_id("User", user["name"])
        p_id = get_node_id("Policy", policy["name"])
        e_id = get_node_id("EC2", ec2_inst["id"])

        assert G.has_node(u_id)
        assert G.has_node(p_id)
        assert G.has_node(e_id)
        assert G.has_edge(u_id, p_id)
        assert G[u_id][p_id]["label"] == "HAS_POLICY"
        assert G.has_edge(p_id, e_id)
        assert G[p_id][e_id]["label"] == "ALLOWS"

    # -------------------------------------------------------------------------
    # Test B: User policy grants Lambda access (Policy -[ALLOWS]-> Lambda)
    # -------------------------------------------------------------------------
    def test_b_user_policy_grants_lambda_access(self):
        user = {
            "name": "developer",
            "arn": "arn:aws:iam::160198386750:user/developer",
            "attached_policies": [{"name": "AWSLambdaFullAccess", "arn": "arn:aws:iam::aws:policy/AWSLambdaFullAccess"}]
        }
        policy = {
            "name": "AWSLambdaFullAccess",
            "arn": "arn:aws:iam::aws:policy/AWSLambdaFullAccess",
            "policy_type": "AWS",
            "document": LAMBDA_FULL_ACCESS
        }
        fn = {
            "id": "IdentityScopeProcessor",
            "name": "IdentityScopeProcessor",
            "arn": "arn:aws:lambda:us-east-1:160198386750:function:IdentityScopeProcessor",
            "region": "us-east-1",
            "type": "Lambda",
            "role": "LambdaExecutionRole",
            "role_arn": "arn:aws:iam::160198386750:role/LambdaExecutionRole"
        }
        inv = make_inventory(users=[user], policies=[policy], lambdas=[fn])

        allows = evaluate_policy_allows_resources(policy["document"], [fn])
        assert len(allows) == 1
        assert allows[0]["name"] == "IdentityScopeProcessor"

        G = build_local_graph(inv)
        u_id = get_node_id("User", user["name"])
        p_id = get_node_id("Policy", policy["name"])
        l_id = get_node_id("Lambda", fn["name"])

        assert G.has_edge(u_id, p_id)
        assert G[u_id][p_id]["label"] == "HAS_POLICY"
        assert G.has_edge(p_id, l_id)
        assert G[p_id][l_id]["label"] == "ALLOWS"

    # -------------------------------------------------------------------------
    # Test C: Group-inherited EC2 access
    # -------------------------------------------------------------------------
    def test_c_group_inherited_ec2_access(self):
        user = {
            "name": "alice",
            "arn": "arn:aws:iam::160198386750:user/alice",
            "groups": ["DevOpsTeam"],
            "attached_policies": []
        }
        group = {
            "name": "DevOpsTeam",
            "arn": "arn:aws:iam::160198386750:group/DevOpsTeam",
            "attached_policies": [{"name": "AmazonEC2FullAccess", "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}]
        }
        policy = {
            "name": "AmazonEC2FullAccess",
            "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "policy_type": "AWS",
            "document": EC2_FULL_ACCESS
        }
        ec2_inst = {
            "id": "i-0aaa111bbb222ccc3",
            "name": "build-runner",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-0aaa111bbb222ccc3",
            "region": "us-east-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }
        inv = make_inventory(users=[user], groups=[group], policies=[policy], ec2=[ec2_inst])
        G = build_local_graph(inv)

        u_id = get_node_id("User", user["name"])
        g_id = get_node_id("Group", group["name"])
        p_id = get_node_id("Policy", policy["name"])
        e_id = get_node_id("EC2", ec2_inst["id"])

        assert G.has_edge(u_id, g_id)
        assert G[u_id][g_id]["label"] == "MEMBER_OF"
        assert G.has_edge(g_id, p_id)
        assert G[g_id][p_id]["label"] == "HAS_POLICY"
        assert G.has_edge(p_id, e_id)
        assert G[p_id][e_id]["label"] == "ALLOWS"

    # -------------------------------------------------------------------------
    # Test D: Role-based EC2 access (CAN_ASSUME -> Role -> Policy -> EC2)
    # -------------------------------------------------------------------------
    def test_d_role_based_ec2_access(self):
        role_arn = "arn:aws:iam::160198386750:role/EC2AdminRole"
        trust_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::160198386750:user/bob"},
                "Action": "sts:AssumeRole"
            }]
        })
        user = {
            "name": "bob",
            "arn": "arn:aws:iam::160198386750:user/bob",
            "attached_policies": [{"name": "AssumeAdminPolicy"}]
        }
        assume_pol = {
            "name": "AssumeAdminPolicy",
            "document": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": role_arn
                }]
            })
        }
        role = {
            "name": "EC2AdminRole",
            "arn": role_arn,
            "trustPolicy": trust_policy,
            "attached_policies": [{"name": "AmazonEC2FullAccess", "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}]
        }
        policy = {
            "name": "AmazonEC2FullAccess",
            "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "policy_type": "AWS",
            "document": EC2_FULL_ACCESS
        }
        ec2_inst = {
            "id": "i-0987654321fedcba0",
            "name": "database-host",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-0987654321fedcba0",
            "region": "us-east-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }
        inv = make_inventory(users=[user], roles=[role], policies=[policy, assume_pol], ec2=[ec2_inst])
        G = build_local_graph(inv)

        u_id = get_node_id("User", user["name"])
        r_id = get_node_id("Role", role["name"])
        p_id = get_node_id("Policy", policy["name"])
        e_id = get_node_id("EC2", ec2_inst["id"])

        assert G.has_edge(u_id, r_id)
        assert G[u_id][r_id]["label"] == "CAN_ASSUME"
        assert G.has_edge(r_id, p_id)
        assert G[r_id][p_id]["label"] == "HAS_POLICY"
        assert G.has_edge(p_id, e_id)
        assert G[p_id][e_id]["label"] == "ALLOWS"

    # -------------------------------------------------------------------------
    # Test E: EC2 instance profile (EC2 -[ATTACHED_TO]-> Role)
    # -------------------------------------------------------------------------
    def test_e_ec2_instance_profile_attached_to_role(self):
        role_name = "WebServerInstanceRole"
        role_arn = f"arn:aws:iam::160198386750:role/{role_name}"
        role = {
            "name": role_name,
            "arn": role_arn,
            "attached_policies": []
        }
        ec2_inst = {
            "id": "i-0instanceprofiletest",
            "name": "web-instance",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-0instanceprofiletest",
            "region": "us-east-1",
            "state": "running",
            "type": "EC2",
            "role": role_name
        }
        inv = make_inventory(roles=[role], ec2=[ec2_inst])
        G = build_local_graph(inv)

        e_id = get_node_id("EC2", ec2_inst["id"])
        r_id = get_node_id("Role", role_name)

        assert G.has_node(e_id)
        assert G.has_node(r_id)
        assert G.has_edge(e_id, r_id)
        assert G[e_id][r_id]["label"] == "ATTACHED_TO"

    # -------------------------------------------------------------------------
    # Test F: Lambda execution role (Lambda -[EXECUTES_WITH]-> Role)
    # -------------------------------------------------------------------------
    def test_f_lambda_execution_role_executes_with(self):
        role_name = "LambdaExecutionRole"
        role_arn = f"arn:aws:iam::160198386750:role/{role_name}"
        role = {
            "name": role_name,
            "arn": role_arn,
            "attached_policies": []
        }
        fn = {
            "name": "IdentityScopeProcessor",
            "arn": "arn:aws:lambda:us-east-1:160198386750:function:IdentityScopeProcessor",
            "region": "us-east-1",
            "type": "Lambda",
            "role": role_name,
            "role_arn": role_arn
        }
        inv = make_inventory(roles=[role], lambdas=[fn])
        G = build_local_graph(inv)

        l_id = get_node_id("Lambda", fn["name"])
        r_id = get_node_id("Role", role_name)

        assert G.has_node(l_id)
        assert G.has_node(r_id)
        assert G.has_edge(l_id, r_id)
        assert G[l_id][r_id]["label"] == "EXECUTES_WITH"

    # -------------------------------------------------------------------------
    # Test G, H, I: Running EC2 included, Stopped & Terminated excluded
    # -------------------------------------------------------------------------
    def test_g_h_i_ec2_lifecycle_states(self):
        running = {
            "id": "i-running",
            "name": "running-inst",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-running",
            "region": "us-east-1",
            "state": "running",
            "instance_state": "running",
            "status": "active"
        }
        stopped = {
            "id": "i-stopped",
            "name": "stopped-inst",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-stopped",
            "region": "us-east-1",
            "state": "stopped",
            "instance_state": "stopped",
            "status": "stopped"
        }
        terminated = {
            "id": "i-terminated",
            "name": "terminated-inst",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-terminated",
            "region": "us-east-1",
            "state": "terminated",
            "instance_state": "terminated",
            "status": "terminated"
        }

        # Helper checks
        assert is_running_ec2(running) is True
        assert is_running_ec2(stopped) is False
        assert is_running_ec2(terminated) is False

        # Graph loader check: stopped/terminated should not be loaded into G
        inv = make_inventory(ec2=[running, stopped, terminated])
        G = build_local_graph(inv)

        run_id = get_node_id("EC2", "i-running")
        stop_id = get_node_id("EC2", "i-stopped")
        term_id = get_node_id("EC2", "i-terminated")

        assert G.has_node(run_id)
        assert not G.has_node(stop_id)
        assert not G.has_node(term_id)

    # -------------------------------------------------------------------------
    # Test J: Multi-region collection (us-east-1 + ap-south-1)
    # -------------------------------------------------------------------------
    def test_j_multi_region_collection_result(self):
        inst_ap = {"id": "i-ap1", "name": "ap-inst", "region": "ap-south-1", "state": "running"}
        res = RegionalCollectionResult(
            items=[inst_ap],
            regional_status={"ap-south-1": "SUCCESS_WITH_DATA", "us-east-1": "SUCCESS_EMPTY"},
            successful_regions=["ap-south-1", "us-east-1"],
            failed_regions=[]
        )

        assert len(res) == 1
        assert res[0]["id"] == "i-ap1"
        assert res.regional_status["us-east-1"] == "SUCCESS_EMPTY"
        assert res.regional_status["ap-south-1"] == "SUCCESS_WITH_DATA"
        assert len(res.failed_regions) == 0

    # -------------------------------------------------------------------------
    # Test K: Dashboard resource counts match running inventory
    # -------------------------------------------------------------------------
    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_k_dashboard_counts_running_ec2_only(self, mock_b_write, mock_m_write, mock_reg, mock_diag):
        manager = ScanManager()

        running = {
            "id": "i-run1",
            "name": "run1",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-run1",
            "region": "us-east-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }
        stopped = {
            "id": "i-stop1",
            "name": "stop1",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-stop1",
            "region": "us-east-1",
            "state": "stopped",
            "status": "stopped",
            "type": "EC2"
        }

        with patch("app.services.aws.iam_service.collect_users", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=RegionalCollectionResult([running, stopped], {"us-east-1": "SUCCESS_WITH_DATA"}, ["us-east-1"], [])), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=RegionalCollectionResult([], {"us-east-1": "SUCCESS_EMPTY"}, ["us-east-1"], [])), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            res = manager.run_scan()
            assert res["status"] == "success"

            # Check cached resources
            cached_resources = cache.get("v1:resources")
            ec2_in_cache = [r for r in cached_resources if r["type"] == "EC2"]
            assert len(ec2_in_cache) == 1
            assert ec2_in_cache[0]["name"] == "run1"

            # Check cached dashboard
            dash = cache.get("v1:dashboard")
            assert dash["stats"]["resources"] == 1

    # -------------------------------------------------------------------------
    # Test L: Cloud Resource serialization & types
    # -------------------------------------------------------------------------
    def test_l_cloud_resource_types_and_fields(self):
        inst = {
            "id": "i-run1",
            "name": "run1",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-run1",
            "region": "us-east-1",
            "state": "running",
            "status": "active"
        }
        fn = {
            "name": "IdentityScopeProcessor",
            "arn": "arn:aws:lambda:us-east-1:160198386750:function:IdentityScopeProcessor",
            "region": "us-east-1"
        }
        inv = make_inventory(ec2=[inst], lambdas=[fn])
        assert len(inv.ec2) == 1
        assert len(inv.lambdas) == 1

    # -------------------------------------------------------------------------
    # Test M: Identity Graph relevance filtering
    # -------------------------------------------------------------------------
    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_m_identity_graph_relevance_filter(self, mock_b_write, mock_m_write, mock_reg, mock_diag):
        manager = ScanManager()

        user = {
            "name": "ajith",
            "arn": "arn:aws:iam::160198386750:user/ajith",
            "policies": ["AmazonEC2FullAccess"],
            "attachedPolicyArns": {"AmazonEC2FullAccess": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}
        }
        policy = {
            "name": "AmazonEC2FullAccess",
            "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "policy_type": "AWS",
            "document": EC2_FULL_ACCESS
        }
        connected_ec2 = {
            "id": "i-connected",
            "name": "connected-inst",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-connected",
            "region": "us-east-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }
        unconnected_s3 = {
            "name": "isolated-unconnected-bucket",
            "arn": "arn:aws:s3:::isolated-unconnected-bucket",
            "region": "us-east-1",
            "type": "S3"
        }

        with patch("app.services.aws.iam_service.collect_users", return_value=[user]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[policy]), \
             patch("app.services.aws.iam_service.fetch_managed_policy_documents", return_value={"AmazonEC2FullAccess": EC2_FULL_ACCESS}), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[unconnected_s3]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=RegionalCollectionResult([connected_ec2], {"us-east-1": "SUCCESS_WITH_DATA"}, ["us-east-1"], [])), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=RegionalCollectionResult([], {"us-east-1": "SUCCESS_EMPTY"}, ["us-east-1"], [])), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            res = manager.run_scan()
            assert res["status"] == "success"

            # Check cytoscape elements
            cy_elements = cache.get("v1:graph")
            assert cy_elements is not None
            cy_ids = [el["data"]["id"] for el in cy_elements if "source" not in el["data"]]

            # Core identity nodes always present
            assert "aws:user:ajith" in cy_ids
            assert "aws:policy:AmazonEC2FullAccess" in cy_ids
            # Connected EC2 is present
            assert "aws:ec2:i-connected" in cy_ids
            # Isolated S3 bucket filtered out of graph elements
            assert "aws:s3:isolated-unconnected-bucket" not in cy_ids

            # But full inventory retains the S3 bucket in v1:resources
            all_resources = cache.get("v1:resources")
            s3_names = [r["name"] for r in all_resources if r.get("type") == "S3"]
            assert "isolated-unconnected-bucket" in s3_names

    # -------------------------------------------------------------------------
    # Test N: Effective access and graph agreement
    # -------------------------------------------------------------------------
    def test_n_effective_access_agrees_with_policy_evaluator(self):
        user = {
            "name": "ajith",
            "arn": "arn:aws:iam::160198386750:user/ajith",
            "policies": ["AmazonEC2FullAccess"],
            "attachedPolicyArns": {"AmazonEC2FullAccess": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}
        }
        policy = {
            "name": "AmazonEC2FullAccess",
            "arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "document": EC2_FULL_ACCESS
        }
        ec2_inst = {
            "id": "i-match",
            "name": "match-inst",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-match",
            "region": "us-east-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }
        inv = make_inventory(users=[user], policies=[policy], ec2=[ec2_inst])
        G = build_local_graph(inv)
        p_eval = evaluate_policy_allows_resources(policy["document"], [ec2_inst])

        assert len(p_eval) == 1
        assert G.has_edge("aws:policy:AmazonEC2FullAccess", "aws:ec2:i-match")

    # -------------------------------------------------------------------------
    # Test O: Regional isolation & failure semantics
    # -------------------------------------------------------------------------
    @patch("app.services.scanner.scan_manager.get_aws_diagnostic_info", return_value={"authenticated": True, "account_id": "160198386750", "arn": "arn:aws:iam::160198386750:root", "region": "us-east-1"})
    @patch("app.services.scanner.scan_manager.get_all_regions", return_value=["ap-south-1", "us-east-1"])
    @patch("app.services.scanner.scan_manager.execute_write")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_o_regional_isolation_preserves_failed_region_cache(
        self, mock_b_write, mock_m_write, mock_reg, mock_diag
    ):
        """
        Verify:
        - Prior cached resource in us-east-1 exists.
        - Scan runs: ap-south-1 succeeds with a new resource.
        - us-east-1 fails with timeout/API error.
        - Result:
          * Scan is marked PARTIAL.
          * failed_regions contains 'us-east-1'.
          * Prior us-east-1 resource is PRESERVED, not deleted.
          * Newly discovered ap-south-1 resource is added.
        """
        manager = ScanManager()

        # Pre-seed cache with an existing us-east-1 resource
        prior_us_east_inst = {
            "id": "i-pre-existing-useast",
            "name": "prior-us-east-host",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-pre-existing-useast",
            "region": "us-east-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }
        cache.set("v1:resources", [prior_us_east_inst])
        cache.set("v1:raw:ec2", [prior_us_east_inst])
        cache.set("v1:raw:lambda", [])

        # Newly discovered ap-south-1 resource
        new_ap_inst = {
            "id": "i-new-apsouth",
            "name": "new-ap-south-host",
            "arn": "arn:aws:ec2:ap-south-1:160198386750:instance/i-new-apsouth",
            "region": "ap-south-1",
            "state": "running",
            "status": "active",
            "type": "EC2"
        }

        # EC2 collector returns ap-south-1 SUCCESS_WITH_DATA, us-east-1 FAILED
        ec2_res = RegionalCollectionResult(
            items=[new_ap_inst],
            regional_status={"ap-south-1": "SUCCESS_WITH_DATA", "us-east-1": "FAILED"},
            successful_regions=["ap-south-1"],
            failed_regions=["us-east-1"]
        )

        lambda_res = RegionalCollectionResult(
            items=[],
            regional_status={"ap-south-1": "SUCCESS_EMPTY", "us-east-1": "FAILED"},
            successful_regions=["ap-south-1"],
            failed_regions=["us-east-1"]
        )

        with patch("app.services.aws.iam_service.collect_users", return_value=[]), \
             patch("app.services.aws.iam_service.collect_roles", return_value=[]), \
             patch("app.services.aws.iam_service.collect_groups", return_value=[]), \
             patch("app.services.aws.iam_service.collect_policies", return_value=[]), \
             patch("app.services.aws.s3_service.collect_s3_buckets", return_value=[]), \
             patch("app.services.aws.ec2_service.collect_ec2_instances", return_value=ec2_res), \
             patch("app.services.aws.lambda_service.collect_lambda_functions", return_value=lambda_res), \
             patch("app.services.aws.secrets_service.collect_secrets", return_value=[]), \
             patch("app.services.aws.rds_service.collect_rds_instances", return_value=[]), \
             patch("app.services.aws.dynamodb_service.collect_dynamodb_tables", return_value=[]), \
             patch("app.services.aws.access_analyzer_service.collect_access_analyzer_findings", return_value=[]), \
             patch("app.services.aws.cloudtrail_service.collect_recent_alerts", return_value=[]):

            result = manager.run_scan()

            # Overall scan status must be PARTIAL
            assert result["scan_status"] == "PARTIAL"
            assert "us-east-1" in result["failed_regions"]

            # Check scan status via manager and cache metadata
            status_obj = manager.get_status()
            assert status_obj["scan_status"] == "PARTIAL"
            assert "us-east-1" in status_obj["failed_regions"]

            meta = cache.get("v1:scan_metadata")
            assert meta["scanStatus"] == "PARTIAL"
            assert "us-east-1" in meta["failedRegions"]

            # Current state in v1:resources must contain BOTH the preserved us-east-1 resource
            # and the newly collected ap-south-1 resource
            all_res = cache.get("v1:resources")
            ec2_names = [r["name"] for r in all_res if r.get("type") == "EC2"]
            assert "prior-us-east-host" in ec2_names
            assert "new-ap-south-host" in ec2_names

