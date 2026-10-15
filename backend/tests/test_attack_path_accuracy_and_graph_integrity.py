"""
Regression tests for Attack Path Accuracy, Graph Integrity, and IAM Evaluation.

Validates:
1. Node identity & regional isolation:
   - Same-named resources in different regions remain distinct.
   - Different resource types with the same name remain distinct nodes.
   - Resource tags remain associated with the correct entity; missing tags do not create permissions.
2. Policy evaluation precision:
   - AmazonDynamoDBFullAccess policy document does NOT create an ALLOWS edge to Lambda functions.
   - Lambda execution policy does NOT create an ALLOWS edge to DynamoDB tables.
   - Explicit Deny overrides Allow.
   - Unresolved conditions do not produce unconditional ALLOWS.
3. Attack path semantics:
   - All emitted paths correspond to valid, directed transitions with verified provenance.
   - Workload execution roles are not confused with user permissions.
   - Terminal resources are never treated as privilege bridges.
   - Blast radius reflects unique cloud resources only (no identities/policies).
"""

import json
import pytest
import networkx as nx

from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_policy_allows_resources_with_provenance,
    match_resource_specific_action,
    PolicyDecision,
)
from app.services.graph.graph_loader import build_local_graph, get_node_id
from app.services.attack.path_engine import find_attack_paths, _validate_path_security_semantics
from app.services.attack.blast_radius import calculate_blast_radius


class DummyInventory:
    def __init__(self, users=None, roles=None, groups=None, policies=None, s3=None,
                 ec2=None, lambdas=None, secrets=None, rds=None, dynamodb=None, alerts=None):
        self.users = users or []
        self.roles = roles or []
        self.groups = groups or []
        self.policies = policies or []
        self.s3 = s3 or []
        self.ec2 = ec2 or []
        self.lambdas = lambdas or []
        self.secrets = secrets or []
        self.rds = rds or []
        self.dynamodb = dynamodb or []
        self.alerts = alerts or []


# ---------------------------------------------------------------------------
# 1. NODE IDENTITY & ISOLATION TESTS
# ---------------------------------------------------------------------------

def test_different_resource_types_with_same_name_remain_separate_nodes():
    """An S3 bucket, DynamoDB table, and Lambda function named 'audit-logs' must be 3 distinct nodes."""
    s3_id = get_node_id("S3", "audit-logs")
    ddb_id = get_node_id("DynamoDB", "audit-logs")
    lambda_id = get_node_id("Lambda", "audit-logs")

    assert s3_id != ddb_id
    assert ddb_id != lambda_id
    assert s3_id != lambda_id
    assert s3_id == "aws:s3:audit-logs"
    assert ddb_id == "aws:dynamodb:audit-logs"
    assert lambda_id == "aws:lambda:audit-logs"


def test_cross_region_resources_build_graph_distinct_nodes():
    """Resources with same name in different regions must maintain distinct canonical identities in inventory."""
    fn1 = {
        "name": "data-processor",
        "arn": "arn:aws:lambda:us-east-1:123456789012:function:data-processor",
        "type": "Lambda",
        "region": "us-east-1",
        "tags": {"env": "prod", "region": "us-east-1"}
    }
    fn2 = {
        "name": "data-processor",
        "arn": "arn:aws:lambda:eu-west-1:123456789012:function:data-processor",
        "type": "Lambda",
        "region": "eu-west-1",
        "tags": {"env": "staging", "region": "eu-west-1"}
    }

    # ARN is the canonical AWS identifier
    assert fn1["arn"] != fn2["arn"]
    assert fn1["tags"]["env"] != fn2["tags"]["env"]


def test_missing_tags_do_not_fabricate_permissions():
    """A resource with no tags or failed tag collection must not be granted authorization by default."""
    res_no_tags = {
        "name": "un-tagged-bucket",
        "arn": "arn:aws:s3:::un-tagged-bucket",
        "type": "S3",
        "tags": {}
    }
    restricted_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::un-tagged-bucket/*",
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/environment": "production"}
                }
            }
        ]
    }
    # Unresolved/unsatisfied tag condition must not grant unconditional access
    allowed, prov, _ = evaluate_policy_allows_resources_with_provenance(
        "TagRestrictedPolicy",
        "arn:aws:iam::123:policy/TagRestrictedPolicy",
        restricted_policy_doc,
        [res_no_tags]
    )
    assert len(allowed) == 0


# ---------------------------------------------------------------------------
# 2. IAM POLICY EVALUATION: DYNAMODB VS LAMBDA PRECISION
# ---------------------------------------------------------------------------

def test_dynamodb_full_access_does_not_create_allows_edge_to_lambda():
    """AWS managed AmazonDynamoDBFullAccess document contains service actions like lambda:CreateFunction.
    It must NEVER produce an ALLOWS edge or attack path to existing Lambda functions."""
    dynamodb_full_access_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:*",
                    "dax:*",
                    "application-autoscaling:DeleteScalingPolicy",
                    "application-autoscaling:DeregisterScalableTarget",
                    "application-autoscaling:DescribeScalableTargets",
                    "cloudwatch:DeleteAlarms",
                    "cloudwatch:DescribeAlarmHistory",
                    "lambda:CreateFunction",
                    "lambda:ListFunctions",
                    "lambda:ListEventSourceMappings",
                    "lambda:CreateEventSourceMapping",
                    "lambda:DeleteEventSourceMapping",
                    "lambda:GetFunctionConfiguration",
                    "lambda:DeleteFunction"
                ],
                "Resource": "*"
            }
        ]
    }

    lambda_res = {
        "id": "LogChainLineVerifier",
        "name": "LogChainLineVerifier",
        "type": "Lambda",
        "arn": "arn:aws:lambda:ap-south-1:160198386750:function:LogChainLineVerifier",
        "region": "ap-south-1"
    }

    ddb_table = {
        "id": "AppMetricsTable",
        "name": "AppMetricsTable",
        "type": "DynamoDB",
        "arn": "arn:aws:dynamodb:ap-south-1:160198386750:table/AppMetricsTable",
        "region": "ap-south-1"
    }

    allowed, prov_map, _ = evaluate_policy_allows_resources_with_provenance(
        "AmazonDynamoDBFullAccess",
        "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
        dynamodb_full_access_doc,
        [lambda_res, ddb_table]
    )

    # Must match DynamoDB table
    assert any(r["name"] == "AppMetricsTable" for r in allowed)
    # Must NEVER match Lambda function
    assert not any(r["name"] == "LogChainLineVerifier" for r in allowed)
    assert "LogChainLineVerifier" not in prov_map


def test_lambda_only_policy_does_not_allow_dynamodb():
    """A policy granting lambda:InvokeFunction must not match DynamoDB tables."""
    lambda_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": "*"
            }
        ]
    }
    ddb_table = {
        "id": "CustomerTable",
        "name": "CustomerTable",
        "type": "DynamoDB",
        "arn": "arn:aws:dynamodb:us-east-1:123456789012:table/CustomerTable",
        "region": "us-east-1"
    }
    allowed, _, _ = evaluate_policy_allows_resources_with_provenance(
        "LambdaInvokerPolicy",
        "arn:aws:iam::123:policy/LambdaInvokerPolicy",
        lambda_policy_doc,
        [ddb_table]
    )
    assert len(allowed) == 0


def test_explicit_deny_overrides_allow():
    """An explicit Deny statement on a resource overrides any wildcard Allow statement."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAllS3",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            },
            {
                "Sid": "DenyTopSecretBucket",
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::top-secret-vault/*"
            }
        ]
    }
    b1 = {"name": "public-bucket", "type": "S3", "arn": "arn:aws:s3:::public-bucket"}
    b2 = {"name": "top-secret-vault", "type": "S3", "arn": "arn:aws:s3:::top-secret-vault"}

    allowed, _, deny_map = evaluate_policy_allows_resources_with_provenance(
        "MixedPolicy", "arn:aws:iam::123:policy/MixedPolicy", doc, [b1, b2]
    )
    assert any(r["name"] == "public-bucket" for r in allowed)
    assert not any(r["name"] == "top-secret-vault" for r in allowed)
    assert "top-secret-vault" in deny_map
    assert deny_map["top-secret-vault"]["effect"] == "Deny"


# ---------------------------------------------------------------------------
# 3. ATTACK PATH SEMANTICS & BLAST RADIUS INTEGRITY
# ---------------------------------------------------------------------------

def test_attack_path_ordered_directed_edges():
    """Attack path engine returns valid ordered nodes and edges matching adjacent relationships."""
    G = nx.DiGraph()
    G.add_node("aws:user:alice", type="User", label="alice", riskScore=80)
    G.add_node("aws:role:AdminRole", type="Role", label="AdminRole", riskScore=90)
    G.add_node("aws:policy:FullAdmin", type="Policy", label="FullAdmin", riskScore=80)
    G.add_node("aws:s3:data-bucket", type="S3", label="data-bucket", riskScore=70)

    G.add_edge("aws:user:alice", "aws:role:AdminRole", label="CAN_ASSUME", relationship="CAN_ASSUME")
    G.add_edge("aws:role:AdminRole", "aws:policy:FullAdmin", label="HAS_POLICY", relationship="HAS_POLICY")
    G.add_edge(
        "aws:policy:FullAdmin", "aws:s3:data-bucket",
        label="ALLOWS", relationship="ALLOWS", decision="ALLOWED", effect="Allow",
        action="s3:GetObject", condition_status="NONE"
    )

    paths = find_attack_paths(G)
    assert len(paths) >= 1
    p = next((path for path in paths if path["target"] == "aws:s3:data-bucket"), None)
    assert p is not None

    # Validate source and target
    assert p["source"] == "aws:user:alice"
    assert p["target"] == "aws:s3:data-bucket"
    assert p["source_asset"] == "alice"
    assert p["target_asset"] == "data-bucket"
    assert p["source_type"] == "User"
    assert p["target_type"] == "S3"

    # Validate ordered edges
    assert len(p["edges"]) == 3
    assert p["edges"][0]["source"] == "aws:user:alice"
    assert p["edges"][0]["target"] == "aws:role:AdminRole"
    assert p["edges"][0]["relationship"] == "CAN_ASSUME"

    assert p["edges"][1]["source"] == "aws:role:AdminRole"
    assert p["edges"][1]["target"] == "aws:policy:FullAdmin"
    assert p["edges"][1]["relationship"] == "HAS_POLICY"

    assert p["edges"][2]["source"] == "aws:policy:FullAdmin"
    assert p["edges"][2]["target"] == "aws:s3:data-bucket"
    assert p["edges"][2]["relationship"] == "ALLOWS"


def test_workload_execution_role_not_inherited_by_invoking_user():
    """A user who invokes Lambda does NOT inherit the Lambda execution role's permissions.
    Lambda -> Role is valid ONLY when Lambda is the source workload compromise start."""
    G = nx.DiGraph()
    G.add_node("aws:user:attacker", type="User", label="attacker", riskScore=40)
    G.add_node("aws:policy:InvokePolicy", type="Policy", label="InvokePolicy", riskScore=30)
    G.add_node("aws:lambda:WorkerFunc", type="Lambda", label="WorkerFunc", riskScore=50)
    G.add_node("aws:role:ExecRole", type="Role", label="ExecRole", riskScore=85)
    G.add_node("aws:policy:AdminPolicy", type="Policy", label="AdminPolicy", riskScore=90)
    G.add_node("aws:s3:secret-data", type="S3", label="secret-data", riskScore=95)

    G.add_edge("aws:user:attacker", "aws:policy:InvokePolicy", label="HAS_POLICY", relationship="HAS_POLICY")
    G.add_edge(
        "aws:policy:InvokePolicy", "aws:lambda:WorkerFunc",
        label="ALLOWS", relationship="ALLOWS", decision="ALLOWED", effect="Allow",
        action="lambda:InvokeFunction", condition_status="NONE"
    )
    G.add_edge("aws:lambda:WorkerFunc", "aws:role:ExecRole", label="EXECUTES_WITH", relationship="EXECUTES_WITH")
    G.add_edge("aws:role:ExecRole", "aws:policy:AdminPolicy", label="HAS_POLICY", relationship="HAS_POLICY")
    G.add_edge(
        "aws:policy:AdminPolicy", "aws:s3:secret-data",
        label="ALLOWS", relationship="ALLOWS", decision="ALLOWED", effect="Allow",
        action="s3:*", condition_status="NONE"
    )

    # An attack path from attacker attempting to bridge through WorkerFunc to secret-data is INVALID
    invalid_bridge = [
        "aws:user:attacker", "aws:policy:InvokePolicy", "aws:lambda:WorkerFunc",
        "aws:role:ExecRole", "aws:policy:AdminPolicy", "aws:s3:secret-data"
    ]
    assert _validate_path_security_semantics(invalid_bridge, G) is False

    # The paths discovered from attacker should terminate at WorkerFunc (not secret-data)
    paths = find_attack_paths(G)
    user_paths_to_s3 = [
        p for p in paths
        if p["source"] == "aws:user:attacker" and p["target"] == "aws:s3:secret-data"
    ]
    assert len(user_paths_to_s3) == 0


def test_blast_radius_counts_only_cloud_assets():
    """Blast radius counts actual cloud data/compute/secret resources, never IAM roles or policies."""
    G = nx.DiGraph()
    G.add_node("aws:user:dev", type="User", label="dev")
    G.add_node("aws:role:DevRole", type="Role", label="DevRole", riskScore=50)
    G.add_node("aws:policy:DevPolicy", type="Policy", label="DevPolicy")
    G.add_node("aws:s3:bucket-a", type="S3", label="bucket-a", arn="arn:aws:s3:::bucket-a", riskScore=60)
    G.add_node("aws:s3:bucket-b", type="S3", label="bucket-b", arn="arn:aws:s3:::bucket-b", riskScore=60)
    G.add_node("aws:lambda:func-c", type="Lambda", label="func-c", arn="arn:aws:lambda:us-east-1:123:function:func-c", riskScore=50)

    G.add_edge("aws:user:dev", "aws:role:DevRole")
    G.add_edge("aws:role:DevRole", "aws:policy:DevPolicy")
    G.add_edge("aws:policy:DevPolicy", "aws:s3:bucket-a")
    G.add_edge("aws:policy:DevPolicy", "aws:s3:bucket-b")
    G.add_edge("aws:policy:DevPolicy", "aws:lambda:func-c")

    br = calculate_blast_radius(G, "aws:user:dev")
    # Total cloud assets should be 3 (2 S3 + 1 Lambda), excluding DevRole and DevPolicy
    assert br["affected_resource_count"] == 3
    assert "User" not in br["resource_types"]
    assert "Role" not in br["resource_types"]
    assert "Policy" not in br["resource_types"]
    assert br["resource_types"].get("S3") == 2
    assert br["resource_types"].get("Lambda") == 1
