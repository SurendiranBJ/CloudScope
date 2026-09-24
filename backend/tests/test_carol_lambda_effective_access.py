"""
Regression test for IAM effective access correctness in Identity Graph.

Validates:
1. carol-no-mfa with only lambda:InvokeFunction on FirstLambda:
   - Carol -> FirstLambda is PRESENT with relationship CAN_INVOKE.
   - Carol -> arbitrary S3 bucket is ABSENT.
   - Carol -> arbitrary RDS is ABSENT.
   - Carol -> arbitrary EC2 is ABSENT.
   - Carol -> arbitrary Secret is ABSENT.
2. Distinct intermediate security relationships:
   - FirstLambda -> LambdaExecutionRole is PRESENT (EXECUTES_WITH).
   - LambdaExecutionRole -> S3 bucket is PRESENT (EFFECTIVE_ACCESS).
   - Role permissions are NOT collapsed into direct User -> S3 access.
3. Edge provenance retention:
   - sourceId, targetId, relationshipType, decision, actions, policies, statementSids, evidence.
4. Principals with legitimate direct S3 permissions (e.g. alice-s3-user) still have valid access.
5. AWSLambda_FullAccess does NOT grant access to EC2 instances despite EC2 describe actions.
"""

import json
import pytest
from unittest.mock import MagicMock

from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_policy_allows_resources_with_provenance,
    classify_resource_relationship,
)
from app.services.simulation.effective_access import compute_effective_access
from app.services.graph.graph_loader import build_local_graph


@pytest.fixture
def mock_inventory():
    """Create isolated inventory for testing Carol and related resources."""
    inv = MagicMock()
    
    # 1. Carol: User with ONLY lambda:InvokeFunction on FirstLambda
    carol_policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowInvokeFirstLambda",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": "arn:aws:lambda:us-east-1:160198386750:function:FirstLambda"
            }
        ]
    })
    
    # 2. Alice: User with legitimate S3 Read access
    alice_s3_policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3ReadBucket",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::production-data-bucket",
                    "arn:aws:s3:::production-data-bucket/*"
                ]
            }
        ]
    })

    # 3. LambdaExecutionRole: Role executed by FirstLambda with S3 Full Access
    lambda_role_s3_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3FullAccess",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    })

    inv.users = [
        {
            "name": "carol-no-mfa",
            "arn": "arn:aws:iam::160198386750:user/carol-no-mfa",
            "type": "User",
            "policies": ["CarolLambdaInvokePolicy"],
            "groups": [],
            "attachedPolicyArns": {
                "CarolLambdaInvokePolicy": "arn:aws:iam::160198386750:policy/CarolLambdaInvokePolicy"
            },
            "inlinePolicyDocuments": {}
        },
        {
            "name": "alice-s3-user",
            "arn": "arn:aws:iam::160198386750:user/alice-s3-user",
            "type": "User",
            "policies": ["AliceS3ReadPolicy"],
            "groups": [],
            "attachedPolicyArns": {
                "AliceS3ReadPolicy": "arn:aws:iam::160198386750:policy/AliceS3ReadPolicy"
            },
            "inlinePolicyDocuments": {}
        }
    ]

    inv.groups = []

    inv.roles = [
        {
            "name": "LambdaExecutionRole",
            "arn": "arn:aws:iam::160198386750:role/LambdaExecutionRole",
            "type": "Role",
            "policies": ["LambdaExecutionRoleS3Policy"],
            "attachedPolicies": ["LambdaExecutionRoleS3Policy"],
            "attachedPolicyArns": {
                "LambdaExecutionRoleS3Policy": "arn:aws:iam::160198386750:policy/LambdaExecutionRoleS3Policy"
            },
            "trustPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }),
            "inlinePolicyDocuments": {}
        }
    ]

    inv.policies = [
        {
            "name": "CarolLambdaInvokePolicy",
            "arn": "arn:aws:iam::160198386750:policy/CarolLambdaInvokePolicy",
            "document": carol_policy_doc
        },
        {
            "name": "AliceS3ReadPolicy",
            "arn": "arn:aws:iam::160198386750:policy/AliceS3ReadPolicy",
            "document": alice_s3_policy_doc
        },
        {
            "name": "LambdaExecutionRoleS3Policy",
            "arn": "arn:aws:iam::160198386750:policy/LambdaExecutionRoleS3Policy",
            "document": lambda_role_s3_doc
        }
    ]

    inv.lambdas = [
        {
            "name": "FirstLambda",
            "arn": "arn:aws:lambda:us-east-1:160198386750:function:FirstLambda",
            "type": "Lambda",
            "region": "us-east-1",
            "role": "LambdaExecutionRole",
            "details": {
                "execution_role": "LambdaExecutionRole"
            }
        }
    ]

    inv.s3 = [
        {
            "id": "production-data-bucket",
            "name": "production-data-bucket",
            "arn": "arn:aws:s3:::production-data-bucket",
            "type": "S3",
            "region": "us-east-1"
        },
        {
            "id": "confidential-financial-bucket",
            "name": "confidential-financial-bucket",
            "arn": "arn:aws:s3:::confidential-financial-bucket",
            "type": "S3",
            "region": "us-east-1"
        }
    ]

    inv.ec2 = [
        {
            "id": "i-0987654321fedcba0",
            "name": "app-server-ec2",
            "arn": "arn:aws:ec2:us-east-1:160198386750:instance/i-0987654321fedcba0",
            "type": "EC2",
            "state": "running",
            "region": "us-east-1",
            "details": {}
        }
    ]

    inv.rds = [
        {
            "id": "prod-customer-db",
            "name": "prod-customer-db",
            "arn": "arn:aws:rds:us-east-1:160198386750:db:prod-customer-db",
            "type": "RDS",
            "region": "us-east-1"
        }
    ]

    inv.secrets = [
        {
            "id": "db-master-credentials",
            "name": "db-master-credentials",
            "arn": "arn:aws:secretsmanager:us-east-1:160198386750:secret:db-master-credentials-ab12",
            "type": "Secrets",
            "region": "us-east-1"
        }
    ]

    inv.dynamodb = []
    return inv


def test_carol_lambda_effective_access_no_false_s3_edges(mock_inventory):
    """Carol with lambda:InvokeFunction on FirstLambda must only access FirstLambda, never S3/RDS/EC2/Secret."""
    inv = mock_inventory
    policy_doc_map = {p["name"]: p["document"] for p in inv.policies}
    all_res = inv.s3 + inv.ec2 + inv.rds + inv.secrets + inv.lambdas

    effective_access = compute_effective_access(inv, policy_doc_map, all_res)

    # 1. Carol's access records
    carol_records = [r for r in effective_access if r["identity_name"] == "carol-no-mfa"]
    carol_targets = [(r["target_resource_type"], r["target_resource_name"]) for r in carol_records]

    # EXPECTED: Carol -> FirstLambda
    assert ("Lambda", "FirstLambda") in carol_targets, "Carol must have effective access to FirstLambda"
    assert len(carol_records) == 1, f"Carol must only access FirstLambda, got: {carol_targets}"

    # NOT EXPECTED: Carol must NOT have direct access to S3, RDS, EC2, or Secret
    for r in carol_records:
        assert r["target_resource_type"] != "S3", f"False S3 effective access detected for Carol: {r}"
        assert r["target_resource_type"] != "RDS", f"False RDS effective access detected for Carol: {r}"
        assert r["target_resource_type"] != "EC2", f"False EC2 effective access detected for Carol: {r}"
        assert r["target_resource_type"] != "Secrets", f"False Secret effective access detected for Carol: {r}"

    # 2. Check provenance on Carol's record
    carol_first_lambda = next(r for r in carol_records if r["target_resource_name"] == "FirstLambda")
    ev = carol_first_lambda["evidence"]
    assert ev["decision"] in ("ALLOW", "ALLOWED")
    assert ev["matched_action"] == "lambda:InvokeFunction"
    assert ev["relationship_type"] == "CAN_INVOKE"
    assert ev["statement_sid"] == "AllowInvokeFirstLambda"
    assert "AllowInvokeFirstLambda" in ev["reason"]


def test_role_based_access_preserved_and_not_collapsed_to_carol(mock_inventory):
    """Lambda execution role S3 access is attributed to the Role, NOT to Carol."""
    inv = mock_inventory
    policy_doc_map = {p["name"]: p["document"] for p in inv.policies}
    all_res = inv.s3 + inv.ec2 + inv.rds + inv.secrets + inv.lambdas

    effective_access = compute_effective_access(inv, policy_doc_map, all_res)

    role_records = [r for r in effective_access if r["identity_name"] == "LambdaExecutionRole"]
    role_s3_targets = [r["target_resource_name"] for r in role_records if r["target_resource_type"] == "S3"]

    # LambdaExecutionRole genuinely has S3 access
    assert "production-data-bucket" in role_s3_targets
    assert "confidential-financial-bucket" in role_s3_targets

    # But Carol does NOT have S3 access
    carol_s3_targets = [r["target_resource_name"] for r in effective_access if r["identity_name"] == "carol-no-mfa" and r["target_resource_type"] == "S3"]
    assert len(carol_s3_targets) == 0, f"Role S3 permissions were incorrectly collapsed to Carol: {carol_s3_targets}"


def test_legitimate_s3_access_preserved_for_authorized_users(mock_inventory):
    """Alice with explicit S3 policy must retain legitimate S3 access."""
    inv = mock_inventory
    policy_doc_map = {p["name"]: p["document"] for p in inv.policies}
    all_res = inv.s3 + inv.ec2 + inv.rds + inv.secrets + inv.lambdas

    effective_access = compute_effective_access(inv, policy_doc_map, all_res)

    alice_records = [r for r in effective_access if r["identity_name"] == "alice-s3-user"]
    alice_s3_targets = [r["target_resource_name"] for r in alice_records if r["target_resource_type"] == "S3"]

    assert "production-data-bucket" in alice_s3_targets, "Alice must retain access to production-data-bucket"
    assert "confidential-financial-bucket" not in alice_s3_targets, "Alice scoped to production-data-bucket must not access confidential bucket"


def test_aws_lambda_full_access_does_not_grant_ec2_instances():
    """AWSLambda_FullAccess with ec2:DescribeSecurityGroups must NOT allow EC2 instances."""
    lambda_full_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudformation:DescribeStacks",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "lambda:*"
                ],
                "Resource": "*"
            }
        ]
    })

    resources = [
        {"id": "i-12345", "name": "prod-ec2", "type": "EC2", "arn": "arn:aws:ec2:us-east-1:123:instance/i-12345"},
        {"id": "fn-123", "name": "prod-lambda", "type": "Lambda", "arn": "arn:aws:lambda:us-east-1:123:function:prod-lambda"},
        {"id": "b-123", "name": "prod-bucket", "type": "S3", "arn": "arn:aws:s3:::prod-bucket"}
    ]

    matched, prov_map, _ = evaluate_policy_allows_resources_with_provenance(
        "AWSLambda_FullAccess", "arn:aws:iam::aws:policy/AWSLambda_FullAccess", lambda_full_doc, resources
    )

    matched_names = [r["name"] for r in matched]
    assert "prod-lambda" in matched_names, "Lambda function must be allowed by AWSLambda_FullAccess"
    assert "prod-ec2" not in matched_names, "EC2 instance must NOT be allowed by AWSLambda_FullAccess"
    assert "prod-bucket" not in matched_names, "S3 bucket must NOT be allowed by AWSLambda_FullAccess"

    lambda_prov = prov_map["prod-lambda"]
    assert lambda_prov["action"] == "lambda:*", f"Action must be lambda:*, got: {lambda_prov['action']}"
    assert lambda_prov["relationship_type"] == "CAN_INVOKE"


def test_graph_construction_preserves_distinct_hops(mock_inventory):
    """Verify that build_local_graph constructs distinct hops Carol->Policy->Lambda and Lambda-[EXECUTES_WITH]->Role."""
    inv = mock_inventory
    running_ec2 = [e for e in inv.ec2 if e.get("state") == "running"]
    
    G = build_local_graph(inv)

    # Find edges in graph
    carol_id = "aws:user:carol-no-mfa"
    lambda_id = "aws:lambda:FirstLambda"
    role_id = "aws:role:LambdaExecutionRole"
    s3_id = "aws:s3:production-data-bucket"

    # There should NOT be a direct Carol -> S3 edge
    assert not G.has_edge(carol_id, s3_id), "Direct edge from Carol to S3 must not exist"

    # Lambda -> Role must have EXECUTES_WITH edge
    assert G.has_edge(lambda_id, role_id), "Lambda -> Role edge must exist"
    edge_data = G.get_edge_data(lambda_id, role_id)
    assert edge_data.get("relationship") == "EXECUTES_WITH" or edge_data.get("edge_type") == "EXECUTES_WITH"
