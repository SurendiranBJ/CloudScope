"""
Comprehensive tests for:
1. Resource effective access respecting permissions boundaries (User, Group, Role, Multi-hop)
2. Resource policy Conditions (satisfied, violated, runtime-dependent/unresolved)
3. NotAction and NotResource semantics (Allow/Deny combinations)
4. Explicit Deny precedence across multiple policy sources (direct, group, inline, boundary)
"""

import json
import pytest
from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    check_resource_explicitly_denied,
    has_service_action,
    match_resource_arn,
    principal_effective_allows_assume_role,
    parse_policy_document,
)
from app.services.simulation.effective_access import (
    compute_effective_access,
    _filter_by_permissions_boundary,
)


class MockInventory:
    def __init__(self, users=None, roles=None, groups=None, policies=None, s3=None, rds=None, secrets=None, ec2=None, lambdas=None, dynamodb=None):
        self.users = users or []
        self.roles = roles or []
        self.groups = groups or []
        self.policies = policies or []
        self.s3 = s3 or []
        self.rds = rds or []
        self.secrets = secrets or []
        self.ec2 = ec2 or []
        self.lambdas = lambdas or []
        self.dynamodb = dynamodb or []


# ─── 1. Permissions Boundary on Resource Access ───────────────────────────────

def test_user_permissions_boundary_allow():
    """Identity Allow + Boundary Allow => Resource access allowed."""
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]
    }
    policy_doc_map = {
        "S3Full": json.dumps(policy_doc),
        "arn:aws:iam::123:policy/BoundaryS3": json.dumps(boundary_doc),
    }
    user = {
        "name": "alice",
        "policies": ["S3Full"],
        "permissionsBoundary": "arn:aws:iam::123:policy/BoundaryS3"
    }
    s3_res = {"id": "b1", "name": "my-bucket", "type": "S3", "arn": "arn:aws:s3:::my-bucket"}
    inv = MockInventory(users=[user], s3=[s3_res])

    records = compute_effective_access(inv, policy_doc_map, [s3_res])
    assert len(records) == 1
    assert records[0]["target_resource_name"] == "my-bucket"


def test_user_permissions_boundary_restricts_service():
    """Identity Allow (S3 & RDS) + Boundary Allow (S3 only) => RDS access denied."""
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ]
    }
    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    policy_doc_map = {
        "Admin": json.dumps(policy_doc),
        "arn:aws:iam::123:policy/BoundaryS3Only": json.dumps(boundary_doc),
    }
    user = {
        "name": "alice",
        "policies": ["Admin"],
        "permissionsBoundary": "arn:aws:iam::123:policy/BoundaryS3Only"
    }
    s3_res = {"id": "b1", "name": "my-bucket", "type": "S3", "arn": "arn:aws:s3:::my-bucket"}
    rds_res = {"id": "r1", "name": "prod-db", "type": "RDS", "arn": "arn:aws:rds:us-east-1:123:db:prod-db"}
    inv = MockInventory(users=[user], s3=[s3_res], rds=[rds_res])

    records = compute_effective_access(inv, policy_doc_map, [s3_res, rds_res])
    assert len(records) == 1
    assert records[0]["target_resource_name"] == "my-bucket"


def test_user_permissions_boundary_explicit_deny():
    """Identity Allow + Boundary explicit Deny => Denied."""
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::confidential/*"}
        ]
    }
    policy_doc_map = {
        "S3Full": json.dumps(policy_doc),
        "arn:aws:iam::123:policy/BoundaryWithDeny": json.dumps(boundary_doc),
    }
    user = {
        "name": "alice",
        "policies": ["S3Full"],
        "permissionsBoundary": "arn:aws:iam::123:policy/BoundaryWithDeny"
    }
    b_confidential = {"id": "b1", "name": "confidential", "type": "S3", "arn": "arn:aws:s3:::confidential"}
    b_public = {"id": "b2", "name": "public-bucket", "type": "S3", "arn": "arn:aws:s3:::public-bucket"}
    inv = MockInventory(users=[user], s3=[b_confidential, b_public])

    records = compute_effective_access(inv, policy_doc_map, [b_confidential, b_public])
    assert len(records) == 1
    assert records[0]["target_resource_name"] == "public-bucket"


def test_permissions_boundary_document_unavailable():
    """Boundary attached but document unavailable => Access Denied (not converted to definitive)."""
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    policy_doc_map = {"S3Full": json.dumps(policy_doc)}
    user = {
        "name": "alice",
        "policies": ["S3Full"],
        "permissionsBoundary": "arn:aws:iam::123:policy/MissingBoundary"
    }
    s3_res = {"id": "b1", "name": "my-bucket", "type": "S3", "arn": "arn:aws:s3:::my-bucket"}
    inv = MockInventory(users=[user], s3=[s3_res])

    records = compute_effective_access(inv, policy_doc_map, [s3_res])
    assert len(records) == 0


def test_role_permissions_boundary():
    """Role with boundary: direct role access respects boundary."""
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    policy_doc_map = {
        "Admin": json.dumps(role_policy),
        "arn:aws:iam::123:policy/RoleBoundary": json.dumps(boundary_doc),
    }
    role = {
        "name": "AppRole",
        "attachedPolicies": ["Admin"],
        "permissionsBoundary": "arn:aws:iam::123:policy/RoleBoundary"
    }
    s3_res = {"id": "b1", "name": "app-bucket", "type": "S3", "arn": "arn:aws:s3:::app-bucket"}
    sec_res = {"id": "s1", "name": "app-secret", "type": "Secrets", "arn": "arn:aws:secretsmanager:us-east-1:123:secret:app-secret"}
    inv = MockInventory(roles=[role], s3=[s3_res], secrets=[sec_res])

    records = compute_effective_access(inv, policy_doc_map, [s3_res, sec_res])
    # S3 should be allowed, Secret should be denied by boundary
    assert len(records) == 1
    assert records[0]["target_resource_name"] == "app-bucket"


# ─── 2. Resource Policy Conditions ───────────────────────────────────────────

def test_resource_condition_satisfied():
    """Condition satisfied (matching aws:PrincipalArn) => statement applies."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"
                    }
                }
            }
        ]
    }
    res = [{"id": "b1", "name": "bucket-one", "type": "S3", "arn": "arn:aws:s3:::bucket-one"}]
    principal = {"arn": "arn:aws:iam::123456789012:user/alice"}
    matched = evaluate_policy_allows_resources(doc, res, principal=principal)
    assert len(matched) == 1


def test_resource_condition_violated():
    """Condition deterministically violated => statement does not apply."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:user/bob"
                    }
                }
            }
        ]
    }
    res = [{"id": "b1", "name": "bucket-one", "type": "S3", "arn": "arn:aws:s3:::bucket-one"}]
    principal = {"arn": "arn:aws:iam::123456789012:user/alice"}
    matched = evaluate_policy_allows_resources(doc, res, principal=principal)
    assert len(matched) == 0


def test_resource_condition_runtime_unresolved_never_unconditional_allow():
    """Runtime-dependent condition (e.g. aws:SourceIp) => never convert to unconditional Allow."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "10.0.0.0/24"
                    }
                }
            }
        ]
    }
    res = [{"id": "b1", "name": "bucket-one", "type": "S3", "arn": "arn:aws:s3:::bucket-one"}]
    matched = evaluate_policy_allows_resources(doc, res)
    assert len(matched) == 0, "Runtime-dependent condition must not grant unconditional access"


def test_resource_condition_runtime_unresolved_never_unconditional_deny():
    """Runtime-dependent condition on Deny (e.g. MultiFactorAuthPresent=false) => does not blindly deny static scan."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            }
        ]
    }
    res = [{"id": "b1", "name": "bucket-one", "type": "S3", "arn": "arn:aws:s3:::bucket-one"}]
    matched = evaluate_policy_allows_resources(doc, res)
    assert len(matched) == 1, "Runtime-dependent Deny condition must not unconditionally deny static access"


# ─── 3. NotAction and NotResource Semantics ───────────────────────────────────

def test_allow_with_notaction():
    """Allow + NotAction: NotAction iam:* allows all services other than IAM."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": ["iam:*"],
                "Resource": "*"
            }
        ]
    }
    res = [
        {"id": "b1", "name": "my-bucket", "type": "S3", "arn": "arn:aws:s3:::my-bucket"},
        {"id": "r1", "name": "my-db", "type": "RDS", "arn": "arn:aws:rds:us-east-1:123:db:my-db"}
    ]
    matched = evaluate_policy_allows_resources(doc, res)
    assert len(matched) == 2


def test_deny_with_notaction():
    """Deny + NotAction: Deny NotAction s3:* denies all services other than S3."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "NotAction": ["s3:*"], "Resource": "*"}
        ]
    }
    res = [
        {"id": "b1", "name": "my-bucket", "type": "S3", "arn": "arn:aws:s3:::my-bucket"},
        {"id": "r1", "name": "my-db", "type": "RDS", "arn": "arn:aws:rds:us-east-1:123:db:my-db"}
    ]
    matched = evaluate_policy_allows_resources(doc, res)
    # S3 was excluded from Deny, so it survives; RDS was denied by Deny NotAction s3:*
    assert len(matched) == 1
    assert matched[0]["name"] == "my-bucket"


def test_allow_with_notresource():
    """Allow + NotResource: allows all resources except the specified exclusion."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "NotResource": ["arn:aws:s3:::secret-bucket", "arn:aws:s3:::secret-bucket/*"]
            }
        ]
    }
    res = [
        {"id": "b1", "name": "secret-bucket", "type": "S3", "arn": "arn:aws:s3:::secret-bucket"},
        {"id": "b2", "name": "public-bucket", "type": "S3", "arn": "arn:aws:s3:::public-bucket"}
    ]
    matched = evaluate_policy_allows_resources(doc, res)
    assert len(matched) == 1
    assert matched[0]["name"] == "public-bucket"


def test_deny_with_notresource():
    """Deny + NotResource: denies all resources except the specified exclusion."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "NotResource": ["arn:aws:s3:::allowed-bucket", "arn:aws:s3:::allowed-bucket/*"]
            }
        ]
    }
    res = [
        {"id": "b1", "name": "allowed-bucket", "type": "S3", "arn": "arn:aws:s3:::allowed-bucket"},
        {"id": "b2", "name": "other-bucket", "type": "S3", "arn": "arn:aws:s3:::other-bucket"}
    ]
    matched = evaluate_policy_allows_resources(doc, res)
    # other-bucket is denied; allowed-bucket was excluded from Deny
    assert len(matched) == 1
    assert matched[0]["name"] == "allowed-bucket"


# ─── 4. Explicit Deny Precedence Across Multiple Policy Sources ───────────────

def test_direct_allow_plus_group_deny():
    """User has direct Allow policy, but belongs to a Group with an explicit Deny => Denied."""
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::confidential/*"}]
    }
    policy_doc_map = {
        "S3Allow": json.dumps(allow_policy),
        "S3DenyConfidential": json.dumps(deny_policy),
    }
    user = {
        "name": "alice",
        "policies": ["S3Allow"],
        "groups": ["SecurityGroup"]
    }
    group = {
        "name": "SecurityGroup",
        "attachedPolicies": ["S3DenyConfidential"]
    }
    b_conf = {"id": "b1", "name": "confidential", "type": "S3", "arn": "arn:aws:s3:::confidential"}
    b_pub = {"id": "b2", "name": "public", "type": "S3", "arn": "arn:aws:s3:::public"}
    inv = MockInventory(users=[user], groups=[group], s3=[b_conf, b_pub])

    records = compute_effective_access(inv, policy_doc_map, [b_conf, b_pub])
    assert len(records) == 1
    assert records[0]["target_resource_name"] == "public"


def test_direct_deny_plus_group_allow():
    """User has direct Deny policy, and Group has Allow => Denied."""
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    }
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]
    }
    policy_doc_map = {
        "S3Allow": json.dumps(allow_policy),
        "S3DenyAll": json.dumps(deny_policy),
    }
    user = {
        "name": "alice",
        "policies": ["S3DenyAll"],
        "groups": ["DevGroup"]
    }
    group = {
        "name": "DevGroup",
        "attachedPolicies": ["S3Allow"]
    }
    b_pub = {"id": "b1", "name": "public", "type": "S3", "arn": "arn:aws:s3:::public"}
    inv = MockInventory(users=[user], groups=[group], s3=[b_pub])

    records = compute_effective_access(inv, policy_doc_map, [b_pub])
    assert len(records) == 0


def test_multiple_allows_one_deny():
    """Multiple direct/group policies grant Allow, one policy Denies => Denied."""
    doc_allow1 = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    doc_allow2 = {"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]}
    doc_deny = {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::target/*"}]}

    policy_doc_map = {
        "P1": json.dumps(doc_allow1),
        "P2": json.dumps(doc_allow2),
        "P3": json.dumps(doc_deny),
    }
    user = {"name": "alice", "policies": ["P1", "P2", "P3"]}
    target_res = {"id": "b1", "name": "target", "type": "S3", "arn": "arn:aws:s3:::target"}
    inv = MockInventory(users=[user], s3=[target_res])

    records = compute_effective_access(inv, policy_doc_map, [target_res])
    assert len(records) == 0
