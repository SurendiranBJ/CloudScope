"""
CloudScope Phase 2 Comprehensive Mocked Test Suite.

Covers all 37 required test scenarios:
- Policy decision model: ALLOWED, DENIED, CONDITIONAL, NOT_APPLICABLE
- Action / NotAction matching
- Resource / NotResource matching
- Condition evaluation (satisfiable vs unresolved runtime parameters)
- Principal / trust matching
- Permissions boundary intersection
- Explicit Deny precedence
- Aurora / RDS IAM database authentication (rds-db:connect vs rds:*)
- Effective access calculation with evidence provenance
- Prevention of false ALLOWS edges when conditions are conditional
"""

import json
import pytest
from app.services.attack.policy_evaluator import (
    PolicyDecision,
    DECISION_ALLOWED,
    DECISION_DENIED,
    DECISION_CONDITIONAL,
    DECISION_NOT_APPLICABLE,
    match_action,
    match_statement_action,
    match_resource_arn,
    match_statement_resource,
    match_principal,
    evaluate_statement,
    evaluate_authorization_decision,
    evaluate_rds_db_connect,
    evaluate_policy_allows_resources,
    evaluate_condition_block,
    parse_policy_document,
)
from app.services.simulation.effective_access import (
    compute_effective_access,
    explain_principal_access,
)


class MockInventory:
    def __init__(self, users=None, roles=None, groups=None, policies=None,
                 s3=None, ec2=None, lambdas=None, secrets=None, rds=None, dynamodb=None):
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


# -----------------------------------------------------------------------------
# 1. Exact Action Match
# -----------------------------------------------------------------------------
def test_01_exact_action_match():
    stmt = {
        "Effect": "Allow",
        "Action": ["ec2:DescribeInstances"],
        "Resource": ["*"]
    }
    dec_match, ev_match = evaluate_statement(stmt, "ec2:DescribeInstances", "*")
    assert dec_match == PolicyDecision.ALLOWED
    assert ev_match["matched_action"] == "ec2:DescribeInstances"

    dec_mismatch, ev_mismatch = evaluate_statement(stmt, "ec2:RunInstances", "*")
    assert dec_mismatch == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 2. Service Wildcard Action Match
# -----------------------------------------------------------------------------
def test_02_service_wildcard_action():
    stmt = {
        "Effect": "Allow",
        "Action": ["ec2:Describe*"],
        "Resource": ["*"]
    }
    assert evaluate_statement(stmt, "ec2:DescribeInstances", "*")[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "ec2:DescribeSecurityGroups", "*")[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "ec2:RunInstances", "*")[0] == PolicyDecision.NOT_APPLICABLE
    assert evaluate_statement(stmt, "s3:GetObject", "*")[0] == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 3. Global Wildcard Action Match
# -----------------------------------------------------------------------------
def test_03_global_wildcard_action():
    stmt = {
        "Effect": "Allow",
        "Action": ["*"],
        "Resource": ["*"]
    }
    assert evaluate_statement(stmt, "s3:GetObject", "*")[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "ec2:StartInstances", "*")[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "iam:CreateUser", "*")[0] == PolicyDecision.ALLOWED


# -----------------------------------------------------------------------------
# 4. NotAction Evaluation
# -----------------------------------------------------------------------------
def test_04_not_action():
    stmt = {
        "Effect": "Allow",
        "NotAction": ["iam:*"],
        "Resource": ["*"]
    }
    # Any action outside iam:* matches and is ALLOWED
    dec_s3, _ = evaluate_statement(stmt, "s3:GetObject", "*")
    assert dec_s3 == PolicyDecision.ALLOWED

    dec_ec2, _ = evaluate_statement(stmt, "ec2:DescribeInstances", "*")
    assert dec_ec2 == PolicyDecision.ALLOWED

    # An action inside iam:* is excluded by NotAction -> NOT_APPLICABLE
    dec_iam, _ = evaluate_statement(stmt, "iam:CreateUser", "*")
    assert dec_iam == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 5. Exact Resource ARN
# -----------------------------------------------------------------------------
def test_05_exact_resource_arn():
    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::production-vault"]
    }
    target = {"arn": "arn:aws:s3:::production-vault", "name": "production-vault", "type": "S3"}
    other = {"arn": "arn:aws:s3:::dev-bucket", "name": "dev-bucket", "type": "S3"}

    dec_match, _ = evaluate_statement(stmt, "s3:GetObject", target)
    assert dec_match == PolicyDecision.ALLOWED

    dec_other, _ = evaluate_statement(stmt, "s3:GetObject", other)
    assert dec_other == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 6. Wildcard Resource ARN
# -----------------------------------------------------------------------------
def test_06_wildcard_resource_arn():
    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::prod-*/*"]
    }
    match1 = {"arn": "arn:aws:s3:::prod-analytics/2026/data.parquet", "type": "S3"}
    match2 = {"arn": "arn:aws:s3:::prod-logs/system.log", "type": "S3"}
    nomatch = {"arn": "arn:aws:s3:::test-bucket/file.txt", "type": "S3"}

    assert evaluate_statement(stmt, "s3:GetObject", match1)[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "s3:GetObject", match2)[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "s3:GetObject", nomatch)[0] == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 7. NotResource Evaluation
# -----------------------------------------------------------------------------
def test_07_not_resource():
    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::*"],
        "NotResource": ["arn:aws:s3:::confidential-*"]
    }
    public_b = {"arn": "arn:aws:s3:::public-bucket", "type": "S3"}
    secret_b = {"arn": "arn:aws:s3:::confidential-vault", "type": "S3"}

    assert evaluate_statement(stmt, "s3:GetObject", public_b)[0] == PolicyDecision.ALLOWED
    assert evaluate_statement(stmt, "s3:GetObject", secret_b)[0] == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 8. Allow Statement Evaluation
# -----------------------------------------------------------------------------
def test_08_allow_statement():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"]
            }
        ]
    }
    dec, ev = evaluate_authorization_decision(
        [doc], "s3:GetObject", "arn:aws:s3:::my-bucket/file.json"
    )
    assert dec == PolicyDecision.ALLOWED
    assert ev["effect"] == "Allow"
    assert ev["statement_sid"] == "AllowS3Read"


# -----------------------------------------------------------------------------
# 9. Explicit Deny Override
# -----------------------------------------------------------------------------
def test_09_explicit_deny_override():
    allow_doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        ]
    }
    deny_doc = {
        "Statement": [
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::restricted-bucket"}
        ]
    }
    restricted = {"arn": "arn:aws:s3:::restricted-bucket", "type": "S3"}
    regular = {"arn": "arn:aws:s3:::regular-bucket", "type": "S3"}

    # Restricted resource receives explicit Deny
    dec_denied, ev_denied = evaluate_authorization_decision(
        [allow_doc, deny_doc], "s3:GetObject", restricted
    )
    assert dec_denied == PolicyDecision.DENIED
    assert ev_denied["decision"] == "DENIED"
    assert "Explicit Deny" in ev_denied["reason"]

    # Regular resource remains ALLOWED
    dec_allowed, _ = evaluate_authorization_decision(
        [allow_doc, deny_doc], "s3:GetObject", regular
    )
    assert dec_allowed == PolicyDecision.ALLOWED


# -----------------------------------------------------------------------------
# 10. Unresolved Condition -> CONDITIONAL
# -----------------------------------------------------------------------------
def test_10_unresolved_condition():
    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["*"],
        "Condition": {
            "IpAddress": {"aws:SourceIp": "203.0.113.0/24"}
        }
    }
    dec, ev = evaluate_statement(stmt, "s3:GetObject", "arn:aws:s3:::bucket/file")
    assert dec == PolicyDecision.CONDITIONAL
    assert ev["condition_status"] == "unresolved"
    assert any("SourceIp" in u for u in ev["conditions_unresolved"])


# -----------------------------------------------------------------------------
# 11. Satisfiable Condition -> ALLOWED
# -----------------------------------------------------------------------------
def test_11_satisfiable_condition():
    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["*"],
        "Condition": {
            "StringEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}
        }
    }
    matching_user = {"arn": "arn:aws:iam::123456789012:user/alice", "name": "alice"}
    other_user = {"arn": "arn:aws:iam::123456789012:user/bob", "name": "bob"}

    dec_match, ev_match = evaluate_statement(stmt, "s3:GetObject", "arn:aws:s3:::bucket/file", principal=matching_user)
    assert dec_match == PolicyDecision.ALLOWED
    assert ev_match["condition_status"] == "satisfied"

    dec_diff, ev_diff = evaluate_statement(stmt, "s3:GetObject", "arn:aws:s3:::bucket/file", principal=other_user)
    assert dec_diff == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 12. Principal Matching
# -----------------------------------------------------------------------------
def test_12_principal_matching():
    stmt_principal = {"AWS": "arn:aws:iam::123456789012:user/charlie"}
    user_charlie = {"arn": "arn:aws:iam::123456789012:user/charlie", "name": "charlie"}
    user_dave = {"arn": "arn:aws:iam::123456789012:user/dave", "name": "dave"}

    assert match_principal(stmt_principal, user_charlie) is True
    assert match_principal(stmt_principal, user_dave) is False


# -----------------------------------------------------------------------------
# 13. Wildcard Principal
# -----------------------------------------------------------------------------
def test_13_wildcard_principal():
    assert match_principal("*", {"arn": "arn:aws:iam::123456789012:user/anyone"}) is True
    assert match_principal({"AWS": "*"}, {"arn": "arn:aws:iam::123456789012:role/AnyRole"}) is True


# -----------------------------------------------------------------------------
# 14. Cross-Account Root Trust
# -----------------------------------------------------------------------------
def test_14_cross_account_root_trust():
    trust_principal = {"AWS": "arn:aws:iam::999888777666:root"}
    foreign_user = {"arn": "arn:aws:iam::999888777666:user/external_analyst"}
    local_user = {"arn": "arn:aws:iam::123456789012:user/local_dev"}

    assert match_principal(trust_principal, foreign_user, account_id="123456789012") is True
    assert match_principal(trust_principal, local_user, account_id="123456789012") is False


# -----------------------------------------------------------------------------
# 15. Role Trust vs Permissions Policy Distinction
# -----------------------------------------------------------------------------
def test_15_role_trust_vs_permissions_policy_distinction():
    # Trust policy allows sts:AssumeRole for a role, not s3:GetObject
    trust_doc = {
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:user/alice"}, "Action": "sts:AssumeRole"}
        ]
    }
    # An S3 resource evaluated against trust policy must NOT be granted
    s3_res = [{"id": "b1", "name": "vault", "type": "S3", "arn": "arn:aws:s3:::vault"}]
    allowed = evaluate_policy_allows_resources(trust_doc, s3_res)
    assert len(allowed) == 0, "Trust policy must not grant resource permissions"


# -----------------------------------------------------------------------------
# 16. Permissions Boundary Limiting Access
# -----------------------------------------------------------------------------
def test_16_permissions_boundary_limiting_access():
    user = {
        "name": "boundary_user",
        "policies": ["BroadAccess"],
        "permissionsBoundary": "arn:aws:iam::123:policy/S3OnlyBoundary"
    }
    policy_doc_map = {
        "BroadAccess": json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }),
        "S3OnlyBoundary": json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
        })
    }
    s3_bucket = {"id": "b1", "name": "my-bucket", "type": "S3", "arn": "arn:aws:s3:::my-bucket"}
    ec2_inst = {"id": "i-123", "name": "app-server", "type": "EC2", "arn": "arn:aws:ec2:us-east-1:123:instance/i-123"}

    inv = MockInventory(users=[user])
    records = compute_effective_access(inv, policy_doc_map, [s3_bucket, ec2_inst])

    # S3 bucket is within boundary -> allowed
    target_ids = [r["target_resource_id"] for r in records]
    assert "i-123" not in target_ids, "EC2 must be blocked by S3OnlyBoundary"
    assert "b1" in target_ids, "S3 must pass through S3OnlyBoundary"


# -----------------------------------------------------------------------------
# 17. Direct User Policy
# -----------------------------------------------------------------------------
def test_17_direct_user_policy():
    user = {"name": "alice", "policies": ["AliceS3Policy"]}
    doc_map = {
        "AliceS3Policy": json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
        })
    }
    res = [{"id": "b1", "name": "data-bucket", "type": "S3", "arn": "arn:aws:s3:::data-bucket"}]
    records = compute_effective_access(MockInventory(users=[user]), doc_map, res)

    assert len(records) == 1
    assert records[0]["identity_name"] == "alice"
    assert records[0]["through_relationship"] == ["HAS_POLICY", "ALLOWS"]


# -----------------------------------------------------------------------------
# 18. Group-Derived Access
# -----------------------------------------------------------------------------
def test_18_group_derived_access():
    user = {"name": "bob", "groups": ["DataEngineers"], "policies": []}
    group = {"name": "DataEngineers", "attachedPolicies": ["DynamoPolicy"]}
    doc_map = {
        "DynamoPolicy": json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]
        })
    }
    table = [{"id": "t1", "name": "AnalyticsTable", "type": "DynamoDB", "arn": "arn:aws:dynamodb:us-east-1:123:table/AnalyticsTable"}]
    records = compute_effective_access(MockInventory(users=[user], groups=[group]), doc_map, table)

    assert len(records) == 1
    assert records[0]["identity_name"] == "bob"
    assert records[0]["through_relationship"] == ["MEMBER_OF", "HAS_POLICY", "ALLOWS"]


# -----------------------------------------------------------------------------
# 19. Role-Derived Access
# -----------------------------------------------------------------------------
def test_19_role_derived_access():
    role = {"name": "WorkerRole", "attachedPolicies": ["WorkerPolicy"]}
    doc_map = {
        "WorkerPolicy": json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        })
    }
    s3_b = [{"id": "b1", "name": "queue-bucket", "type": "S3", "arn": "arn:aws:s3:::queue-bucket"}]
    records = compute_effective_access(MockInventory(roles=[role]), doc_map, s3_b)

    assert any(r["identity_name"] == "WorkerRole" and r["target_resource_id"] == "b1" for r in records)


# -----------------------------------------------------------------------------
# 20. Multi-Hop Role Assumption
# -----------------------------------------------------------------------------
def test_20_multihop_role_assumption():
    user = {"name": "junior_dev", "arn": "arn:aws:iam::123:user/junior_dev", "policies": ["AssumeStage1"]}
    role1 = {
        "name": "Stage1Role",
        "arn": "arn:aws:iam::123:role/Stage1Role",
        "attachedPolicies": ["AssumeStage2"],
        "trustPolicy": json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:user/junior_dev"}, "Action": "sts:AssumeRole"}]
        })
    }
    role2 = {
        "name": "Stage2Role",
        "arn": "arn:aws:iam::123:role/Stage2Role",
        "attachedPolicies": ["SecretsAccess"],
        "trustPolicy": json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/Stage1Role"}, "Action": "sts:AssumeRole"}]
        })
    }
    doc_map = {
        "AssumeStage1": json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123:role/Stage1Role"}]}),
        "AssumeStage2": json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123:role/Stage2Role"}]}),
        "SecretsAccess": json.dumps({"Statement": [{"Effect": "Allow", "Action": "secretsmanager:*", "Resource": "*"}]}),
    }
    secret = [{"id": "sec-1", "name": "prod-passwords", "type": "Secrets", "arn": "arn:aws:secretsmanager:us-east-1:123:secret:prod-passwords"}]
    inv = MockInventory(users=[user], roles=[role1, role2])
    records = compute_effective_access(inv, doc_map, secret)

    user_sec_records = [r for r in records if r["identity_name"] == "junior_dev" and r["target_resource_id"] == "sec-1"]
    assert len(user_sec_records) >= 1
    assert "Stage1Role" in user_sec_records[0]["access_path"]
    assert "Stage2Role" in user_sec_records[0]["access_path"]


# -----------------------------------------------------------------------------
# 21. No False Access from Resource Names
# -----------------------------------------------------------------------------
def test_21_no_false_access_from_resource_names():
    # A resource with an alluring name must NOT be accessible without actual policy grant
    secret = [{"id": "s-critical", "name": "top-secret-credentials", "type": "Secrets", "arn": "arn:aws:secretsmanager:us-east-1:123:secret:top-secret-credentials"}]
    user = {"name": "guest", "policies": []}
    records = compute_effective_access(MockInventory(users=[user]), {}, secret)
    assert len(records) == 0, "No access must be inferred from resource names"


# -----------------------------------------------------------------------------
# 22. No False Access from Policy Names
# -----------------------------------------------------------------------------
def test_22_no_false_access_from_policy_names():
    # A policy named AdministratorAccess but having empty document grants nothing
    user = {"name": "fake_admin", "policies": ["AdministratorAccess"]}
    doc_map = {"AdministratorAccess": json.dumps({"Statement": []})}
    res = [{"id": "b1", "name": "target", "type": "S3", "arn": "arn:aws:s3:::target"}]
    records = compute_effective_access(MockInventory(users=[user]), doc_map, res)
    assert len(records) == 0, "No access must be inferred from policy name alone"


# -----------------------------------------------------------------------------
# 23. rds:DescribeDBClusters is Management Permission, Not DB Login
# -----------------------------------------------------------------------------
def test_23_rds_describe_db_clusters_is_management_permission():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "rds:DescribeDBClusters", "Resource": "*"}
        ]
    }
    # Management action evaluates as allowed
    dec_mgmt, ev_mgmt = evaluate_statement(doc["Statement"][0], "rds:DescribeDBClusters", "*")
    assert dec_mgmt == PolicyDecision.ALLOWED

    # But database authentication evaluates as DENIED
    dec_login, ev_login = evaluate_rds_db_connect(doc, "cluster-PROD123", "db_admin")
    assert dec_login == PolicyDecision.DENIED
    assert ev_login["decision"] == "DENIED"


# -----------------------------------------------------------------------------
# 24. rds:ModifyDBCluster is Management Permission
# -----------------------------------------------------------------------------
def test_24_rds_modify_db_cluster_is_management_permission():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "rds:ModifyDBCluster", "Resource": "*"}
        ]
    }
    dec_mgmt, _ = evaluate_statement(doc["Statement"][0], "rds:ModifyDBCluster", "*")
    assert dec_mgmt == PolicyDecision.ALLOWED

    dec_login, _ = evaluate_rds_db_connect(doc, "cluster-XYZ", "app_user")
    assert dec_login == PolicyDecision.DENIED


# -----------------------------------------------------------------------------
# 25. rds-db:connect Creates DB Authentication Evidence
# -----------------------------------------------------------------------------
def test_25_rds_db_connect_creates_db_authentication_evidence():
    doc = {
        "Statement": [
            {
                "Sid": "AllowAuroraConnect",
                "Effect": "Allow",
                "Action": "rds-db:connect",
                "Resource": "arn:aws:rds-db:us-east-1:123456789012:dbuser:cluster-ABC12345/jane_doe"
            }
        ]
    }
    dec, ev = evaluate_rds_db_connect(
        doc, "cluster-ABC12345", "jane_doe",
        account_id="123456789012", region="us-east-1"
    )
    assert dec == PolicyDecision.ALLOWED
    assert ev["decision"] == "ALLOWED"
    assert ev["statement_sid"] == "AllowAuroraConnect"
    assert ev["source"] == "database_authentication"
    assert ev["db_resource_id"] == "cluster-ABC12345"
    assert ev["db_username"] == "jane_doe"


# -----------------------------------------------------------------------------
# 26. Incorrect DB-User ARN Does Not Match
# -----------------------------------------------------------------------------
def test_26_incorrect_db_user_arn_does_not_match():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds-db:connect",
                "Resource": "arn:aws:rds-db:us-east-1:123456789012:dbuser:cluster-ABC12345/alice"
            }
        ]
    }
    # Connecting as bob must be DENIED
    dec, ev = evaluate_rds_db_connect(
        doc, "cluster-ABC12345", "bob",
        account_id="123456789012", region="us-east-1"
    )
    assert dec == PolicyDecision.DENIED


# -----------------------------------------------------------------------------
# 27. Matching DB-User ARN Creates DB_CONNECT Evidence
# -----------------------------------------------------------------------------
def test_27_matching_db_user_arn_creates_db_connect_evidence():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds-db:connect",
                "Resource": "arn:aws:rds-db:eu-west-1:987654321098:dbuser:db-INST999/*"
            }
        ]
    }
    dec, ev = evaluate_rds_db_connect(
        doc, "db-INST999", "reporting_service",
        account_id="987654321098", region="eu-west-1"
    )
    assert dec == PolicyDecision.ALLOWED
    assert "arn:aws:rds-db:eu-west-1:987654321098:dbuser:db-INST999/reporting_service" in ev["resource_arn"]


# -----------------------------------------------------------------------------
# 28. Explicit Deny Overrides rds-db:connect
# -----------------------------------------------------------------------------
def test_28_explicit_deny_overrides_rds_db_connect():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds-db:connect",
                "Resource": "arn:aws:rds-db:us-east-1:123:dbuser:cluster-FIN/*"
            },
            {
                "Effect": "Deny",
                "Action": "rds-db:connect",
                "Resource": "arn:aws:rds-db:us-east-1:123:dbuser:cluster-FIN/root_db_user"
            }
        ]
    }
    # root_db_user receives explicit Deny
    dec_root, ev_root = evaluate_rds_db_connect(doc, "cluster-FIN", "root_db_user", account_id="123")
    assert dec_root == PolicyDecision.DENIED
    assert "Explicit Deny" in ev_root["reason"]

    # normal user is ALLOWED
    dec_app, _ = evaluate_rds_db_connect(doc, "cluster-FIN", "app_reader", account_id="123")
    assert dec_app == PolicyDecision.ALLOWED


# -----------------------------------------------------------------------------
# 29. Unresolved DB Conditions Remain CONDITIONAL
# -----------------------------------------------------------------------------
def test_29_unresolved_db_conditions_remain_conditional():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds-db:connect",
                "Resource": "arn:aws:rds-db:us-east-1:123:dbuser:cluster-A/user1",
                "Condition": {
                    "IpAddress": {"aws:SourceIp": "10.0.0.5/32"}
                }
            }
        ]
    }
    dec, ev = evaluate_rds_db_connect(doc, "cluster-A", "user1", account_id="123")
    assert dec == PolicyDecision.CONDITIONAL
    assert ev["decision"] == "CONDITIONAL"


# -----------------------------------------------------------------------------
# 30. DB_CONNECT and RDS Management Access Remain Separate
# -----------------------------------------------------------------------------
def test_30_db_connect_and_rds_management_access_remain_separate():
    mgmt_doc = {"Statement": [{"Effect": "Allow", "Action": "rds:*", "Resource": "*"}]}
    db_auth_doc = {"Statement": [{"Effect": "Allow", "Action": "rds-db:connect", "Resource": "arn:aws:rds-db:us-east-1:123:dbuser:cluster-X/analyst"}]}

    # mgmt_doc does NOT grant DB login
    dec1, _ = evaluate_rds_db_connect(mgmt_doc, "cluster-X", "analyst", account_id="123")
    assert dec1 == PolicyDecision.DENIED

    # db_auth_doc does NOT grant RDS management actions
    dec2, _ = evaluate_statement(db_auth_doc["Statement"][0], "rds:ModifyDBCluster", "*")
    assert dec2 == PolicyDecision.NOT_APPLICABLE


# -----------------------------------------------------------------------------
# 31. Effective Access Direct Policy
# -----------------------------------------------------------------------------
def test_31_effective_access_direct_policy():
    user = {"name": "dave", "policies": ["DavePolicy"]}
    doc_map = {"DavePolicy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})}
    res = [{"id": "b-dave", "name": "dave-bucket", "type": "S3", "arn": "arn:aws:s3:::dave-bucket"}]

    records = compute_effective_access(MockInventory(users=[user]), doc_map, res)
    assert len(records) == 1
    assert records[0]["identity_name"] == "dave"
    assert records[0]["target_resource_id"] == "b-dave"


# -----------------------------------------------------------------------------
# 32. Effective Access Group Policy
# -----------------------------------------------------------------------------
def test_32_effective_access_group_policy():
    user = {"name": "eve", "groups": ["DevOps"], "policies": []}
    group = {"name": "DevOps", "attachedPolicies": ["EC2Access"]}
    doc_map = {"EC2Access": json.dumps({"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]})}
    inst = [{"id": "i-eve", "name": "eve-inst", "type": "EC2", "arn": "arn:aws:ec2:us-east-1:123:instance/i-eve"}]

    records = compute_effective_access(MockInventory(users=[user], groups=[group]), doc_map, inst)
    assert len(records) == 1
    assert records[0]["identity_name"] == "eve"
    assert "DevOps" in records[0]["access_path"]


# -----------------------------------------------------------------------------
# 33. Effective Access Assumed Role
# -----------------------------------------------------------------------------
def test_33_effective_access_assumed_role():
    user = {"name": "frank", "arn": "arn:aws:iam::123:user/frank", "policies": ["AssumeAudit"]}
    role = {
        "name": "AuditRole",
        "arn": "arn:aws:iam::123:role/AuditRole",
        "attachedPolicies": ["AuditRead"],
        "trustPolicy": json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:user/frank"}, "Action": "sts:AssumeRole"}]
        })
    }
    doc_map = {
        "AssumeAudit": json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123:role/AuditRole"}]}),
        "AuditRead": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    }
    b = [{"id": "b-audit", "name": "audit-logs", "type": "S3", "arn": "arn:aws:s3:::audit-logs"}]
    records = compute_effective_access(MockInventory(users=[user], roles=[role]), doc_map, b)

    f_records = [r for r in records if r["identity_name"] == "frank"]
    assert len(f_records) >= 1
    assert "CAN_ASSUME" in f_records[0]["through_relationship"]


# -----------------------------------------------------------------------------
# 34. Effective Access Permissions Boundary Blocks Grant
# -----------------------------------------------------------------------------
def test_34_effective_access_permissions_boundary_blocks_grant():
    user = {
        "name": "bounded_dev",
        "policies": ["FullEC2"],
        "permissionsBoundary": "arn:aws:iam::123:policy/StrictBoundary"
    }
    doc_map = {
        "FullEC2": json.dumps({"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}),
        # Boundary permits only S3, NOT EC2
        "StrictBoundary": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    }
    inst = [{"id": "i-bound", "name": "bounded-ec2", "type": "EC2", "arn": "arn:aws:ec2:us-east-1:123:instance/i-bound"}]
    records = compute_effective_access(MockInventory(users=[user]), doc_map, inst)
    assert len(records) == 0, "Permissions boundary must block access when it does not permit the service/resource"


# -----------------------------------------------------------------------------
# 35. Effective Access Explicit Deny Blocks Grant
# -----------------------------------------------------------------------------
def test_35_effective_access_explicit_deny_blocks_grant():
    user = {
        "name": "developer",
        "policies": ["AllowAllS3", "DenyVault"]
    }
    doc_map = {
        "AllowAllS3": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}),
        "DenyVault": json.dumps({"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::vault"}]})
    }
    vault = {"id": "b-vault", "name": "vault", "type": "S3", "arn": "arn:aws:s3:::vault"}
    open_b = {"id": "b-open", "name": "open-data", "type": "S3", "arn": "arn:aws:s3:::open-data"}

    records = compute_effective_access(MockInventory(users=[user]), doc_map, [vault, open_b])
    target_ids = [r["target_resource_id"] for r in records]
    assert "b-vault" not in target_ids, "Explicit Deny must block access to vault"
    assert "b-open" in target_ids, "Unblocked resource must remain accessible"


# -----------------------------------------------------------------------------
# 36. Evidence Object Is Returned
# -----------------------------------------------------------------------------
def test_36_evidence_object_is_returned():
    user = {"name": "ajith", "policies": ["EC2Full"]}
    doc_map = {
        "EC2Full": json.dumps({
            "Statement": [
                {"Sid": "EC2All", "Effect": "Allow", "Action": "ec2:*", "Resource": "*"}
            ]
        })
    }
    inst = [{"id": "i-prod", "name": "prod-app", "type": "EC2", "arn": "arn:aws:ec2:us-east-1:123:instance/i-prod"}]
    inv = MockInventory(users=[user], policies=[{"name": "EC2Full", "document": doc_map["EC2Full"]}])

    # 1. compute_effective_access returns evidence
    records = compute_effective_access(inv, doc_map, inst)
    assert len(records) == 1
    assert "evidence" in records[0]
    ev = records[0]["evidence"]
    assert ev["principal"] == "ajith"
    assert ev["decision"] == "ALLOWED"

    # 2. explain_principal_access returns rich explanation
    explanation = explain_principal_access("ajith", "i-prod", inv, doc_map)
    assert explanation["principal"] == "ajith"
    assert explanation["decision"] == "ALLOWED"
    assert "policy" in explanation
    assert "reason" in explanation


# -----------------------------------------------------------------------------
# 37. No False ALLOWS Edge Emitted When Access is Only CONDITIONAL
# -----------------------------------------------------------------------------
def test_37_no_false_allows_edge_when_access_is_only_conditional():
    # If a policy statement is conditional on runtime context (e.g. MFA present),
    # it must NOT emit an unconditional ALLOWS edge in evaluate_policy_allows_resources.
    conditional_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    resources = [{"id": "b-critical", "name": "critical-vault", "type": "S3", "arn": "arn:aws:s3:::critical-vault"}]

    allowed = evaluate_policy_allows_resources(conditional_doc, resources)
    assert len(allowed) == 0, "Unconditional ALLOWS edge must NOT be emitted for runtime CONDITIONAL policy"
