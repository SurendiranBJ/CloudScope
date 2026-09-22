import pytest
import networkx as nx
from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources_with_provenance,
    PolicyEvaluator,
)
from app.services.graph.edge_validation import validate_edge, VALID_SEMANTIC_EDGES
from app.services.graph.graph_loader import build_local_graph
from app.services.attack.path_engine import check_passrole_escalation, PathEngine
from app.services.attack.blast_radius import calculate_blast_radius


def test_allows_edge_provenance_populated():
    evaluator = PolicyEvaluator()
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::confidential-data/*"
            }
        ]
    }
    known_resources = {
        "arn:aws:s3:::confidential-data/keys.txt": {"type": "S3", "region": "us-east-1"}
    }
    allowed, prov_list, denies = evaluate_policy_allows_resources_with_provenance(
        policy_doc=policy_doc,
        policy_name="S3ConfidentialReader",
        known_resources=known_resources,
        default_region="us-east-1"
    )
    assert len(allowed) == 1
    assert "arn:aws:s3:::confidential-data/keys.txt" in allowed
    assert len(prov_list) == 1
    prov = prov_list[0]
    assert prov["policy_name"] == "S3ConfidentialReader"
    assert prov["statement_sid"] == "AllowS3Read"
    assert prov["action"] == "s3:GetObject"
    assert prov["decision"] == "ALLOW"
    assert prov["region"] == "us-east-1"
    assert "AllowS3Read" in prov["why"]


def test_wildcard_resource_resolution_provenance():
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAllSecrets",
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*"
            }
        ]
    }
    known_resources = {
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db": {"type": "Secret", "region": "us-east-1"},
        "arn:aws:s3:::public-bucket": {"type": "S3", "region": "us-east-1"}
    }
    allowed, prov_list, _ = evaluate_policy_allows_resources_with_provenance(
        policy_doc=policy_doc,
        policy_name="SecretReader",
        known_resources=known_resources
    )
    assert "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db" in allowed
    assert "arn:aws:s3:::public-bucket" not in allowed
    assert prov_list[0]["statement_sid"] == "AllowAllSecrets"


def test_explicit_deny_prevents_edge_creation():
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            },
            {
                "Sid": "DenyS3Secret",
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::classified-vault"
            }
        ]
    }
    known_resources = {
        "arn:aws:s3:::classified-vault": {"type": "S3", "region": "us-east-1"},
        "arn:aws:s3:::public-logs": {"type": "S3", "region": "us-east-1"}
    }
    allowed, prov_list, denies = evaluate_policy_allows_resources_with_provenance(
        policy_doc=policy_doc,
        policy_name="GuardrailPolicy",
        known_resources=known_resources
    )
    assert "arn:aws:s3:::classified-vault" not in allowed
    assert "arn:aws:s3:::public-logs" in allowed
    assert len(denies) >= 1
    assert any("DenyS3Secret" in d.get("statement_sid", "") for d in denies)


def test_unresolved_condition_treated_as_unmet():
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ConditionalAccess",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::restricted-bucket/*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/Department": "Finance"
                    }
                }
            }
        ]
    }
    known_resources = {
        "arn:aws:s3:::restricted-bucket/budget.pdf": {"type": "S3", "region": "us-east-1"}
    }
    allowed, prov_list, _ = evaluate_policy_allows_resources_with_provenance(
        policy_doc=policy_doc,
        policy_name="FinancePolicy",
        known_resources=known_resources
    )
    # Unmet condition should NOT allow resource access without matching context
    assert len(allowed) == 0


def test_stable_id_preservation():
    raw_data = {
        "iam_users": [
            {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}
        ],
        "s3_buckets": [
            {"Name": "prod-data", "Arn": "arn:aws:s3:::prod-data", "region": "us-east-1"}
        ]
    }
    G = build_local_graph(raw_data)
    assert G.has_node("arn:aws:iam::123456789012:user/alice")
    assert G.has_node("arn:aws:s3:::prod-data")
    assert G.nodes["arn:aws:s3:::prod-data"]["type"] == "S3"


def test_safe_add_edge_semantic_validation_rejects_illegal_edges():
    # Secret cannot ALLOW User
    is_valid, reason = validate_edge("Secret", "ALLOWS", "User")
    assert not is_valid
    assert "Disallowed relationship" in reason

    # Role CAN_ASSUME Role is valid
    is_valid_role, _ = validate_edge("Role", "CAN_ASSUME", "Role")
    assert is_valid_role

    # User MEMBER_OF Group is valid
    is_valid_group, _ = validate_edge("User", "MEMBER_OF", "Group")
    assert is_valid_group


def test_member_of_edge_provenance():
    raw_data = {
        "iam_users": [
            {
                "UserName": "bob",
                "Arn": "arn:aws:iam::123456789012:user/bob",
                "Groups": ["Developers"]
            }
        ],
        "iam_groups": [
            {"GroupName": "Developers", "Arn": "arn:aws:iam::123456789012:group/Developers"}
        ]
    }
    G = build_local_graph(raw_data)
    u_id = "arn:aws:iam::123456789012:user/bob"
    g_id = "arn:aws:iam::123456789012:group/Developers"
    assert G.has_edge(u_id, g_id)
    edge = G[u_id][g_id]
    assert edge["relationship"] == "MEMBER_OF"
    assert "provenance" in edge
    assert edge["provenance"]["edge_type"] == "MEMBER_OF"
    assert "IAM Group Membership" in edge["provenance"]["why"]


def test_has_policy_attached_to_edge_provenance():
    raw_data = {
        "iam_users": [
            {
                "UserName": "carol",
                "Arn": "arn:aws:iam::123456789012:user/carol",
                "AttachedPolicies": [
                    {"PolicyName": "SecurityAudit", "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"}
                ]
            }
        ]
    }
    G = build_local_graph(raw_data)
    u_id = "arn:aws:iam::123456789012:user/carol"
    p_id = "arn:aws:iam::aws:policy/SecurityAudit"
    assert G.has_edge(u_id, p_id)
    edge = G[u_id][p_id]
    assert edge["relationship"] == "HAS_POLICY"
    assert edge["provenance"]["policy_name"] == "SecurityAudit"


def test_trust_evidence_in_can_assume_edge():
    raw_data = {
        "iam_users": [
            {
                "UserName": "dave",
                "Arn": "arn:aws:iam::123456789012:user/dave",
                "AttachedPolicies": [
                    {
                        "PolicyName": "AssumeOpsRolePolicy",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Sid": "AllowAssumeOps",
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Resource": "arn:aws:iam::123456789012:role/OpsRole"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "iam_roles": [
            {
                "RoleName": "OpsRole",
                "Arn": "arn:aws:iam::123456789012:role/OpsRole",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Sid": "TrustDave",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:user/dave"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            }
        ]
    }
    G = build_local_graph(raw_data)
    u_id = "arn:aws:iam::123456789012:user/dave"
    r_id = "arn:aws:iam::123456789012:role/OpsRole"
    assert G.has_edge(u_id, r_id)
    edge = G[u_id][r_id]
    assert edge["relationship"] == "CAN_ASSUME"
    assert "TrustDave" in edge["provenance"]["statement_sid"]
    assert "sts:AssumeRole" in edge["provenance"]["action"]


def test_executes_with_edge_provenance():
    raw_data = {
        "ec2_instances": [
            {
                "InstanceId": "i-0123456789abcdef0",
                "region": "us-east-1",
                "State": {"Name": "running"},
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::123456789012:instance-profile/AppProfile"
                }
            }
        ],
        "iam_roles": [
            {
                "RoleName": "AppProfile",
                "Arn": "arn:aws:iam::123456789012:role/AppProfile",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            }
        ]
    }
    G = build_local_graph(raw_data)
    inst_id = "i-0123456789abcdef0"
    role_id = "arn:aws:iam::123456789012:role/AppProfile"
    assert G.has_edge(inst_id, role_id)
    edge = G[inst_id][role_id]
    assert edge["relationship"] == "EXECUTES_WITH"
    assert "ec2.amazonaws.com" in edge["provenance"]["why"]


def test_db_connect_edge_provenance():
    raw_data = {
        "iam_users": [
            {
                "UserName": "db_user",
                "Arn": "arn:aws:iam::123456789012:user/db_user",
                "AttachedPolicies": [
                    {
                        "PolicyName": "RDSConnectPolicy",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Sid": "AllowDBAuth",
                                    "Effect": "Allow",
                                    "Action": "rds-db:connect",
                                    "Resource": "arn:aws:rds-db:us-east-1:123456789012:dbuser:cluster-abc/app_user"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "rds_instances": [
            {
                "DBInstanceIdentifier": "cluster-abc",
                "DBClusterIdentifier": "cluster-abc",
                "Arn": "arn:aws:rds:us-east-1:123456789012:cluster:cluster-abc",
                "IAMDatabaseAuthenticationEnabled": True,
                "region": "us-east-1"
            }
        ]
    }
    G = build_local_graph(raw_data)
    u_id = "arn:aws:iam::123456789012:user/db_user"
    rds_id = "arn:aws:rds:us-east-1:123456789012:cluster:cluster-abc"
    assert G.has_edge(u_id, rds_id)
    edge = G[u_id][rds_id]
    assert edge["relationship"] == "DB_CONNECT"
    assert edge["provenance"]["action"] == "rds-db:connect"


def test_passrole_escalation_detection():
    G = nx.DiGraph()
    user_id = "arn:aws:iam::123456789012:user/dev_user"
    role_id = "arn:aws:iam::123456789012:role/HighPrivilegeExecutionRole"
    
    G.add_node(user_id, type="User", name="dev_user", riskScore=40)
    G.add_node(
        role_id,
        type="Role",
        name="HighPrivilegeExecutionRole",
        riskScore=85,
        assume_role_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    )
    # dev_user has permission to pass HighPrivilegeExecutionRole
    pass_perm = {
        "Action": "iam:PassRole",
        "Resource": role_id
    }
    user_permissions = [pass_perm]

    escalation = check_passrole_escalation(G, user_id, user_permissions)
    assert escalation is not None
    assert escalation["is_passrole"] is True
    assert escalation["target_role"] == role_id
    assert "lambda.amazonaws.com" in escalation["target_role_trust_evidence"]
    assert "Target role risk score: 85" in escalation["risk_elevation"]


def test_passrole_no_escalation_when_target_role_unprivileged():
    G = nx.DiGraph()
    user_id = "arn:aws:iam::123456789012:user/dev_user"
    role_id = "arn:aws:iam::123456789012:role/LowPrivilegeRole"
    
    G.add_node(user_id, type="User", name="dev_user", riskScore=20)
    G.add_node(
        role_id,
        type="Role",
        name="LowPrivilegeRole",
        riskScore=30,  # Below the 60 threshold
        assume_role_policy={
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ]
        }
    )
    user_permissions = [{"Action": "iam:PassRole", "Resource": role_id}]
    escalation = check_passrole_escalation(G, user_id, user_permissions)
    assert escalation is None


def test_passrole_no_escalation_when_service_trust_missing():
    G = nx.DiGraph()
    user_id = "arn:aws:iam::123456789012:user/dev_user"
    role_id = "arn:aws:iam::123456789012:role/AdminRole"
    
    G.add_node(user_id, type="User", name="dev_user", riskScore=30)
    G.add_node(
        role_id,
        type="Role",
        name="AdminRole",
        riskScore=90,
        assume_role_policy={
            # Only trusts a specific user, no AWS service trust to execute compute with PassRole
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "sts:AssumeRole"}
            ]
        }
    )
    user_permissions = [{"Action": "iam:PassRole", "Resource": role_id}]
    escalation = check_passrole_escalation(G, user_id, user_permissions)
    assert escalation is None


def test_ordered_nodes_and_ordered_relationships_in_attack_paths():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/alice"
    r = "arn:aws:iam::123456789012:role/S3Admin"
    s = "arn:aws:s3:::confidential-vault"

    G.add_node(u, type="User", name="alice", riskScore=50)
    G.add_node(r, type="Role", name="S3Admin", riskScore=70)
    G.add_node(s, type="S3", name="confidential-vault", riskScore=80, region="us-east-1")

    G.add_edge(u, r, relationship="CAN_ASSUME", provenance={"action": "sts:AssumeRole", "decision": "ALLOW", "why": "STS AssumeRole"})
    G.add_edge(r, s, relationship="ALLOWS", provenance={"action": "s3:*", "decision": "ALLOW", "why": "Full S3 Access"})

    engine = PathEngine()
    paths = engine.find_attack_paths(G)
    assert len(paths) >= 1
    p = paths[0]
    assert len(p["nodes"]) == 3
    assert len(p["ordered_relationships"]) == 2
    assert p["ordered_relationships"] == ["CAN_ASSUME", "ALLOWS"]
    assert "evidence" in p
    assert len(p["evidence"]) == 2
    assert p["evidence"][0]["relationship"] == "CAN_ASSUME"
    assert p["evidence"][1]["relationship"] == "ALLOWS"


def test_blast_radius_strict_resource_counting():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/attacker"
    r1 = "arn:aws:iam::123456789012:role/Role1"
    r2 = "arn:aws:iam::123456789012:role/Role2"
    p1 = "arn:aws:iam::123456789012:policy/Policy1"
    s3 = "arn:aws:s3:::target-bucket"
    sec = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-pw"

    G.add_node(u, type="User", name="attacker")
    G.add_node(r1, type="Role", name="Role1")
    G.add_node(r2, type="Role", name="Role2")
    G.add_node(p1, type="Policy", name="Policy1")
    G.add_node(s3, type="S3", name="target-bucket", region="us-west-2")
    G.add_node(sec, type="Secret", name="db-pw", region="us-east-1")

    G.add_edge(u, r1)
    G.add_edge(r1, r2)
    G.add_edge(r2, p1)
    G.add_edge(p1, s3)
    G.add_edge(r2, sec)

    radius = calculate_blast_radius(G, u)
    # Strictly count unique reachable cloud resources: S3 and Secret = 2 resources!
    # Intermediate IAM nodes (Role1, Role2, Policy1) must NOT be counted as target resources.
    assert radius["affected_resource_count"] == 2
    assert set(radius["resource_types"]) == {"S3", "Secret"}
    assert set(radius["regions"]) == {"us-west-2", "us-east-1"}


def test_region_field_preservation_across_all_findings():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/bob"
    s = "arn:aws:s3:::eu-central-vault"
    G.add_node(u, type="User", name="bob", riskScore=40)
    G.add_node(s, type="S3", name="eu-central-vault", riskScore=85, region="eu-central-1")
    G.add_edge(u, s, relationship="ALLOWS", provenance={"action": "s3:GetObject", "decision": "ALLOW", "region": "eu-central-1"})

    engine = PathEngine()
    paths = engine.find_attack_paths(G)
    assert len(paths) >= 1
    found = [p for p in paths if p["target"] == s]
    assert len(found) == 1
    assert found[0]["region"] == "eu-central-1"


def test_idempotent_graph_construction():
    raw_data = {
        "iam_users": [
            {
                "UserName": "eva",
                "Arn": "arn:aws:iam::123456789012:user/eva",
                "AttachedPolicies": [
                    {"PolicyName": "ReadOnly", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
                ]
            }
        ],
        "s3_buckets": [
            {"Name": "audit-bucket", "Arn": "arn:aws:s3:::audit-bucket", "region": "us-east-1"}
        ]
    }
    G1 = build_local_graph(raw_data)
    G2 = build_local_graph(raw_data)

    assert set(G1.nodes()) == set(G2.nodes())
    assert set(G1.edges()) == set(G2.edges())
    assert len(G1.edges()) == len(G2.edges())
