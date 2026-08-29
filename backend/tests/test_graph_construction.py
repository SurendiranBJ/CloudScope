import json
import pytest
import networkx as nx
from app.services.scanner.inventory import AWSInventory
from app.services.graph.graph_loader import build_local_graph
from app.services.attack.path_engine import find_attack_paths
from app.services.attack.blast_radius import calculate_blast_radius


def test_build_local_graph_and_attack_paths():
    inv = AWSInventory()
    inv.users = [
        {"id": "u1", "name": "alice", "arn": "arn:aws:iam::123:user/alice", "groups": ["DevGroup"], "policies": ["DevPolicy"], "riskScore": 75}
    ]
    inv.groups = [
        {"id": "g1", "name": "DevGroup", "arn": "arn:aws:iam::123:group/DevGroup", "attachedPolicies": []}
    ]
    inv.roles = [
        {
            "name": "AdminRole",
            "arn": "arn:aws:iam::123:role/AdminRole",
            "trustPolicy": json.dumps({
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:user/alice"}, "Action": "sts:AssumeRole"}]
            }),
            "attachedPolicies": ["AdminPolicy"],
            "riskScore": 85
        }
    ]
    inv.policies = [
        {
            "name": "DevPolicy",
            "arn": "arn:aws:iam::123:policy/DevPolicy",
            "type": "custom",
            "document": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::dev-bucket"}]}),
            "riskScore": 10
        },
        {
            "name": "AdminPolicy",
            "arn": "arn:aws:iam::123:policy/AdminPolicy",
            "type": "custom",
            "document": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
            "riskScore": 90
        }
    ]
    inv.s3 = [
        {"id": "dev-bucket", "name": "dev-bucket", "arn": "arn:aws:s3:::dev-bucket", "type": "S3", "region": "ap-south-1", "riskScore": 20, "status": "configured", "owner": "123"},
        {"id": "prod-secrets", "name": "prod-secrets", "arn": "arn:aws:s3:::prod-secrets", "type": "S3", "region": "ap-south-1", "riskScore": 90, "status": "critical", "owner": "123"}
    ]
    inv.secrets = [
        {"id": "db-creds", "name": "db-creds", "arn": "arn:aws:secretsmanager:ap-south-1:123:secret:db-creds", "type": "Secrets", "region": "ap-south-1", "riskScore": 80, "status": "warning", "owner": "123"}
    ]

    G = build_local_graph(inv)

    assert G.has_node("aws:user:alice")
    assert G.has_node("aws:role:AdminRole")
    assert G.has_node("aws:policy:AdminPolicy")
    assert G.has_node("aws:s3:prod-secrets")
    assert G.has_node("aws:secret:db-creds")

    # Verify relationships
    assert G.has_edge("aws:user:alice", "aws:role:AdminRole") # CAN_ASSUME
    assert G.has_edge("aws:role:AdminRole", "aws:policy:AdminPolicy") # HAS_POLICY
    assert G.has_edge("aws:policy:AdminPolicy", "aws:secret:db-creds") # ALLOWS

    # Find attack paths
    paths = find_attack_paths(G)
    assert len(paths) > 0
    # There should be an attack path from alice to db-creds
    alice_to_secrets = [p for p in paths if p["source"] == "aws:user:alice" and p["destination"] == "aws:secret:db-creds"]
    assert len(alice_to_secrets) == 1
    assert "CAN_ASSUME" in alice_to_secrets[0]["orderedRelationships"]
    assert alice_to_secrets[0]["severity"] == "critical"

    # Test blast radius
    blast = calculate_blast_radius(G, "aws:user:alice")
    assert blast["reachable_count"] >= 3
    assert blast["critical_assets_count"] >= 1
