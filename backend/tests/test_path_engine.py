"""Tests for the attack path discovery engine (path_engine.py)."""
import networkx as nx
import pytest

from app.services.attack.path_engine import find_attack_paths


class TestFindAttackPaths:
    """Verify that find_attack_paths discovers expected paths in a
    synthetic graph."""

    def _build_graph(self):
        """Build a small graph:

            low-priv-user  --CAN_ASSUME-->  AdminRole  --CAN_ACCESS-->  S3-Secret-Bucket

        The path engine should discover a path from the User to both the
        Role and the S3 bucket.
        """
        G = nx.DiGraph()
        G.add_node("usr-001", label="low-priv-user", type="User", riskScore=20)
        G.add_node("rol-001", label="AdminRole", type="Role", riskScore=85)
        G.add_node("res-001", label="S3-Secret-Bucket", type="S3", riskScore=70)

        G.add_edge("usr-001", "rol-001", label="CAN_ASSUME")
        G.add_edge("rol-001", "res-001", label="CAN_ACCESS")
        return G

    def test_path_is_discovered(self):
        """At least one path should be found from the low-priv user to
        the S3 bucket target."""
        G = self._build_graph()
        paths = find_attack_paths(G)

        # There should be at least one path whose nodes include our user
        # and the S3 bucket.
        user_to_s3 = [
            p for p in paths
            if any(n["id"] == "usr-001" for n in p["nodes"])
            and any(n["id"] == "res-001" for n in p["nodes"])
        ]
        assert len(user_to_s3) >= 1, "Expected a path from usr-001 to res-001"

    def test_path_contains_intermediate_hop(self):
        """The discovered path usr-001 → rol-001 → res-001 should have
        3 nodes (including the intermediate Role hop)."""
        G = self._build_graph()
        paths = find_attack_paths(G)

        user_to_s3 = [
            p for p in paths
            if any(n["id"] == "usr-001" for n in p["nodes"])
            and any(n["id"] == "res-001" for n in p["nodes"])
        ]
        assert len(user_to_s3) >= 1
        # The path should be usr-001 → rol-001 → res-001 (3 nodes)
        assert len(user_to_s3[0]["nodes"]) == 3

    def test_path_metadata_populated(self):
        """The returned path dict must have required schema fields and no likelihood."""
        G = self._build_graph()
        paths = find_attack_paths(G)
        assert len(paths) >= 1

        p = paths[0]
        assert "id" in p
        assert "severity" in p
        assert "riskScore" in p
        assert "likelihood" not in p  # Deprecated and removed from output dict
        assert "blastRadius" in p
        assert "mitreTechniques" in p
        assert isinstance(p["mitreTechniques"], list)
        assert "recommendation" in p
        assert "nodes" in p

    def test_no_paths_in_disconnected_graph(self):
        """If there is no edge from any start to any target, zero paths
        should be returned."""
        G = nx.DiGraph()
        G.add_node("usr-001", label="isolated-user", type="User", riskScore=10)
        G.add_node("res-001", label="isolated-bucket", type="S3", riskScore=10)
        # No edges connecting them.

        paths = find_attack_paths(G)
        assert len(paths) == 0

    def test_multiple_distinct_paths_both_discovered(self):
        """When an identity reaches a target via two distinct roles, both paths
        must be discovered and returned."""
        G = nx.DiGraph()
        G.add_node("usr-001", label="alice", type="User", riskScore=30)
        G.add_node("rol-001", label="DevRole", type="Role", riskScore=50)
        G.add_node("rol-002", label="SecRole", type="Role", riskScore=75)
        G.add_node("pol-001", label="DevPolicy", type="Policy")
        G.add_node("pol-002", label="SecPolicy", type="Policy")
        G.add_node("res-001", label="ProductionDB", type="RDS", riskScore=90)

        # Path 1: alice -> DevRole -> DevPolicy -> ProductionDB
        G.add_edge("usr-001", "rol-001", label="CAN_ASSUME")
        G.add_edge("rol-001", "pol-001", label="HAS_POLICY")
        G.add_edge("pol-001", "res-001", label="ALLOWS")

        # Path 2: alice -> SecRole -> SecPolicy -> ProductionDB
        G.add_edge("usr-001", "rol-002", label="CAN_ASSUME")
        G.add_edge("rol-002", "pol-002", label="HAS_POLICY")
        G.add_edge("pol-002", "res-001", label="ALLOWS")

        paths = find_attack_paths(G)
        db_paths = [p for p in paths if p["destination"] == "res-001"]
        assert len(db_paths) == 2, f"Expected 2 distinct paths to ProductionDB, found {len(db_paths)}"

    def test_semantically_invalid_path_rejected(self):
        """Graph connectivity that violates AWS IAM security semantics
        (e.g., User -> EC2 -> CONNECTED_TO -> S3) must be rejected."""
        G = nx.DiGraph()
        G.add_node("usr-001", label="charlie", type="User", riskScore=20)
        G.add_node("ec2-001", label="WebInstance", type="EC2", riskScore=40)
        G.add_node("res-001", label="SecretBucket", type="S3", riskScore=80)

        # Semantically invalid: User cannot traverse directly to EC2 via arbitrary edge
        G.add_edge("usr-001", "ec2-001", label="CONNECTED_TO")
        G.add_edge("ec2-001", "res-001", label="CONNECTED_TO")

        paths = find_attack_paths(G)
        user_to_s3 = [p for p in paths if p["source"] == "usr-001" and p["destination"] == "res-001"]
        assert len(user_to_s3) == 0, "Invalid connectivity path must be rejected by validator"
