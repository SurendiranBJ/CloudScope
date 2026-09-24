"""Tests for the attack path discovery engine (path_engine.py)."""
import networkx as nx
import pytest

from app.services.attack.path_engine import (
    find_attack_paths,
    compute_effective_blast_radius,
    _validate_path_security_semantics,
)


class TestFindAttackPaths:
    """Verify that find_attack_paths discovers expected paths in a
    synthetic graph conforming to canonical AWS IAM semantics."""

    def _build_graph(self):
        """Build a canonical graph:

            low-priv-user --CAN_ASSUME--> AdminRole --HAS_POLICY--> AdminPolicy --ALLOWS--> S3-Secret-Bucket

        The path engine should discover a path from the User to both the
        Role (escalation) and the S3 bucket (resource compromise).
        """
        G = nx.DiGraph()
        G.add_node("usr-001", label="low-priv-user", type="User", riskScore=20)
        G.add_node("rol-001", label="AdminRole", type="Role", riskScore=85)
        G.add_node("pol-001", label="AdminPolicy", type="Policy", riskScore=75)
        G.add_node("res-001", label="S3-Secret-Bucket", type="S3", riskScore=70)

        G.add_edge("usr-001", "rol-001", label="CAN_ASSUME")
        G.add_edge("rol-001", "pol-001", label="HAS_POLICY")
        G.add_edge("pol-001", "res-001", label="ALLOWS")
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
        """The discovered path usr-001 → rol-001 → pol-001 → res-001 should have
        4 nodes (User -> Role -> Policy -> Resource)."""
        G = self._build_graph()
        paths = find_attack_paths(G)

        user_to_s3 = [
            p for p in paths
            if any(n["id"] == "usr-001" for n in p["nodes"])
            and any(n["id"] == "res-001" for n in p["nodes"])
        ]
        assert len(user_to_s3) >= 1
        assert len(user_to_s3[0]["nodes"]) == 4

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

    def test_direct_role_to_resource_shortcut_rejected(self):
        """A Role cannot directly allow access to a Resource without a Policy in AWS IAM.
        Direct edges like Role -CAN_ACCESS-> S3 or Role -ALLOWS-> S3 must be rejected."""
        G = nx.DiGraph()
        G.add_node("usr-001", label="dave", type="User", riskScore=20)
        G.add_node("rol-001", label="AdminRole", type="Role", riskScore=80)
        G.add_node("res-001", label="DataBucket", type="S3", riskScore=70)

        G.add_edge("usr-001", "rol-001", label="CAN_ASSUME")
        G.add_edge("rol-001", "res-001", label="CAN_ACCESS")

        paths = find_attack_paths(G)
        user_to_s3 = [p for p in paths if p["source"] == "usr-001" and p["destination"] == "res-001"]
        assert len(user_to_s3) == 0, "Direct Role->Resource shortcut must be rejected"

    def test_effective_blast_radius_counts_only_cloud_assets(self):
        """Blast radius must count actual cloud resources (S3, Secrets, RDS, etc.)
        and never count identity/privilege nodes (User, Group, Role, Policy)."""
        G = nx.DiGraph()
        G.add_node("usr-001", label="eve", type="User", riskScore=30)
        G.add_node("grp-001", label="DevGroup", type="Group")
        G.add_node("rol-001", label="AppRole", type="Role", riskScore=60)
        G.add_node("pol-001", label="AppPolicy", type="Policy")
        G.add_node("s3-001", label="Bucket1", type="S3", riskScore=50)
        G.add_node("s3-002", label="Bucket2", type="S3", riskScore=60)
        G.add_node("sec-001", label="DbPassword", type="Secrets", riskScore=90)

        # Structure: User -> Group -> Policy -> Bucket1
        # Also User -> Role -> Policy -> Bucket2 & DbPassword
        G.add_edge("usr-001", "grp-001", label="MEMBER_OF")
        G.add_edge("grp-001", "pol-001", label="HAS_POLICY")
        G.add_edge("pol-001", "s3-001", label="ALLOWS")

        G.add_edge("usr-001", "rol-001", label="CAN_ASSUME")
        G.add_edge("rol-001", "pol-001", label="HAS_POLICY")
        G.add_edge("pol-001", "s3-002", label="ALLOWS")
        G.add_edge("pol-001", "sec-001", label="ALLOWS")

        desc, count = compute_effective_blast_radius("usr-001", G)
        # Even though there are 4 identity/privilege nodes (User, Group, Role, Policy),
        # only the 3 unique cloud assets (Bucket1, Bucket2, DbPassword) must be counted.
        assert count == 3
        assert "3 unique cloud assets" in desc

    def test_deterministic_path_sorting(self):
        """Paths must be sorted deterministically: -riskScore, hopCount, source, destination."""
        G = nx.DiGraph()
        G.add_node("usr-001", label="alice", type="User", riskScore=10)
        G.add_node("pol-001", label="LowPol", type="Policy", riskScore=20)
        G.add_node("pol-002", label="HighPol", type="Policy", riskScore=90)
        G.add_node("res-low", label="LowBucket", type="S3", riskScore=20)
        G.add_node("res-high", label="HighSecret", type="Secrets", riskScore=95)

        G.add_edge("usr-001", "pol-001", label="HAS_POLICY")
        G.add_edge("pol-001", "res-low", label="ALLOWS")

        G.add_edge("usr-001", "pol-002", label="HAS_POLICY")
        G.add_edge("pol-002", "res-high", label="ALLOWS")

        paths = find_attack_paths(G)
        assert len(paths) >= 2
        # First path must have higher or equal riskScore than second
        assert paths[0]["riskScore"] >= paths[1]["riskScore"]
        assert paths[0]["destination"] == "res-high"

    def test_target_discovery_all_cloud_resource_types(self):
        """Verify attack paths ending at ALL cloud resource types are discovered:
        1. User -> Policy -> Lambda (COMPUTE_RESOURCE)
        2. User -> Policy -> EC2 (COMPUTE_RESOURCE)
        3. User -> Policy -> S3 (DATA_RESOURCE)
        4. User -> Role -> Policy -> RDS (DATA_RESOURCE)
        5. User -> Role -> Policy -> Secrets (CREDENTIAL_RESOURCE)
        6. User -> Policy -> DynamoDB (DATA_RESOURCE)
        """
        G = nx.DiGraph()
        G.add_node("usr-001", label="alice", type="User", riskScore=20)
        G.add_node("rol-001", label="DataRole", type="Role", riskScore=70)
        G.add_node("pol-compute", label="ComputePolicy", type="Policy", riskScore=40)
        G.add_node("pol-data", label="DataPolicy", type="Policy", riskScore=60)

        # Resources
        G.add_node("lambda-001", label="ProcessOrderFunction", type="Lambda", riskScore=30)
        G.add_node("ec2-001", label="WebServerInstance", type="EC2", riskScore=45)
        G.add_node("s3-001", label="DataArchiveBucket", type="S3", riskScore=50)
        G.add_node("rds-001", label="ProductionPostgres", type="RDS", riskScore=80)
        G.add_node("sec-001", label="StripeApiKey", type="Secrets", riskScore=90)
        G.add_node("dyn-001", label="SessionsTable", type="DynamoDB", riskScore=40)

        # Direct policy edges to compute & S3 & DynamoDB
        G.add_edge("usr-001", "pol-compute", label="HAS_POLICY")
        G.add_edge("pol-compute", "lambda-001", label="ALLOWS")
        G.add_edge("pol-compute", "ec2-001", label="ALLOWS")
        G.add_edge("pol-compute", "s3-001", label="ALLOWS")
        G.add_edge("pol-compute", "dyn-001", label="ALLOWS")

        # AssumeRole chain to RDS and Secrets
        G.add_edge("usr-001", "rol-001", label="CAN_ASSUME")
        G.add_edge("rol-001", "pol-data", label="HAS_POLICY")
        G.add_edge("pol-data", "rds-001", label="ALLOWS")
        G.add_edge("pol-data", "sec-001", label="ALLOWS")

        paths = find_attack_paths(G)

        # 1. Lambda path discovered
        lambda_paths = [p for p in paths if p["destination"] == "lambda-001"]
        assert len(lambda_paths) == 1, "Expected path to Lambda"
        assert lambda_paths[0]["target_type"] == "Lambda"
        assert lambda_paths[0]["target_category"] == "COMPUTE_RESOURCE"
        assert lambda_paths[0]["pathType"] == "compute_resource_access"

        # 2. EC2 path discovered
        ec2_paths = [p for p in paths if p["destination"] == "ec2-001"]
        assert len(ec2_paths) == 1, "Expected path to EC2"
        assert ec2_paths[0]["target_type"] == "EC2"
        assert ec2_paths[0]["target_category"] == "COMPUTE_RESOURCE"
        assert ec2_paths[0]["pathType"] == "compute_resource_access"

        # 3. S3 path discovered
        s3_paths = [p for p in paths if p["destination"] == "s3-001"]
        assert len(s3_paths) == 1, "Expected path to S3"
        assert s3_paths[0]["target_type"] == "S3"
        assert s3_paths[0]["target_category"] == "DATA_RESOURCE"

        # 4. RDS path discovered
        rds_paths = [p for p in paths if p["destination"] == "rds-001"]
        assert len(rds_paths) == 1, "Expected path to RDS"
        assert rds_paths[0]["target_type"] == "RDS"
        assert rds_paths[0]["target_category"] == "DATA_RESOURCE"
        assert rds_paths[0]["pathType"] == "sensitive_resource_access"

        # 5. Secrets path discovered
        sec_paths = [p for p in paths if p["destination"] == "sec-001"]
        assert len(sec_paths) == 1, "Expected path to Secrets"
        assert sec_paths[0]["target_type"] == "Secrets"
        assert sec_paths[0]["target_category"] == "CREDENTIAL_RESOURCE"
        assert sec_paths[0]["pathType"] == "sensitive_resource_access"

        # 6. DynamoDB path discovered
        dyn_paths = [p for p in paths if p["destination"] == "dyn-001"]
        assert len(dyn_paths) == 1, "Expected path to DynamoDB"
        assert dyn_paths[0]["target_type"] == "DynamoDB"
        assert dyn_paths[0]["target_category"] == "DATA_RESOURCE"

    def test_lambda_workload_start_with_explicit_evidence(self):
        """Verify Lambda is accepted as an attack starting point ONLY when it has
        explicit structural evidence of an execution role with attached policies,
        and not when unconfigured/dormant."""
        G = nx.DiGraph()
        # Lambda 1: Configured workload with execution role & policy
        G.add_node("lambda-workload", label="ReportGenerator", type="Lambda", riskScore=40)
        G.add_node("rol-exec", label="ReportExecRole", type="Role", riskScore=60,
                   assume_role_policy='{"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}')
        G.add_node("pol-s3", label="ReportS3Policy", type="Policy")
        G.add_node("s3-target", label="CompanyReports", type="S3", riskScore=50)

        G.add_edge("lambda-workload", "rol-exec", label="EXECUTES_WITH")
        G.add_edge("rol-exec", "pol-s3", label="HAS_POLICY")
        G.add_edge("pol-s3", "s3-target", label="ALLOWS")

        # Lambda 2: Unconfigured Lambda without an execution role
        G.add_node("lambda-dormant", label="DormantFunction", type="Lambda", riskScore=20)

        paths = find_attack_paths(G)

        # Workload Lambda -> Role -> Policy -> S3 must be found
        workload_paths = [p for p in paths if p["source"] == "lambda-workload"]
        assert len(workload_paths) == 1
        assert workload_paths[0]["destination"] == "s3-target"
        assert workload_paths[0]["orderedRelationships"] == ["EXECUTES_WITH", "HAS_POLICY", "ALLOWS"]

        # Dormant Lambda must NOT be considered an attack start
        dormant_paths = [p for p in paths if p["source"] == "lambda-dormant"]
        assert len(dormant_paths) == 0

    def test_lambda_execution_role_s3_not_attributed_to_invoking_user(self):
        """Preserve difference between direct access and execution-role access:
        Carol invoking FirstLambda does NOT collapse into Carol having direct S3 access."""
        G = nx.DiGraph()
        G.add_node("carol-no-mfa", label="carol-no-mfa", type="User", riskScore=25)
        G.add_node("pol-invoke", label="CarolInvokePolicy", type="Policy")
        G.add_node("fn-first", label="FirstLambda", type="Lambda", riskScore=30)
        G.add_node("rol-exec", label="LambdaExecutionRole", type="Role", riskScore=70,
                   assume_role_policy='{"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}')
        G.add_node("pol-s3", label="S3FullAccessPolicy", type="Policy")
        G.add_node("s3-bucket", label="production-data-bucket", type="S3", riskScore=75)

        # Carol -> Policy -> FirstLambda
        G.add_edge("carol-no-mfa", "pol-invoke", label="HAS_POLICY")
        G.add_edge("pol-invoke", "fn-first", label="ALLOWS")

        # FirstLambda -> Role -> Policy -> S3
        G.add_edge("fn-first", "rol-exec", label="EXECUTES_WITH")
        G.add_edge("rol-exec", "pol-s3", label="HAS_POLICY")
        G.add_edge("pol-s3", "s3-bucket", label="ALLOWS")

        paths = find_attack_paths(G)

        # Carol has path to FirstLambda
        carol_to_lambda = [p for p in paths if p["source"] == "carol-no-mfa" and p["destination"] == "fn-first"]
        assert len(carol_to_lambda) == 1

        # Carol does NOT have a valid semantic path directly to s3-bucket without valid transitions
        carol_to_s3 = [p for p in paths if p["source"] == "carol-no-mfa" and p["destination"] == "s3-bucket"]
        assert len(carol_to_s3) == 0, "Carol must not receive direct path to S3"

        # The workload path from FirstLambda -> s3-bucket is present independently
        lambda_to_s3 = [p for p in paths if p["source"] == "fn-first" and p["destination"] == "s3-bucket"]
        assert len(lambda_to_s3) == 1

