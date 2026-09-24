import networkx as nx
import pytest
from app.services.attack.path_engine import find_attack_paths, get_downstream_reachable_assets


class TestRoleTargetDownstreamAssets:
    """Regression test suite for Cases A, B, C, D, E specified in task."""

    def test_case_a_user_to_elevated_role_with_downstream_assets(self):
        """CASE A: User -> elevated Role
        Expected:
        - Role remains the attack-path target.
        - Downstream reachable assets are present.
        - Blast radius count equals actual assets shown.
        """
        G = nx.DiGraph()
        G.add_node("u-1", label="Surendiran", type="User", riskScore=20)
        G.add_node("r-admin", label="OverlyTrustingAdminRole", type="Role", riskScore=85)
        G.add_node("pol-admin", label="AdminPolicy", type="Policy", riskScore=80)
        G.add_edge("u-1", "r-admin", label="CAN_ASSUME")
        G.add_edge("r-admin", "pol-admin", label="HAS_POLICY")

        # 9 reachable assets matching the screenshot scenario (4 S3, 1 EC2, 3 Lambda, 1 RDS)
        assets = [
            ("s3-1", "bucket-alpha", "S3", 65),
            ("s3-2", "bucket-beta", "S3", 65),
            ("s3-3", "bucket-gamma", "S3", 65),
            ("s3-4", "bucket-delta", "S3", 65),
            ("ec2-1", "i-prod-web", "EC2", 70),
            ("lam-1", "payment-fn", "Lambda", 75),
            ("lam-2", "auth-fn", "Lambda", 75),
            ("lam-3", "report-fn", "Lambda", 75),
            ("rds-1", "customer-db", "RDS", 85),
        ]
        for aid, aname, atype, arisk in assets:
            G.add_node(aid, label=aname, type=atype, riskScore=arisk, region="us-east-1")
            G.add_edge("pol-admin", aid, label="ALLOWS", action=f"{atype.lower()}:*")

        paths = find_attack_paths(G)

        # Locate the direct User -> Role path
        role_paths = [p for p in paths if p["target"] == "r-admin" and p["source"] == "u-1"]
        assert len(role_paths) >= 1, "User -> Role attack path must be discovered"

        role_path = role_paths[0]
        # Role remains the attack-path target
        assert role_path["target_type"] == "Role"
        assert role_path["destination"] == "r-admin"
        assert len(role_path["nodes"]) == 2
        assert role_path["nodes"][-1]["type"] == "Role"
        assert role_path["nodes"][-1]["name"] == "OverlyTrustingAdminRole"

        # Downstream reachable assets are present
        downstream = role_path.get("downstream_reachable_assets", [])
        assert len(downstream) == 9, f"Expected 9 downstream assets, got {len(downstream)}"

        types_found = {a["type"] for a in downstream}
        assert types_found == {"S3", "EC2", "Lambda", "RDS"}

        # Blast radius count equals actual assets shown
        assert role_path["blastRadius"] == "High (9 unique cloud assets)"
        assert f"({len(downstream)} unique cloud assets)" in role_path["blastRadius"]

    def test_case_b_user_to_s3_direct_target(self):
        """CASE B: User -> Role -> Policy -> S3
        Expected:
        - S3 remains the direct path target.
        - No duplicate downstream asset section is required.
        """
        G = nx.DiGraph()
        G.add_node("u-1", label="Alice", type="User", riskScore=20)
        G.add_node("r-1", label="StorageRole", type="Role", riskScore=50)
        G.add_node("pol-1", label="S3Policy", type="Policy", riskScore=60)
        G.add_node("s3-target", label="data-bucket", type="S3", riskScore=70)
        G.add_edge("u-1", "r-1", label="CAN_ASSUME")
        G.add_edge("r-1", "pol-1", label="HAS_POLICY")
        G.add_edge("pol-1", "s3-target", label="ALLOWS")

        paths = find_attack_paths(G)
        s3_paths = [p for p in paths if p["target"] == "s3-target"]
        assert len(s3_paths) >= 1
        p = s3_paths[0]
        assert p["target_type"] == "S3"
        assert p["nodes"][-1]["id"] == "s3-target"
        # Terminal resource target has no downstream role expansion
        assert p.get("downstream_reachable_assets") == []

    def test_case_c_user_to_lambda_direct_target(self):
        """CASE C: User -> Role -> Policy -> Lambda
        Expected:
        - Lambda target displayed.
        """
        G = nx.DiGraph()
        G.add_node("u-1", label="Bob", type="User", riskScore=20)
        G.add_node("r-1", label="ComputeRole", type="Role", riskScore=50)
        G.add_node("pol-1", label="LambdaPolicy", type="Policy", riskScore=60)
        G.add_node("lam-target", label="process-function", type="Lambda", riskScore=70)
        G.add_edge("u-1", "r-1", label="CAN_ASSUME")
        G.add_edge("r-1", "pol-1", label="HAS_POLICY")
        G.add_edge("pol-1", "lam-target", label="ALLOWS")

        paths = find_attack_paths(G)
        lam_paths = [p for p in paths if p["target"] == "lam-target"]
        assert len(lam_paths) >= 1
        p = lam_paths[0]
        assert p["target_type"] == "Lambda"
        assert p["nodes"][-1]["id"] == "lam-target"

    def test_case_d_user_to_ec2_direct_target(self):
        """CASE D: User -> Role -> Policy -> EC2
        Expected:
        - EC2 target displayed.
        """
        G = nx.DiGraph()
        G.add_node("u-1", label="Charlie", type="User", riskScore=20)
        G.add_node("r-1", label="Ec2AdminRole", type="Role", riskScore=50)
        G.add_node("pol-1", label="Ec2Policy", type="Policy", riskScore=60)
        G.add_node("ec2-target", label="i-database-worker", type="EC2", riskScore=70)
        G.add_edge("u-1", "r-1", label="CAN_ASSUME")
        G.add_edge("r-1", "pol-1", label="HAS_POLICY")
        G.add_edge("pol-1", "ec2-target", label="ALLOWS")

        paths = find_attack_paths(G)
        ec2_paths = [p for p in paths if p["target"] == "ec2-target"]
        assert len(ec2_paths) >= 1
        p = ec2_paths[0]
        assert p["target_type"] == "EC2"
        assert p["nodes"][-1]["id"] == "ec2-target"

    def test_case_e_role_has_s3_user_has_no_direct_s3_access(self):
        """CASE E: Role has S3 access but user does not directly have S3 access.
        Expected:
        - UI / Engine must not rewrite the original User -> Role path into User -> S3.
        - User -> Role remains distinct, with Role as target and S3 in downstream assets.
        """
        G = nx.DiGraph()
        G.add_node("u-carol", label="Carol", type="User", riskScore=20)
        G.add_node("r-power", label="PowerUserRole", type="Role", riskScore=80)
        G.add_node("pol-s3", label="S3FullAccess", type="Policy", riskScore=75)
        G.add_node("s3-confidential", label="confidential-bucket", type="S3", riskScore=85)

        # User CAN_ASSUME Role, Role HAS_POLICY Policy ALLOWS S3
        # Carol has NO direct edge to pol-s3 or s3-confidential
        G.add_edge("u-carol", "r-power", label="CAN_ASSUME")
        G.add_edge("r-power", "pol-s3", label="HAS_POLICY")
        G.add_edge("pol-s3", "s3-confidential", label="ALLOWS")

        paths = find_attack_paths(G)

        # 1. The User -> Role path exists and its target is specifically Role (not rewritten to S3)
        role_paths = [p for p in paths if p["source"] == "u-carol" and p["target"] == "r-power"]
        assert len(role_paths) >= 1, "User -> Role path must exist as a dedicated path"
        rp = role_paths[0]
        assert rp["target_type"] == "Role"
        assert rp["destination"] == "r-power"
        assert rp["nodes"][-1]["id"] == "r-power"
        assert rp["nodes"][-1]["type"] == "Role"

        # 2. Downstream assets of this role path contains the S3 bucket
        downstream = rp.get("downstream_reachable_assets", [])
        assert any(a["name"] == "confidential-bucket" for a in downstream), \
            "confidential-bucket must appear as downstream impact of PowerUserRole"
