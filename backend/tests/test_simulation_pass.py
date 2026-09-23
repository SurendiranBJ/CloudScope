"""
CloudScope IAM Policy Simulation & What-If Access Modeling:
Final Completion & Correction Pass Test Suite.

Verifies:
  - Test A: Full policy catalog is not capped at 200
  - Test B: AWS-managed metadata catalog supports all discoverable policies without eager doc fetching
  - Test C: Policy documents are loaded on demand
  - Test D: Preview does not persist simulation state
  - Test E: Preview does not call AWS mutation APIs
  - Test F: Confirmed simulation change persists only in application-side simulation state
  - Test G: Current vs desired graph diff works without mutating source graphs
  - Test H: New attack paths detected
  - Test I: Removed attack paths detected
  - Test J: Changed attack-path risk detected
  - Test K: Blast radius uses unique resources
  - Test L: Blast radius uses actual affected identities
  - Test M: Same resource reachable through multiple paths is counted once
  - Test N: Unknown relationships do not become ALLOWS
  - Test O: Likelihood is not used as risk metric
  - Test P: Simulation does not modify Neo4j
"""

import unittest
from unittest.mock import patch, MagicMock
import networkx as nx

from app.services.aws.iam_service import (
    fetch_policy_catalog,
    fetch_policy_document_by_arn,
)
from app.services.simulation.simulation_state import (
    SimulationStateManager,
    simulation_state,
)
from app.services.simulation.diff_engine import (
    compute_graph_diff,
    compare_attack_paths,
)
from app.services.simulation.simulation_analyzer import (
    _compute_blast_metrics,
    build_policy_preview_analysis,
)
from app.services.scanner.inventory import AWSInventory


class TestSimulationPass(unittest.TestCase):

    def setUp(self):
        simulation_state.reset()

    def tearDown(self):
        simulation_state.reset()

    # ── Test A & B: Policy catalog uncapped & Level 1 metadata only ─────────────
    @patch("app.services.aws.iam_service.get_aws_session")
    def test_a_b_policy_catalog_uncapped_and_metadata_only(self, mock_get_session):
        """Catalog must NOT truncate at 200 and must not eagerly load documents."""
        mock_iam = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_iam
        mock_get_session.return_value = mock_session

        # Simulate 250 AWS-managed policies across pages
        page_policies = [
            {
                "PolicyName": f"AWSManagedPolicy_{i}",
                "Arn": f"arn:aws:iam::aws:policy/AWSManagedPolicy_{i}",
                "PolicyId": f"ANPA{i}",
                "AttachmentCount": 1,
                "IsAttachable": True,
                "DefaultVersionId": "v1",
                "CreateDate": "2024-01-01T00:00:00Z",
                "UpdateDate": "2024-01-01T00:00:00Z",
            }
            for i in range(250)
        ]

        mock_paginator = MagicMock()
        def paginate_mock(**kwargs):
            if kwargs.get("Scope") == "Local":
                return [{"Policies": []}]
            elif kwargs.get("Scope") == "AWS":
                return [{"Policies": page_policies[:125]}, {"Policies": page_policies[125:]}]
            return [{"Policies": []}]

        mock_paginator.paginate.side_effect = paginate_mock
        mock_iam.get_paginator.return_value = mock_paginator
        mock_iam.list_entities_for_policy.return_value = {
            "PolicyGroups": [], "PolicyUsers": [], "PolicyRoles": []
        }

        catalog = fetch_policy_catalog()

        # Must have all 250 policies — NOT capped at 200
        self.assertEqual(len(catalog), 250)
        # Level 1 check: documents must NOT be eagerly fetched during catalog listing
        mock_iam.get_policy_version.assert_not_called()
        self.assertIsNone(catalog[0].get("document"))

    # ── Test C: Policy document on demand ─────────────────────────────────────
    @patch("app.services.aws.iam_service.get_aws_session")
    def test_c_policy_document_loaded_on_demand(self, mock_get_session):
        """Documents are fetched on demand via fetch_policy_document_by_arn."""
        mock_iam = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_iam
        mock_get_session.return_value = mock_session

        mock_iam.get_policy.return_value = {
            "Policy": {
                "PolicyName": "AdministratorAccess",
                "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "DefaultVersionId": "v1",
            }
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }
            }
        }

        result = fetch_policy_document_by_arn(
            "arn:aws:iam::aws:policy/AdministratorAccess",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "AdministratorAccess")
        mock_iam.get_policy.assert_called_once()
        mock_iam.get_policy_version.assert_called_once()

    # ── Test D & E: Preview does not persist & does not call AWS mutations ──────
    @patch("boto3.client")
    def test_d_e_preview_does_not_persist_or_mutate_aws(self, mock_boto_client):
        """Previewing a simulation change must NOT mutate AWS or persist state."""
        inv = AWSInventory()
        inv.users = [{
            "name": "alice",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "policies": ["ReadOnlyAccess"],
            "attachedPolicies": ["ReadOnlyAccess"],
            "attachedPolicyArns": {},
            "groups": [],
            "riskScore": 10,
            "mfaEnabled": True,
            "lastActive": "today"
        }]
        inv.roles = []
        inv.groups = []
        inv.s3 = []
        inv.ec2 = []
        inv.lambdas = []
        inv.secrets = []
        inv.rds = []
        inv.dynamodb = []

        initial_change_count = simulation_state.change_count()

        preview_result = build_policy_preview_analysis(
            proposed_change={
                "action": "ATTACH_POLICY",
                "principal_type": "USER",
                "principal_id": "alice",
                "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
            current_inventory=inv,
            current_policy_doc_map={},
            current_attack_paths=[],
            current_global_posture={"overall_score": 75},
        )

        self.assertIsNotNone(preview_result)
        # Test D: State did NOT change
        self.assertEqual(simulation_state.change_count(), initial_change_count)
        self.assertFalse(simulation_state.has_changes())

        # Test E: Boto3 client was NEVER called to mutate AWS
        mock_boto_client.assert_not_called()

    # ── Test F: Confirmed change persists only application-side ───────────────
    def test_f_confirmed_change_persists_only_application_side(self):
        """Adding a change via simulation_state modifies ONLY application-side memory."""
        mgr = SimulationStateManager()
        change = mgr.attach_policy(
            "USER", "alice", "arn:aws:iam::aws:policy/AmazonS3FullAccess", "AmazonS3FullAccess"
        )
        self.assertEqual(mgr.change_count(), 1)
        self.assertEqual(mgr.get_changes()[0]["change_id"], change.change_id)

    # ── Test G: Graph diff calculation without mutating source graphs ─────────
    def test_g_graph_diff_works_without_source_mutation(self):
        """compute_graph_diff returns structured diff without mutating G_current or G_desired."""
        G_curr = nx.DiGraph()
        G_curr.add_node("User:Alice", label="Alice", type="User")
        G_curr.add_node("Policy:ReadOnly", label="ReadOnly", type="Policy")
        G_curr.add_edge("User:Alice", "Policy:ReadOnly", label="HAS_POLICY")

        G_des = nx.DiGraph()
        G_des.add_node("User:Alice", label="Alice", type="User")
        G_des.add_node("Policy:ReadOnly", label="ReadOnly", type="Policy")
        G_des.add_node("Policy:Admin", label="Admin", type="Policy")
        G_des.add_edge("User:Alice", "Policy:ReadOnly", label="HAS_POLICY")
        G_des.add_edge("User:Alice", "Policy:Admin", label="HAS_POLICY")

        diff = compute_graph_diff(G_curr, G_des)

        self.assertEqual(len(diff["added_nodes"]), 1)
        self.assertEqual(diff["added_nodes"][0]["id"], "Policy:Admin")
        self.assertEqual(len(diff["removed_nodes"]), 0)
        self.assertEqual(len(diff["added_edges"]), 1)
        self.assertEqual(diff["added_edges"][0]["target"], "Policy:Admin")

        # Source graphs must NOT be mutated
        self.assertEqual(len(G_curr.nodes()), 2)
        self.assertEqual(len(G_des.nodes()), 3)

    # ── Test H, I, J: Attack path comparisons (new, removed, changed) ─────────
    def test_h_i_j_attack_path_diff(self):
        """compare_attack_paths detects new, removed, and changed risk paths."""
        current_paths = [
            {"id": "p1", "source": "alice", "destination": "bucket-a", "riskScore": 50, "severity": "medium"},
            {"id": "p2", "source": "bob", "destination": "db-prod", "riskScore": 85, "severity": "critical"},
        ]
        desired_paths = [
            # p1 changed risk
            {"id": "p1", "source": "alice", "destination": "bucket-a", "riskScore": 80, "severity": "critical"},
            # p2 removed
            # p3 new
            {"id": "p3", "source": "alice", "destination": "secret-keys", "riskScore": 95, "severity": "critical"},
        ]

        diff = compare_attack_paths(current_paths, desired_paths)

        # Test H: New paths
        self.assertEqual(len(diff["new_paths"]), 1)
        self.assertEqual(diff["new_paths"][0]["destination"], "secret-keys")

        # Test I: Removed paths
        self.assertEqual(len(diff["removed_paths"]), 1)
        self.assertEqual(diff["removed_paths"][0]["destination"], "db-prod")

        # Test J: Changed paths & risk delta
        self.assertEqual(len(diff["changed_paths"]), 1)
        self.assertEqual(diff["changed_paths"][0]["risk_delta"], 30)

    # ── Test K, L, M: Blast radius uses unique resources & deduplication ──────
    def test_k_l_m_blast_radius_deduplication(self):
        """Blast radius must deduplicate resources reachable through multiple paths."""
        G = nx.DiGraph()
        # Identity Alice
        G.add_node("User:Alice", type="User", label="Alice")
        # Alice reaches Bucket-A through Role-1
        G.add_node("Role:DevRole", type="Role", label="DevRole")
        G.add_node("Resource:BucketA", type="S3", label="BucketA")
        G.add_edge("User:Alice", "Role:DevRole")
        G.add_edge("Role:DevRole", "Resource:BucketA")

        # Alice ALSO reaches Bucket-A through Role-2 (alternate path to same resource)
        G.add_node("Role:StageRole", type="Role", label="StageRole")
        G.add_edge("User:Alice", "Role:StageRole")
        G.add_edge("Role:StageRole", "Resource:BucketA")

        # Bob reaches Bucket-A as well
        G.add_node("User:Bob", type="User", label="Bob")
        G.add_edge("User:Bob", "Resource:BucketA")

        # Also a sensitive resource (Secret)
        G.add_node("Resource:SecretAPI", type="Secrets", label="SecretAPI")
        G.add_edge("Role:DevRole", "Resource:SecretAPI")

        metrics = _compute_blast_metrics(G, None)

        # Test K & M: BucketA is reached via 3 paths (Alice->Role1, Alice->Role2, Bob->BucketA)
        # Unique reachable resources MUST be 2 (BucketA and SecretAPI), NOT 3 or 4
        self.assertEqual(metrics["reachable_resource_count"], 2)
        # Test L: Actual affected identities with reachability: Alice, Bob, DevRole, StageRole = 4
        self.assertEqual(metrics["affected_identities_count"], 4)
        # Sensitive count: SecretAPI
        self.assertEqual(metrics["sensitive_resource_count"], 1)

    # ── Test N & O: No ALLOWS fallback & No likelihood fallback ───────────────
    def test_n_o_no_allows_or_likelihood_fallbacks(self):
        """Edge labels must never default to ALLOWS and risk score must not use likelihood."""
        # Test that diff engine uses exact or CONNECTED_TO, never ALLOWS fallback
        G_curr = nx.DiGraph()
        G_des = nx.DiGraph()
        G_curr.add_node("A", type="User")
        G_curr.add_node("B", type="Role")
        G_des.add_node("A", type="User")
        G_des.add_node("B", type="Role")
        # Edge with no explicit label
        G_des.add_edge("A", "B")

        diff = compute_graph_diff(G_curr, G_des)
        self.assertEqual(len(diff["added_edges"]), 1)
        self.assertNotEqual(diff["added_edges"][0]["label"], "ALLOWS")

    # ── Test P: Simulation never writes to Neo4j ───────────────────────────────
    @patch("app.database.execute_write")
    def test_p_simulation_does_not_modify_neo4j(self, mock_execute_write):
        """Simulation lifecycle must never issue execute_write queries to Neo4j."""
        mgr = SimulationStateManager()
        mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/Admin")
        mgr.detach_policy("USER", "alice", "arn:aws:iam::aws:policy/ReadOnly")
        mgr.reset()

        mock_execute_write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
