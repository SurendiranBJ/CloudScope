"""
Tests for the Simulation State Engine.

Tests:
  - attach_policy creates a SimulationChange record
  - detach_policy creates a SimulationChange record
  - remove_change removes the change
  - reset clears all changes
  - get_desired_inventory applies changes without mutating the original
  - SimulationStateManager NEVER calls boto3 (mutation guard)
"""

import copy
import json
import unittest
from unittest.mock import patch, MagicMock

from app.services.simulation.simulation_state import (
    SimulationStateManager,
    SimulationChange,
    _apply_policy_change,
    _name_from_arn,
)
from app.services.scanner.inventory import AWSInventory


def _make_inventory() -> AWSInventory:
    """Build a minimal test inventory."""
    inv = AWSInventory()
    inv.users = [
        {
            "name": "alice",
            "policies": ["ReadOnlyAccess"],
            "attachedPolicyArns": {"ReadOnlyAccess": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
            "groups": [],
            "mfaEnabled": True,
        }
    ]
    inv.groups = []
    inv.roles = [
        {
            "name": "DevRole",
            "attachedPolicies": [],
            "attachedPolicyArns": {},
            "trustPolicy": "{}",
        }
    ]
    inv.policies = []
    inv.ec2 = []
    inv.s3 = []
    inv.lambdas = []
    inv.secrets = []
    inv.rds = []
    inv.dynamodb = []
    inv.findings = []
    inv.alerts = []
    return inv


class TestSimulationStateManager(unittest.TestCase):

    def setUp(self):
        self.mgr = SimulationStateManager()

    def test_attach_policy_creates_change(self):
        change = self.mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/AdministratorAccess")
        self.assertEqual(change.action, "ATTACH_POLICY")
        self.assertEqual(change.principal_type, "USER")
        self.assertEqual(change.principal_id, "alice")
        self.assertEqual(len(self.mgr.get_changes()), 1)

    def test_detach_policy_creates_change(self):
        change = self.mgr.detach_policy("ROLE", "DevRole", "arn:aws:iam::aws:policy/ReadOnlyAccess")
        self.assertEqual(change.action, "DETACH_POLICY")
        self.assertEqual(len(self.mgr.get_changes()), 1)

    def test_remove_change(self):
        change = self.mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/PowerUserAccess")
        self.assertTrue(self.mgr.remove_change(change.change_id))
        self.assertEqual(len(self.mgr.get_changes()), 0)

    def test_remove_nonexistent_change(self):
        self.assertFalse(self.mgr.remove_change("nonexistent-id"))

    def test_reset_clears_all_changes(self):
        self.mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/A")
        self.mgr.attach_policy("USER", "bob", "arn:aws:iam::aws:policy/B")
        self.mgr.reset()
        self.assertEqual(len(self.mgr.get_changes()), 0)
        self.assertFalse(self.mgr.has_changes())

    def test_get_desired_inventory_does_not_mutate_original(self):
        """Deep copy must prevent mutation of original inventory."""
        inv = _make_inventory()
        original_policies = copy.deepcopy(inv.users[0]["policies"])
        self.mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/AdministratorAccess")
        desired = self.mgr.get_desired_inventory(inv)

        # Original unchanged
        self.assertEqual(inv.users[0]["policies"], original_policies)
        # Desired has new policy
        self.assertIn("AdministratorAccess", desired.users[0]["policies"])

    def test_desired_inventory_attach_policy(self):
        inv = _make_inventory()
        self.mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/AmazonS3FullAccess")
        desired = self.mgr.get_desired_inventory(inv)
        alice = next(u for u in desired.users if u["name"] == "alice")
        self.assertIn("AmazonS3FullAccess", alice["policies"])

    def test_desired_inventory_detach_policy(self):
        inv = _make_inventory()
        self.mgr.detach_policy("USER", "alice", "arn:aws:iam::aws:policy/ReadOnlyAccess")
        desired = self.mgr.get_desired_inventory(inv)
        alice = next(u for u in desired.users if u["name"] == "alice")
        self.assertNotIn("ReadOnlyAccess", alice["policies"])

    def test_desired_inventory_role_attach(self):
        inv = _make_inventory()
        self.mgr.attach_policy("ROLE", "DevRole", "arn:aws:iam::aws:policy/AmazonEC2FullAccess")
        desired = self.mgr.get_desired_inventory(inv)
        role = next(r for r in desired.roles if r["name"] == "DevRole")
        self.assertIn("AmazonEC2FullAccess", role["attachedPolicies"])

    def test_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            SimulationChange(
                action="MODIFY_POLICY",
                principal_type="USER",
                principal_id="alice",
                policy_arn="arn:aws:iam::aws:policy/X",
            )

    def test_invalid_principal_type_raises(self):
        with self.assertRaises(ValueError):
            SimulationChange(
                action="ATTACH_POLICY",
                principal_type="COMPUTER",
                principal_id="alice",
                policy_arn="arn:aws:iam::aws:policy/X",
            )

    # ── Safety: no boto3 mutation calls ──────────────────────────────────────

    def test_no_aws_iam_attach_user_policy_called(self):
        """CRITICAL: Simulation must NEVER call iam.attach_user_policy."""
        with patch("boto3.client") as mock_client:
            inv = _make_inventory()
            self.mgr.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/X")
            self.mgr.get_desired_inventory(inv)
            # boto3.client should NOT have been called during simulation
            mock_client.assert_not_called()

    def test_no_aws_iam_detach_role_policy_called(self):
        """CRITICAL: Simulation must NEVER call iam.detach_role_policy."""
        with patch("boto3.client") as mock_client:
            inv = _make_inventory()
            self.mgr.detach_policy("ROLE", "DevRole", "arn:aws:iam::aws:policy/X")
            self.mgr.get_desired_inventory(inv)
            mock_client.assert_not_called()


class TestApplyPolicyChange(unittest.TestCase):

    def test_attach_adds_to_list(self):
        entity = {"name": "test", "policies": ["ExistingPolicy"], "attachedPolicyArns": {}}
        _apply_policy_change(entity, "ATTACH_POLICY", "arn:aws:iam::aws:policy/New", "New", "policies", "attachedPolicyArns")
        self.assertIn("New", entity["policies"])
        self.assertEqual(entity["attachedPolicyArns"]["New"], "arn:aws:iam::aws:policy/New")

    def test_attach_is_idempotent(self):
        entity = {"name": "test", "policies": ["Existing"], "attachedPolicyArns": {}}
        _apply_policy_change(entity, "ATTACH_POLICY", "arn:aws:iam::aws:policy/Existing", "Existing", "policies", "attachedPolicyArns")
        _apply_policy_change(entity, "ATTACH_POLICY", "arn:aws:iam::aws:policy/Existing", "Existing", "policies", "attachedPolicyArns")
        self.assertEqual(entity["policies"].count("Existing"), 1)

    def test_detach_removes_from_list(self):
        entity = {
            "name": "test",
            "policies": ["ReadOnlyAccess", "AnotherPolicy"],
            "attachedPolicyArns": {"ReadOnlyAccess": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        }
        _apply_policy_change(entity, "DETACH_POLICY", "arn:aws:iam::aws:policy/ReadOnlyAccess", "ReadOnlyAccess", "policies", "attachedPolicyArns")
        self.assertNotIn("ReadOnlyAccess", entity["policies"])
        self.assertNotIn("ReadOnlyAccess", entity["attachedPolicyArns"])

    def test_detach_nonexistent_policy_is_safe(self):
        entity = {"name": "test", "policies": [], "attachedPolicyArns": {}}
        # Should not raise
        _apply_policy_change(entity, "DETACH_POLICY", "arn:aws:iam::aws:policy/Ghost", "Ghost", "policies", "attachedPolicyArns")
        self.assertEqual(entity["policies"], [])


class TestNameFromArn(unittest.TestCase):

    def test_standard_aws_arn(self):
        self.assertEqual(_name_from_arn("arn:aws:iam::aws:policy/AdministratorAccess"), "AdministratorAccess")

    def test_customer_managed_arn(self):
        self.assertEqual(_name_from_arn("arn:aws:iam::123456789012:policy/MyCustomPolicy"), "MyCustomPolicy")

    def test_non_arn_passthrough(self):
        self.assertEqual(_name_from_arn("ReadOnlyAccess"), "ReadOnlyAccess")

    def test_empty_string(self):
        self.assertEqual(_name_from_arn(""), "")


if __name__ == "__main__":
    unittest.main()
