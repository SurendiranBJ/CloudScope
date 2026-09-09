"""
Unit tests for Neo4j Graph Reconciliation (Tests S & T).

Matrix S/T:
- Test S: Stale CAN_ASSUME relationships in Neo4j are removed when scan runs
  and the trust or call permission is no longer valid.
- Test T: ASSUMED_ROLE relationships from CloudTrail are preserved intact
  and NOT deleted during reconciliation.
- Test U: Stale HAS_POLICY relationships are pruned when policies are detached.
- Test V: CloudTrail activity nodes and edges are preserved across scans.
"""

import json
from unittest.mock import patch, MagicMock
import pytest

from app.services.scanner.inventory import AWSInventory
from app.services.graph.graph_builder import build_graph_in_neo4j, get_node_id


class TestGraphReconciliation:

    @patch("app.services.graph.graph_builder.get_account_id", return_value="123456789012")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_s_stale_can_assume_reconciliation(self, mock_execute_write, mock_acc_id):
        """When an AssumeRole trust is revoked or call permission removed,
        the reconciliation query must DELETE stale CAN_ASSUME edges targeting that role."""
        inv = AWSInventory()
        inv.users = [
            {"id": "u1", "name": "alice", "arn": "arn:aws:iam::123456789012:user/alice", "policies": [], "attachedPolicies": [], "groups": []}
        ]
        inv.roles = [
            {
                "name": "TargetRole",
                "arn": "arn:aws:iam::123456789012:role/TargetRole",
                # Empty/no trust statement for alice
                "trustPolicy": json.dumps({"Version": "2012-10-17", "Statement": []}),
                "attachedPolicies": []
            }
        ]

        build_graph_in_neo4j(inv)

        # Inspect all execute_write calls
        write_queries = [call.args[0] for call in mock_execute_write.call_args_list]
        write_params = [call.args[1] if len(call.args) > 1 else {} for call in mock_execute_write.call_args_list]

        # Verify that a reconciliation query for CAN_ASSUME was executed targeting TargetRole
        can_assume_prune_calls = [
            (q, p) for q, p in zip(write_queries, write_params)
            if "MATCH (s)-[rel:CAN_ASSUME]->(r:Role {id: $r_id})" in q
        ]
        assert len(can_assume_prune_calls) == 1, "Must execute CAN_ASSUME reconciliation query"

        query, params = can_assume_prune_calls[0]
        assert params["r_id"] == "aws:role:TargetRole"
        # Since alice has no trust, valid_source_ids must be empty
        assert params["valid_source_ids"] == []
        assert "DELETE rel" in query

    @patch("app.services.graph.graph_builder.get_account_id", return_value="123456789012")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_t_assumed_role_edges_preserved_during_reconciliation(self, mock_execute_write, mock_acc_id):
        """Reconciliation queries must NEVER target or delete ASSUMED_ROLE edges,
        preserving CloudTrail historical activity intact."""
        inv = AWSInventory()
        inv.users = [
            {"id": "u1", "name": "bob", "arn": "arn:aws:iam::123456789012:user/bob", "policies": [], "attachedPolicies": [], "groups": []}
        ]
        inv.roles = [
            {
                "name": "AuditRole",
                "arn": "arn:aws:iam::123456789012:role/AuditRole",
                "trustPolicy": json.dumps({"Version": "2012-10-17", "Statement": []}),
                "attachedPolicies": []
            }
        ]

        build_graph_in_neo4j(inv)

        write_queries = [call.args[0] for call in mock_execute_write.call_args_list]

        # Ensure NO delete query targets ASSUMED_ROLE
        assumed_role_deletes = [
            q for q in write_queries
            if "ASSUMED_ROLE" in q and "DELETE" in q
        ]
        assert len(assumed_role_deletes) == 0, "Reconciliation must NEVER delete ASSUMED_ROLE edges"

    @patch("app.services.graph.graph_builder.get_account_id", return_value="123456789012")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_u_stale_has_policy_reconciliation(self, mock_execute_write, mock_acc_id):
        """When a policy is detached from a role or user, reconciliation deletes stale HAS_POLICY edges."""
        inv = AWSInventory()
        inv.users = [
            {
                "id": "u1",
                "name": "carol",
                "arn": "arn:aws:iam::123456789012:user/carol",
                "policies": ["ValidPolicy"],
                "attachedPolicies": [],
                "groups": []
            }
        ]
        inv.policies = [
            {"name": "ValidPolicy", "arn": "arn:aws:iam::123456789012:policy/ValidPolicy", "document": "{}"}
        ]

        build_graph_in_neo4j(inv)

        write_queries = [call.args[0] for call in mock_execute_write.call_args_list]
        write_params = [call.args[1] if len(call.args) > 1 else {} for call in mock_execute_write.call_args_list]

        # Verify user HAS_POLICY reconciliation query
        user_policy_prunes = [
            (q, p) for q, p in zip(write_queries, write_params)
            if "MATCH (u:User {id: $u_id})-[rel:HAS_POLICY]->(p:Policy)" in q
        ]
        assert len(user_policy_prunes) == 1
        query, params = user_policy_prunes[0]
        assert params["u_id"] == "aws:user:carol"
        assert params["valid_p_ids"] == ["aws:policy:ValidPolicy"]
        assert "DELETE rel" in query

    @patch("app.services.graph.graph_builder.get_account_id", return_value="123456789012")
    @patch("app.services.graph.graph_builder.execute_write")
    def test_w_stale_configuration_node_reconciliation_preserves_activity_events(self, mock_execute_write, mock_acc_id):
        """When an AWS inventory resource (Role, S3, EC2, User, etc.) is deleted from AWS,
        the configuration reconciliation step prunes obsolete configuration nodes
        while strictly preserving :ActivityEvent nodes and historical CloudTrail data."""
        inv = AWSInventory()
        inv.roles = [
            {
                "name": "ActiveRole",
                "arn": "arn:aws:iam::123456789012:role/ActiveRole",
                "trustPolicy": "{}",
                "attachedPolicies": []
            }
        ]

        build_graph_in_neo4j(inv)

        write_queries = [call.args[0] for call in mock_execute_write.call_args_list]
        write_params = [call.args[1] if len(call.args) > 1 else {} for call in mock_execute_write.call_args_list]

        # Verify role node reconciliation query
        role_prunes = [
            (q, p) for q, p in zip(write_queries, write_params)
            if "MATCH (n:Role)" in q and "DETACH DELETE n" in q
        ]
        assert len(role_prunes) == 1, "Must execute Role node reconciliation query"
        query, params = role_prunes[0]
        assert params["valid_ids"] == ["aws:role:ActiveRole"]
        assert "WHERE NOT n.id IN $valid_ids" in query
        assert "DETACH DELETE n" in query

        # Ensure :ActivityEvent nodes are NEVER deleted by configuration node reconciliation
        activity_deletes = [
            q for q in write_queries
            if "ActivityEvent" in q and "DELETE" in q
        ]
        assert len(activity_deletes) == 0, "Configuration reconciliation must NEVER delete ActivityEvent nodes"
