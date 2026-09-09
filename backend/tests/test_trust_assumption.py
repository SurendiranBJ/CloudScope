"""
Unit tests for the authoritative AssumeRole trust + call-permission evaluation model.

Validates that:
1. Wildcard trust (Principal: "*") does NOT materialize edges for users without sts:AssumeRole.
2. Wildcard trust DOES materialize edges for users who possess an identity policy granting sts:AssumeRole.
3. Exact ARN principal matches in trust policies are verified.
4. Account root trust requires identity policies granting sts:AssumeRole.
5. Role-to-role exact trust is verified.
6. Explicit Deny on sts:AssumeRole strictly excludes the principal even if trusted.
"""

import json
import pytest
from app.services.attack.policy_evaluator import evaluate_assume_role_trust_with_evidence


class TestAssumeRoleTrustModel:

    def test_wildcard_trust_without_assume_permission_creates_no_verified_edge(self):
        """A user without sts:AssumeRole permission in their policies must NOT receive
        a verified CAN_ASSUME edge even if the role trust policy has Principal: '*'."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        user = {
            "name": "alice",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "policies": ["S3ReadOnlyPolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "S3ReadOnlyPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
            })
        }

        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="BroadAdminRole",
            role_arn="arn:aws:iam::123456789012:role/BroadAdminRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )

        assert result["trust_is_broad"] is True
        # alice does NOT have sts:AssumeRole permission, so she should NOT be in result["users"]
        verified_users = [
            u for u in result["users"]
            if u["evidence"].get("call_permission_verified") is True
        ]
        assert len(verified_users) == 0, "User without sts:AssumeRole must not be verified for CAN_ASSUME"

    def test_wildcard_trust_with_assume_permission_is_verified(self):
        """A user WITH sts:AssumeRole permission in their identity policy MUST receive
        a verified CAN_ASSUME edge when the role trust policy has Principal: '*'."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        user = {
            "name": "bob",
            "arn": "arn:aws:iam::123456789012:user/bob",
            "policies": ["AssumeAdminRolePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "AssumeAdminRolePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/BroadAdminRole"
                }]
            })
        }

        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="BroadAdminRole",
            role_arn="arn:aws:iam::123456789012:role/BroadAdminRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )

        assert result["trust_is_broad"] is True
        verified_users = [
            u for u in result["users"]
            if u["evidence"].get("call_permission_verified") is True
        ]
        assert len(verified_users) == 1
        assert verified_users[0]["principal"]["name"] == "bob"
        assert verified_users[0]["evidence"]["trust_principal_type"] == "wildcard"

    def test_exact_arn_principal_in_trust_is_verified(self):
        """An exact user ARN listed directly in the trust policy implies caller permission
        and is immediately verified."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/charlie"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        user = {
            "name": "charlie",
            "arn": "arn:aws:iam::123456789012:user/charlie",
            "policies": [],
            "attachedPolicies": []
        }

        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="TargetRole",
            role_arn="arn:aws:iam::123456789012:role/TargetRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map={},
        )

        assert result["trust_is_broad"] is False
        verified_users = [
            u for u in result["users"]
            if u["evidence"].get("call_permission_verified") is True
        ]
        assert len(verified_users) == 1
        assert verified_users[0]["principal"]["name"] == "charlie"
        assert verified_users[0]["evidence"]["trust_principal_type"] == "exact_arn"

    def test_account_root_trust_requires_identity_policy(self):
        """When a role trusts the account root (arn:aws:iam::123456789012:root),
        users without sts:AssumeRole in their identity policies must NOT receive verified edges."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        user_unauthorized = {
            "name": "david",
            "arn": "arn:aws:iam::123456789012:user/david",
            "policies": [],
            "attachedPolicies": []
        }
        user_authorized = {
            "name": "eve",
            "arn": "arn:aws:iam::123456789012:user/eve",
            "policies": ["AllowAssumeAllRoles"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "AllowAssumeAllRoles": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "*"
                }]
            })
        }

        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="InternalRole",
            role_arn="arn:aws:iam::123456789012:role/InternalRole",
            all_users=[user_unauthorized, user_authorized],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )

        assert result["trust_is_broad"] is True
        verified_names = [
            u["principal"]["name"] for u in result["users"]
            if u["evidence"].get("call_permission_verified") is True
        ]
        assert "david" not in verified_names
        assert "eve" in verified_names

    def test_role_to_role_exact_trust_is_verified(self):
        """Role-to-role delegation with exact ARN is verified."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/SourceRole"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        source_role = {
            "name": "SourceRole",
            "arn": "arn:aws:iam::123456789012:role/SourceRole",
            "attachedPolicies": []
        }

        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="DestRole",
            role_arn="arn:aws:iam::123456789012:role/DestRole",
            all_users=[],
            all_roles=[source_role],
            account_id="123456789012",
            policy_doc_map={},
        )

        verified_roles = [
            r for r in result["roles"]
            if r["evidence"].get("call_permission_verified") is True
        ]
        assert len(verified_roles) == 1
        assert verified_roles[0]["principal"]["name"] == "SourceRole"

    def test_explicit_deny_excludes_principal(self):
        """If an identity policy contains an explicit Deny on sts:AssumeRole for the role,
        the principal is strictly excluded even if the trust policy permits them."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/frank"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        user = {
            "name": "frank",
            "arn": "arn:aws:iam::123456789012:user/frank",
            "policies": ["DenyAssumePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "DenyAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/TargetRole"
                }]
            })
        }

        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="TargetRole",
            role_arn="arn:aws:iam::123456789012:role/TargetRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )

        assert len(result["users"]) == 0, "Explicit Deny must exclude the principal from being returned"
