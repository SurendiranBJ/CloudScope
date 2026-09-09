"""
Unit tests for the authoritative AssumeRole trust + call-permission evaluation model.

Matrix A–O:
A. Direct policy grants sts:AssumeRole on specific role ARN -> Verified
B. Direct policy grants sts:AssumeRole on '*' -> Verified
C. Group policy grants sts:AssumeRole on specific role ARN -> Verified
D. Group policy grants sts:AssumeRole on '*' -> Verified
E. Group normalization handles dict GroupName, full ARN, lowercase/mixed case -> Verified
F. Direct policy Denies sts:AssumeRole, group policy Allows -> Excluded (Deny precedence)
G. Group policy Denies sts:AssumeRole, direct policy Allows -> Excluded (Deny precedence)
H. Trust condition: StringEquals aws:PrincipalArn matches user ARN -> Definitive CAN_ASSUME
I. Trust condition: StringEquals aws:PrincipalArn differs from user ARN -> Violated
J. Trust condition: StringEquals aws:PrincipalAccount matches account ID -> Definitive CAN_ASSUME
K. Trust condition: StringEquals aws:PrincipalAccount differs from account ID -> Violated
L. Trust condition: Bool aws:MultiFactorAuthPresent -> Conditional trust, no CAN_ASSUME
M. Trust condition: StringEquals sts:ExternalId -> Conditional trust, no CAN_ASSUME
N. Trust condition: IpAddress aws:SourceIp -> Conditional trust, no CAN_ASSUME
O. Trust condition: Unsupported operator/key -> Conditional trust, no CAN_ASSUME
"""

import json
import pytest
from app.services.attack.policy_evaluator import (
    evaluate_assume_role_trust_with_evidence,
    principal_effective_allows_assume_role,
    evaluate_trust_statement_condition,
)


class TestAssumeRoleTrustModel:

    # ── Test A: Direct policy grants sts:AssumeRole on specific role ARN ───────
    def test_a_direct_policy_grants_assume_role_arn(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        user = {
            "name": "alice",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "policies": ["DirectAssumeTargetPolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "DirectAssumeTargetPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
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
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "definitive"
        assert result["users"][0]["evidence"]["call_permission_verified"] is True

    # ── Test B: Direct policy grants sts:AssumeRole on '*' ────────────────────
    def test_b_direct_policy_grants_assume_all_wildcard(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        user = {
            "name": "bob",
            "arn": "arn:aws:iam::123456789012:user/bob",
            "policies": ["WildcardAssumePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "WildcardAssumePolicy": json.dumps({
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
            role_name="AnyRole",
            role_arn="arn:aws:iam::123456789012:role/AnyRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "definitive"

    # ── Test C: Group policy grants sts:AssumeRole on specific role ARN ───────
    def test_c_group_policy_grants_assume_role_arn(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        user = {
            "name": "charlie",
            "arn": "arn:aws:iam::123456789012:user/charlie",
            "groups": ["SecurityEngineers"],
            "policies": [],
            "attachedPolicies": []
        }
        groups = [
            {
                "name": "SecurityEngineers",
                "arn": "arn:aws:iam::123456789012:group/SecurityEngineers",
                "attachedPolicies": ["GroupAssumeSecRolePolicy"]
            }
        ]
        policy_doc_map = {
            "GroupAssumeSecRolePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/SecRole"
                }]
            })
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="SecRole",
            role_arn="arn:aws:iam::123456789012:role/SecRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
            all_groups=groups,
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["principal"]["name"] == "charlie"
        assert result["users"][0]["evidence"]["trust_status"] == "definitive"

    # ── Test D: Group policy grants sts:AssumeRole on '*' ─────────────────────
    def test_d_group_policy_grants_assume_wildcard(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        user = {
            "name": "dave",
            "arn": "arn:aws:iam::123456789012:user/dave",
            "groups": ["Admins"],
            "policies": [],
            "attachedPolicies": []
        }
        groups = [
            {
                "name": "Admins",
                "arn": "arn:aws:iam::123456789012:group/Admins",
                "attachedPolicies": ["FullAdminPolicy"]
            }
        ]
        policy_doc_map = {
            "FullAdminPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
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
            all_groups=groups,
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "definitive"

    # ── Test E: Group normalization handles dict GroupName, full ARN, etc. ────
    def test_e_group_normalization_handles_various_formats(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        # User references group by full ARN
        user = {
            "name": "erin",
            "arn": "arn:aws:iam::123456789012:user/erin",
            "groups": ["arn:aws:iam::123456789012:group/DevOpsTeam"],
            "policies": [],
            "attachedPolicies": []
        }
        # Group inventory uses GroupName format (boto3 dict style)
        groups = [
            {
                "GroupName": "DevOpsTeam",
                "arn": "arn:aws:iam::123456789012:group/DevOpsTeam",
                "attachedPolicies": ["DevOpsAssumePolicy"]
            }
        ]
        policy_doc_map = {
            "DevOpsAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/DeployRole"
                }]
            })
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="DeployRole",
            role_arn="arn:aws:iam::123456789012:role/DeployRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
            all_groups=groups,
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["principal"]["name"] == "erin"

    # ── Test F: Direct policy Denies sts:AssumeRole, group policy Allows ──────
    def test_f_direct_deny_overrides_group_allow(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        user = {
            "name": "frank",
            "arn": "arn:aws:iam::123456789012:user/frank",
            "groups": ["Admins"],
            "policies": ["DenyAssumePolicy"],
            "attachedPolicies": []
        }
        groups = [
            {
                "name": "Admins",
                "arn": "arn:aws:iam::123456789012:group/Admins",
                "attachedPolicies": ["AllowAssumePolicy"]
            }
        ]
        policy_doc_map = {
            "AllowAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
            }),
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
            all_groups=groups,
        )
        assert len(result["users"]) == 0, "Direct explicit Deny must override group Allow"

    # ── Test G: Group policy Denies sts:AssumeRole, direct policy Allows ──────
    def test_g_group_deny_overrides_direct_allow(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
        user = {
            "name": "grace",
            "arn": "arn:aws:iam::123456789012:user/grace",
            "groups": ["RestrictedGroup"],
            "policies": ["DirectAllowAssumePolicy"],
            "attachedPolicies": []
        }
        groups = [
            {
                "name": "RestrictedGroup",
                "arn": "arn:aws:iam::123456789012:group/RestrictedGroup",
                "attachedPolicies": ["GroupDenyAssumePolicy"]
            }
        ]
        policy_doc_map = {
            "DirectAllowAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
            }),
            "GroupDenyAssumePolicy": json.dumps({
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
            all_groups=groups,
        )
        assert len(result["users"]) == 0, "Group explicit Deny must override direct Allow"

    # ── Test H: Trust condition: StringEquals aws:PrincipalArn matches ────────
    def test_h_trust_condition_principal_arn_match(self):
        user_arn = "arn:aws:iam::123456789012:user/heidi"
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": user_arn
                        }
                    }
                }
            ]
        }
        user = {
            "name": "heidi",
            "arn": user_arn,
            "policies": ["AllowAssumePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "AllowAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
            })
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="ConditionRole",
            role_arn="arn:aws:iam::123456789012:role/ConditionRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "definitive"
        assert len(result["conditional_trusts"]) == 0

    # ── Test I: Trust condition: StringEquals aws:PrincipalArn differs ────────
    def test_i_trust_condition_principal_arn_differs_is_violated(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": "arn:aws:iam::123456789012:user/other_user"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "ivan",
            "arn": "arn:aws:iam::123456789012:user/ivan",
            "policies": ["AllowAssumePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "AllowAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
            })
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="ConditionRole",
            role_arn="arn:aws:iam::123456789012:role/ConditionRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )
        assert len(result["users"]) == 0, "Violated PrincipalArn condition must reject user"

    # ── Test J: Trust condition: StringEquals aws:PrincipalAccount matches ────
    def test_j_trust_condition_principal_account_match(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalAccount": "123456789012"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "judy",
            "arn": "arn:aws:iam::123456789012:user/judy",
            "policies": ["AllowAssumePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "AllowAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
            })
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="AccountRole",
            role_arn="arn:aws:iam::123456789012:role/AccountRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "definitive"

    # ── Test K: Trust condition: StringEquals aws:PrincipalAccount differs ────
    def test_k_trust_condition_principal_account_differs_is_violated(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalAccount": "999999999999"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "kevin",
            "arn": "arn:aws:iam::123456789012:user/kevin",
            "policies": ["AllowAssumePolicy"],
            "attachedPolicies": []
        }
        policy_doc_map = {
            "AllowAssumePolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
            })
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="AccountRole",
            role_arn="arn:aws:iam::123456789012:role/AccountRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map=policy_doc_map,
        )
        assert len(result["users"]) == 0

    # ── Test L: Trust condition: aws:MultiFactorAuthPresent ───────────────────
    def test_l_trust_condition_mfa_yields_conditional_trust(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/laura"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "Bool": {
                            "aws:MultiFactorAuthPresent": "true"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "laura",
            "arn": "arn:aws:iam::123456789012:user/laura",
            "policies": [],
            "attachedPolicies": []
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="MfaProtectedRole",
            role_arn="arn:aws:iam::123456789012:role/MfaProtectedRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map={},
        )
        # Runtime MFA condition cannot be proven from static inventory
        assert len(result["users"]) == 1
        user_ev = result["users"][0]["evidence"]
        assert user_ev["trust_status"] == "conditional"
        assert user_ev["trust_conditional"] is True
        assert len(result["conditional_trusts"]) == 1

    # ── Test M: Trust condition: sts:ExternalId ───────────────────────────────
    def test_m_trust_condition_external_id_yields_conditional_trust(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/mallory"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "company-secret-pass-token-1234"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "mallory",
            "arn": "arn:aws:iam::123456789012:user/mallory",
            "policies": [],
            "attachedPolicies": []
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="PartnerRole",
            role_arn="arn:aws:iam::123456789012:role/PartnerRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map={},
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "conditional"
        assert len(result["conditional_trusts"]) == 1

    # ── Test N: Trust condition: aws:SourceIp ─────────────────────────────────
    def test_n_trust_condition_source_ip_yields_conditional_trust(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/nancy"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": "203.0.113.0/24"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "nancy",
            "arn": "arn:aws:iam::123456789012:user/nancy",
            "policies": [],
            "attachedPolicies": []
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="IpRestrictedRole",
            role_arn="arn:aws:iam::123456789012:role/IpRestrictedRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map={},
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "conditional"
        assert len(result["conditional_trusts"]) == 1

    # ── Test O: Trust condition: Unsupported operator/key ─────────────────────
    def test_o_trust_condition_unsupported_operator_yields_conditional_trust(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/oscar"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "NumericLessThan": {
                            "aws:CurrentTime": "2026-09-09T12:00:00Z"
                        }
                    }
                }
            ]
        }
        user = {
            "name": "oscar",
            "arn": "arn:aws:iam::123456789012:user/oscar",
            "policies": [],
            "attachedPolicies": []
        }
        result = evaluate_assume_role_trust_with_evidence(
            trust_policy_input=trust_policy,
            role_name="TemporalRole",
            role_arn="arn:aws:iam::123456789012:role/TemporalRole",
            all_users=[user],
            all_roles=[],
            account_id="123456789012",
            policy_doc_map={},
        )
        assert len(result["users"]) == 1
        assert result["users"][0]["evidence"]["trust_status"] == "conditional"
        assert len(result["conditional_trusts"]) == 1
