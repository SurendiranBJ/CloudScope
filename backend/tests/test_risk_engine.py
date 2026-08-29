"""
Unit tests for the Deterministic Evidence-Based IAM Risk Scoring Engine.
"""
import json
import pytest

from app.services.attack.risk_engine import (
    score_user_risk,
    score_role_risk,
    score_resource_risk,
    get_user_risk_assessment,
    get_role_risk_assessment,
    compute_global_security_score,
)
from app.services.attack.policy_evaluator import (
    evaluate_policy_document_risk,
    evaluate_trust_policy_risk,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

WILDCARD_POLICY_DOC = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
})

PRIV_ESC_POLICY_DOC = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["iam:PassRole", "iam:AttachRolePolicy"],
            "Resource": "*"
        }
    ]
})

READONLY_POLICY_DOC = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
})


def _make_user(*, policies=None, mfa=True, groups=None, last_active="2026-01-01T00:00:00Z"):
    return {
        "name": "test-user",
        "arn": "arn:aws:iam::123456789012:user/test-user",
        "status": "active",
        "policies": policies or [],
        "groups": groups or [],
        "mfaEnabled": mfa,
        "lastActive": last_active,
        "riskScore": 0,
    }


def _make_role(*, name="test-role", trust="{}", attached_policies=None):
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:role/{name}",
        "trustPolicy": trust,
        "description": "",
        "activeSessions": 0,
        "attachedPolicies": attached_policies or [],
        "riskScore": 0,
    }


# ===================================================================
# score_user_risk tests
# ===================================================================

class TestScoreUserRisk:
    """Verify deterministic risk scoring for IAM users."""

    def test_wildcard_policy_scores_higher(self):
        doc_map = {
            "WildcardPolicy": WILDCARD_POLICY_DOC,
            "ReadOnlyPolicy": READONLY_POLICY_DOC,
        }
        user_wild = _make_user(policies=["WildcardPolicy"])
        user_safe = _make_user(policies=["ReadOnlyPolicy"])

        assert score_user_risk(user_wild, doc_map) > score_user_risk(user_safe, doc_map)

    def test_no_mfa_scores_higher(self):
        doc_map = {}
        user_no_mfa = _make_user(mfa=False)
        user_mfa = _make_user(mfa=True)

        assert score_user_risk(user_no_mfa, doc_map) > score_user_risk(user_mfa, doc_map)

    def test_privilege_escalation_policy_scores_high(self):
        doc_map = {"PrivEsc": PRIV_ESC_POLICY_DOC}
        user = _make_user(policies=["PrivEsc"])
        assessment = get_user_risk_assessment(user, doc_map)
        
        factor_codes = [f["code"] for f in assessment["factors"]]
        assert "PRIVILEGE_ESCALATION_PERMS" in factor_codes

    def test_many_groups_adds_score(self):
        doc_map = {}
        user_many = _make_user(groups=["g1", "g2", "g3", "g4"])
        user_few = _make_user(groups=["g1"])

        assert score_user_risk(user_many, doc_map) > score_user_risk(user_few, doc_map)

    def test_no_name_heuristics_applied(self):
        """Role or policy names containing 'Admin' without actual doc evidence do NOT falsely score high."""
        doc_map = {}
        user_admin_name = _make_user(policies=["AdminRolePlaceholder"])
        user_plain_name = _make_user(policies=["PlainPlaceholder"])

        assert score_user_risk(user_admin_name, doc_map) == score_user_risk(user_plain_name, doc_map)


# ===================================================================
# score_role_risk tests
# ===================================================================

class TestScoreRoleRisk:
    """Verify risk scoring for IAM roles."""

    def test_wildcard_trust_principal_scores_higher(self):
        trust_wild = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        })
        trust_scoped = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "sts:AssumeRole"}]
        })
        role_wild = _make_role(trust=trust_wild)
        role_safe = _make_role(trust=trust_scoped)

        assert score_role_risk(role_wild, {}) > score_role_risk(role_safe, {})

    def test_role_with_wildcard_policy_doc(self):
        doc_map = {"AdminDoc": WILDCARD_POLICY_DOC}
        role = _make_role(attached_policies=["AdminDoc"])
        assessment = get_role_risk_assessment(role, doc_map)
        
        assert assessment["score"] >= 30
        factor_codes = [f["code"] for f in assessment["factors"]]
        assert "WILDCARD_ALLOW_ALL" in factor_codes


# ===================================================================
# Resource Risk Tests
# ===================================================================

class TestScoreResourceRisk:
    def test_s3_public_exposure_risk(self):
        public_bucket = {"type": "S3", "details": {"public_blocked": False, "encrypted": True}}
        private_bucket = {"type": "S3", "details": {"public_blocked": True, "encrypted": True}}
        assert score_resource_risk(public_bucket) > score_resource_risk(private_bucket)

    def test_secrets_rotation_disabled_risk(self):
        no_rot_secret = {"type": "Secrets", "details": {"rotation_enabled": False}}
        rot_secret = {"type": "Secrets", "details": {"rotation_enabled": True}}
        assert score_resource_risk(no_rot_secret) > score_resource_risk(rot_secret)

    def test_ec2_public_ip_risk(self):
        public_ec2 = {"type": "EC2", "details": {"public_ip": "54.210.10.1"}}
        private_ec2 = {"type": "EC2", "details": {"public_ip": "None"}}
        assert score_resource_risk(public_ec2) > score_resource_risk(private_ec2)


# ===================================================================
# Global 5-Category Posture Score Tests
# ===================================================================

class TestGlobalSecurityScore:
    def test_global_score_calculation(self):
        class MockInventory:
            users = [_make_user(mfa=True)]
            roles = [_make_role()]
            s3 = [{"type": "S3", "details": {"public_blocked": True, "encrypted": True}, "riskScore": 0}]
            ec2 = []
            secrets = []
            rds = []
            dynamodb = []

        inv = MockInventory()
        res = compute_global_security_score(inv, [], [{"id": "alert1"}])
        assert 0 <= res["overall_score"] <= 100
        assert "categories" in res
        assert "iam_security" in res["categories"]
        assert "resource_security" in res["categories"]
        assert "attack_path_risk" in res["categories"]
        assert "identity_hygiene" in res["categories"]
        assert "monitoring_coverage" in res["categories"]
