"""Tests for the IAM risk scoring engine (risk_engine.py)."""
import json
import pytest

from app.services.attack.risk_engine import (
    score_user_risk,
    score_role_risk,
    _has_wildcard_permissions,
)


# ---------------------------------------------------------------------------
# Fixtures — reusable policy documents and identity stubs
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


def _make_user(*, policies=None, mfa=True, groups=None):
    return {
        "name": "test-user",
        "arn": "arn:aws:iam::123456789012:user/test-user",
        "status": "active",
        "policies": policies or [],
        "groups": groups or [],
        "mfaEnabled": mfa,
        "lastActive": "2026-01-01T00:00:00Z",
        "riskScore": 0,
    }


def _make_role(*, name="test-role", trust="{}",
               attached_policies=None):
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
    """Verify risk scoring for IAM users."""

    def test_wildcard_policy_scores_higher(self):
        """A user whose attached policy document contains Action:*/Resource:*
        must score higher than one with only a read-only policy."""
        doc_map = {
            "WildcardPolicy": WILDCARD_POLICY_DOC,
            "ReadOnlyPolicy": READONLY_POLICY_DOC,
        }
        user_wild = _make_user(policies=["WildcardPolicy"])
        user_safe = _make_user(policies=["ReadOnlyPolicy"])

        assert score_user_risk(user_wild, doc_map) > score_user_risk(user_safe, doc_map)

    def test_no_mfa_scores_higher(self):
        """A user without MFA must score higher than one with MFA,
        all else being equal."""
        doc_map = {}
        user_no_mfa = _make_user(mfa=False)
        user_mfa = _make_user(mfa=True)

        assert score_user_risk(user_no_mfa, doc_map) > score_user_risk(user_mfa, doc_map)

    def test_admin_name_fallback_still_elevates(self):
        """When the policy document is NOT in the map (fetch failed),
        a user with an 'AdministratorAccess' policy name must still
        get an elevated score via the name-substring heuristic."""
        doc_map = {}  # no document available — simulates a fetch failure
        user_admin = _make_user(policies=["AdministratorAccess"])
        user_plain = _make_user(policies=["ViewOnlyAccess"])

        score_admin = score_user_risk(user_admin, doc_map)
        score_plain = score_user_risk(user_plain, doc_map)

        assert score_admin > score_plain

    def test_wildcard_doc_beats_name_fallback(self):
        """When a real wildcard policy document IS available, the wildcard
        bonus (+45) must be applied, not just the name fallback (+30).
        This is the regression test for the original json.loads() bug."""
        doc_map = {"AdministratorAccess": WILDCARD_POLICY_DOC}
        user = _make_user(policies=["AdministratorAccess"])

        score = score_user_risk(user, doc_map)
        # Base (10) + wildcard doc bonus (45) = 55 minimum.
        # The name fallback would give only 10 + 30 = 40.
        assert score >= 55

    def test_many_groups_adds_score(self):
        """A user in more than 2 groups gets an extra penalty."""
        doc_map = {}
        user_many = _make_user(groups=["g1", "g2", "g3"])
        user_few = _make_user(groups=["g1"])

        assert score_user_risk(user_many, doc_map) > score_user_risk(user_few, doc_map)


# ===================================================================
# score_role_risk tests
# ===================================================================

class TestScoreRoleRisk:
    """Verify risk scoring for IAM roles."""

    def test_wildcard_trust_principal_scores_higher(self):
        """A role with '"Principal": "*"' in its trust policy must score
        higher than one with a scoped principal."""
        trust_wild = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*",
                           "Action": "sts:AssumeRole"}]
        })
        trust_scoped = json.dumps({
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                           "Action": "sts:AssumeRole"}]
        })
        role_wild = _make_role(trust=trust_wild)
        role_safe = _make_role(trust=trust_scoped)

        assert score_role_risk(role_wild, {}) > score_role_risk(role_safe, {})

    def test_admin_name_scores_higher(self):
        """A role whose name contains 'Admin' must score higher than one
        without, even with identical trust policies."""
        role_admin = _make_role(name="SuperAdminRole")
        role_plain = _make_role(name="ReadOnlyRole")

        assert score_role_risk(role_admin, {}) > score_role_risk(role_plain, {})

    def test_wildcard_policy_doc_bonus_applied(self):
        """REGRESSION: A role with a real wildcard policy document in the
        doc_map must receive the wildcard bonus (+25).  Before the fix
        this code path was dead because json.loads() was called on policy
        names instead of documents, so the bonus was never applied."""
        doc_map = {"PowerUserAccess": WILDCARD_POLICY_DOC}
        role_with_doc = _make_role(attached_policies=["PowerUserAccess"])
        role_no_doc = _make_role(attached_policies=["PowerUserAccess"])

        score_with = score_role_risk(role_with_doc, doc_map)
        score_without = score_role_risk(role_no_doc, {})

        # The role with the resolved document must score higher because
        # the +25 wildcard bonus is actually applied.
        assert score_with > score_without
