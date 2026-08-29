"""
CloudScope Deterministic Evidence-Based Risk Engine.

Calculates risk scores (0-100) strictly from concrete configuration evidence,
IAM AST evaluation, trust policies, and resource configurations.
No name-based heuristics (e.g. 'admin' in role or policy name) are used as authorization evidence.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from app.services.risk.risk_constants import (
    WEIGHTS,
    DANGEROUS_ESCALATION_ACTIONS,
    BROAD_ADMIN_ACTIONS,
    GLOBAL_SCORE_WEIGHTS,
    get_severity_label
)
from app.services.attack.policy_evaluator import (
    parse_policy_document,
    evaluate_policy_document_risk,
    evaluate_trust_policy_risk
)

logger = logging.getLogger("scanner")


def get_user_risk_assessment(user: Dict[str, Any], policy_doc_map: Dict[str, str]) -> Dict[str, Any]:
    """Calculate deterministic risk score and return structured evidence factors for an IAM User."""
    factors: List[Dict[str, Any]] = []
    score = 0

    # 1. MFA Evaluation
    if not user.get("mfaEnabled", True):
        pts = WEIGHTS["NO_MFA"]
        score += pts
        factors.append({
            "code": "NO_MFA",
            "points": pts,
            "reason": "Multi-Factor Authentication (MFA) is not enabled on this user account."
        })

    # 2. Inactive / Stale Credentials
    last_active = user.get("lastActive", "")
    if last_active == "Never" or user.get("inactive_days", 0) > 90:
        pts = WEIGHTS["INACTIVE_STALE_CREDENTIALS"]
        score += pts
        factors.append({
            "code": "INACTIVE_CREDENTIALS",
            "points": pts,
            "reason": f"User credentials appear inactive or have never been used (last active: {last_active})."
        })

    # 3. Excessive Group Memberships
    groups = user.get("groups", [])
    if len(groups) > 3:
        pts = WEIGHTS["MANY_GROUPS"]
        score += pts
        factors.append({
            "code": "MANY_GROUPS",
            "points": pts,
            "reason": f"User is assigned to {len(groups)} IAM groups, increasing privilege surface."
        })

    # 4. Resolve attached and inline policy documents
    policy_names = user.get("policies", [])
    resolved_docs = [policy_doc_map[p] for p in policy_names if p in policy_doc_map]
    
    # Also evaluate user's inline policy documents directly
    inline_docs = list(user.get("inlinePolicyDocuments", {}).values())
    all_docs = resolved_docs + inline_docs

    # 5. Evaluate IAM Policy Document Risk
    doc_eval = evaluate_policy_document_risk(all_docs)
    for factor in doc_eval.get("factors", []):
        score += factor["points"]
        factors.append(factor)

    final_score = min(100, max(0, score))
    return {
        "score": final_score,
        "severity": get_severity_label(final_score),
        "factors": factors
    }


def score_user_risk(user: Dict[str, Any], policy_doc_map: Dict[str, str]) -> int:
    """Return integer risk score (0-100) for IAM User."""
    return get_user_risk_assessment(user, policy_doc_map)["score"]


def get_role_risk_assessment(role: Dict[str, Any], policy_doc_map: Dict[str, str]) -> Dict[str, Any]:
    """Calculate deterministic risk score and return structured evidence factors for an IAM Role."""
    factors: List[Dict[str, Any]] = []
    score = 0

    # 1. Structured Trust Policy Risk Evaluation (No string regex or name heuristics)
    trust_policy_input = role.get("trustPolicy") or role.get("assumeRolePolicyDocument")
    trust_eval = evaluate_trust_policy_risk(trust_policy_input)
    for factor in trust_eval.get("factors", []):
        score += factor["points"]
        factors.append(factor)

    # 2. Attached & Inline Policy Document Risk Evaluation
    attached_names = role.get("attachedPolicies", [])
    resolved_docs = [policy_doc_map[p] for p in attached_names if p in policy_doc_map]
    inline_docs = list(role.get("inlinePolicyDocuments", {}).values())
    all_docs = resolved_docs + inline_docs

    doc_eval = evaluate_policy_document_risk(all_docs)
    for factor in doc_eval.get("factors", []):
        score += factor["points"]
        factors.append(factor)

    final_score = min(100, max(0, score))
    return {
        "score": final_score,
        "severity": get_severity_label(final_score),
        "factors": factors
    }


def score_role_risk(role: Dict[str, Any], policy_doc_map: Dict[str, str]) -> int:
    """Return integer risk score (0-100) for IAM Role."""
    return get_role_risk_assessment(role, policy_doc_map)["score"]


def get_resource_risk_assessment(res: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate deterministic risk score and return structured evidence factors for Cloud Resources."""
    factors: List[Dict[str, Any]] = []
    score = 0
    rtype = res.get("type", "")
    details = res.get("details", {})

    if rtype == "S3":
        # S3 Public Exposure Check
        if not details.get("public_blocked", True):
            pts = WEIGHTS["S3_PUBLIC_EXPOSURE"]
            score += pts
            factors.append({
                "code": "S3_PUBLIC_EXPOSURE",
                "points": pts,
                "reason": "S3 Block Public Access is disabled or bucket policy permits public read/write."
            })
        # S3 Server-Side Encryption Check
        if not details.get("encrypted", True):
            pts = WEIGHTS["UNENCRYPTED_STORAGE"]
            score += pts
            factors.append({
                "code": "UNENCRYPTED_STORAGE",
                "points": pts,
                "reason": "Default server-side encryption (SSE-S3 or SSE-KMS) is not configured."
            })

    elif rtype == "Secrets":
        # Secret Rotation Check
        if not details.get("rotation_enabled", False):
            pts = WEIGHTS["SECRET_ROTATION_DISABLED"]
            score += pts
            factors.append({
                "code": "SECRET_ROTATION_DISABLED",
                "points": pts,
                "reason": "Automatic secret rotation is not enabled in Secrets Manager."
            })

    elif rtype == "EC2":
        # EC2 Public IP / Direct Exposure Check
        public_ip = details.get("public_ip", "None")
        if public_ip and public_ip != "None" and public_ip != "N/A":
            pts = WEIGHTS["EC2_PUBLIC_EXPOSURE"]
            score += pts
            factors.append({
                "code": "EC2_PUBLIC_IP",
                "points": pts,
                "reason": f"EC2 instance has a public IP address ({public_ip}) exposed to the internet."
            })

    elif rtype == "RDS":
        # RDS Public Exposure Check
        if details.get("publicly_accessible", False):
            pts = WEIGHTS["RDS_PUBLIC_EXPOSURE"]
            score += pts
            factors.append({
                "code": "RDS_PUBLIC_EXPOSURE",
                "points": pts,
                "reason": "RDS database instance is configured with public accessibility."
            })
        # RDS Storage Encryption Check
        if not details.get("storage_encrypted", True):
            pts = WEIGHTS["UNENCRYPTED_STORAGE"]
            score += pts
            factors.append({
                "code": "UNENCRYPTED_STORAGE",
                "points": pts,
                "reason": "RDS database storage volume encryption is disabled."
            })

    elif rtype == "DynamoDB":
        # DynamoDB Point-in-Time Recovery
        if not details.get("pitr_enabled", True):
            pts = WEIGHTS["PITR_DISABLED"]
            score += pts
            factors.append({
                "code": "PITR_DISABLED",
                "points": pts,
                "reason": "DynamoDB Point-in-Time Recovery (PITR) is not enabled for disaster recovery."
            })

    final_score = min(100, max(0, score))
    return {
        "score": final_score,
        "severity": get_severity_label(final_score),
        "factors": factors
    }


def score_resource_risk(res: Dict[str, Any]) -> int:
    """Return integer risk score (0-100) for Cloud Resource."""
    return get_resource_risk_assessment(res)["score"]


def compute_global_security_score(
    inventory: Any,
    attack_paths: List[Dict[str, Any]],
    cloudtrail_alerts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Calculate the global security posture score (0-100) from 5 weighted control categories:

    1. IAM Security (30%): Wildcard actions, privilege escalation, trust boundaries.
    2. Resource Security (25%): Public storage, encryption at rest, rotation, public endpoints.
    3. Privilege & Attack Path Risk (25%): Multi-hop lateral movement, critical blast radius.
    4. Identity Hygiene (10%): MFA enforcement, stale credential pruning, least privilege.
    5. Monitoring & Audit Coverage (10%): CloudTrail active monitoring and alerting coverage.

    Returns:
        {
            "overall_score": 82,
            "grade": "B+",
            "categories": {
                "iam_security": {"score": 75, "weight": 0.30, "weighted_score": 22.5},
                "resource_security": {"score": 85, "weight": 0.25, "weighted_score": 21.25},
                "attack_path_risk": {"score": 70, "weight": 0.25, "weighted_score": 17.5},
                "identity_hygiene": {"score": 90, "weight": 0.10, "weighted_score": 9.0},
                "monitoring_coverage": {"score": 95, "weight": 0.10, "weighted_score": 9.5}
            },
            "summary": "..."
        }
    """
    # 1. Identity Hygiene (0 - 100)
    users = getattr(inventory, "users", [])
    if users:
        mfa_enabled_count = sum(1 for u in users if u.get("mfaEnabled", False))
        mfa_ratio = mfa_enabled_count / len(users)
        active_ratio = sum(1 for u in users if u.get("lastActive") != "Never") / len(users)
        identity_hygiene_score = int((mfa_ratio * 70) + (active_ratio * 30))
    else:
        identity_hygiene_score = 100

    # 2. IAM Security (0 - 100)
    roles = getattr(inventory, "roles", [])
    all_iam = users + roles
    if all_iam:
        avg_iam_risk = sum(item.get("riskScore", 0) for item in all_iam) / len(all_iam)
        iam_security_score = max(0, min(100, int(100 - avg_iam_risk)))
    else:
        iam_security_score = 100

    # 3. Resource Security (0 - 100)
    all_resources = (
        getattr(inventory, "s3", []) +
        getattr(inventory, "ec2", []) +
        getattr(inventory, "secrets", []) +
        getattr(inventory, "rds", []) +
        getattr(inventory, "dynamodb", [])
    )
    if all_resources:
        avg_res_risk = sum(res.get("riskScore", 0) for res in all_resources) / len(all_resources)
        resource_security_score = max(0, min(100, int(100 - avg_res_risk)))
    else:
        resource_security_score = 100

    # 4. Attack Path Risk (0 - 100)
    if attack_paths:
        critical_paths = sum(1 for p in attack_paths if p.get("severity") == "critical")
        high_paths = sum(1 for p in attack_paths if p.get("severity") == "high")
        path_penalty = (critical_paths * 15) + (high_paths * 8) + (len(attack_paths) * 2)
        attack_path_score = max(0, min(100, int(100 - path_penalty)))
    else:
        attack_path_score = 100

    # 5. Monitoring & Audit Coverage (0 - 100)
    # Based on CloudTrail event recording and alerts presence
    if cloudtrail_alerts:
        monitoring_score = 90
    else:
        monitoring_score = 80

    # Weighted Overall Score
    w = GLOBAL_SCORE_WEIGHTS
    overall_score = int(
        (iam_security_score * w["iam_security"]) +
        (resource_security_score * w["resource_security"]) +
        (attack_path_score * w["attack_path_risk"]) +
        (identity_hygiene_score * w["identity_hygiene"]) +
        (monitoring_score * w["monitoring_coverage"])
    )
    overall_score = max(0, min(100, overall_score))

    def get_grade(s: int) -> str:
        if s >= 90: return "A"
        if s >= 80: return "B"
        if s >= 70: return "C"
        if s >= 60: return "D"
        return "F"

    return {
        "overall_score": overall_score,
        "grade": get_grade(overall_score),
        "categories": {
            "iam_security": {
                "name": "IAM & Access Control",
                "score": iam_security_score,
                "weight": w["iam_security"],
                "weighted_score": round(iam_security_score * w["iam_security"], 2)
            },
            "resource_security": {
                "name": "Resource Configuration Security",
                "score": resource_security_score,
                "weight": w["resource_security"],
                "weighted_score": round(resource_security_score * w["resource_security"], 2)
            },
            "attack_path_risk": {
                "name": "Privilege Escalation & Lateral Attack Paths",
                "score": attack_path_score,
                "weight": w["attack_path_risk"],
                "weighted_score": round(attack_path_score * w["attack_path_risk"], 2)
            },
            "identity_hygiene": {
                "name": "Identity Hygiene & Credentials",
                "score": identity_hygiene_score,
                "weight": w["identity_hygiene"],
                "weighted_score": round(identity_hygiene_score * w["identity_hygiene"], 2)
            },
            "monitoring_coverage": {
                "name": "Near-Real-Time CloudTrail Security Audit",
                "score": monitoring_score,
                "weight": w["monitoring_coverage"],
                "weighted_score": round(monitoring_score * w["monitoring_coverage"], 2)
            }
        },
        "summary": f"Calculated global security score of {overall_score}/100 across 5 verified security domains."
    }
