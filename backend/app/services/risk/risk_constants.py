"""
CloudScope Risk Scoring Constants and Configuration.
Deterministic, evidence-based weights and threshold definitions.
Single source of truth for backend risk engine, API routers, and reports.
"""

# -------------------------------------------------------------------------
# SEVERITY THRESHOLDS (0 - 100 Scale)
# -------------------------------------------------------------------------
SEVERITY_CRITICAL_THRESHOLD = 80
SEVERITY_HIGH_THRESHOLD = 60
SEVERITY_MEDIUM_THRESHOLD = 40
SEVERITY_LOW_THRESHOLD = 0

def get_severity_label(score: int) -> str:
    """Return normalized severity label from numeric score (0-100)."""
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return "critical"
    if score >= SEVERITY_HIGH_THRESHOLD:
        return "high"
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


# -------------------------------------------------------------------------
# ENTITY RISK SCORING WEIGHTS (Additive Points, Clamped to 0 - 100)
# -------------------------------------------------------------------------
WEIGHTS = {
    # Identity & User Controls
    "NO_MFA": 15,
    "INACTIVE_STALE_CREDENTIALS": 10,
    "MANY_GROUPS": 5,

    # IAM Policy & Permissions Controls
    "WILDCARD_ACTION": 25,
    "WILDCARD_RESOURCE": 25,
    "FULL_ADMIN_PERMISSION": 20,
    "PRIVILEGE_ESCALATION_PERMS": 20,
    "WILDCARD_ALLOW_ALL": 30,

    # Trust Policy Controls
    "WILDCARD_TRUST_PRINCIPAL": 25,
    "CROSS_ACCOUNT_TRUST": 15,
    "UNRESTRICTED_SERVICE_TRUST": 10,

    # Cloud Resource Security Controls
    "S3_PUBLIC_EXPOSURE": 30,
    "RDS_PUBLIC_EXPOSURE": 30,
    "EC2_PUBLIC_EXPOSURE": 20,
    "UNENCRYPTED_STORAGE": 15,
    "SECRET_ROTATION_DISABLED": 10,
    "PITR_DISABLED": 10,

    # Graph Context & Lateral Reachability
    "REACHABLE_PRIVILEGED_ROLE": 10,
    "REACHABLE_SENSITIVE_TARGET": 15,
}

# Dangerous IAM Privilege Escalation Actions
DANGEROUS_ESCALATION_ACTIONS = {
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:passrole",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:putgrouppolicy",
    "iam:addusertogroup",
    "iam:updateassumerolepolicy",
    "iam:createloginprofile",
    "iam:updateaccesskey",
    "sts:assumerole"
}

# Broad Administrative Actions
BROAD_ADMIN_ACTIONS = {
    "*",
    "*:*",
    "iam:*",
    "sts:*",
    "s3:*",
    "ec2:*",
    "dynamodb:*",
    "secretsmanager:*",
    "rds:*"
}

# -------------------------------------------------------------------------
# GLOBAL POSTURE SCORE CATEGORY WEIGHTS (Must sum to 1.00)
# -------------------------------------------------------------------------
GLOBAL_SCORE_WEIGHTS = {
    "iam_security": 0.30,           # 30%
    "resource_security": 0.25,      # 25%
    "attack_path_risk": 0.25,       # 25%
    "identity_hygiene": 0.10,       # 10%
    "monitoring_coverage": 0.10     # 10%
}
