"""
CloudScope Remediation Guidance Engine.

Provides deterministic, evidence-based, safe, and read-only remediation guidance
for all security finding types. Never modifies AWS infrastructure.
"""

from typing import Dict, Any, List, Optional
from app.schemas import FindingRemediation


REMEDIATION_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "NO_MFA": {
        "title": "Enable MFA for IAM User",
        "priority": "HIGH",
        "summary": "Multi-Factor Authentication (MFA) is not enabled on this user account.",
        "steps": [
            "Sign in to the AWS Management Console as an administrator.",
            "Navigate to IAM Console -> Users -> select the affected user.",
            "Under the Security credentials tab, select Assign MFA device.",
            "Follow wizard to register a hardware or virtual TOTP authenticator device.",
            "Enforce an IAM policy requiring MFA for API and console operations."
        ],
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
        ]
    },
    "S3_PUBLIC_EXPOSURE": {
        "title": "Enable S3 Block Public Access",
        "priority": "CRITICAL",
        "summary": "Bucket allows unrestricted public read/write access from the internet.",
        "steps": [
            "Navigate to S3 Console -> select the affected bucket.",
            "Under Permissions tab, edit 'Block public access (bucket settings)'.",
            "Enable 'Block all public access' and save changes.",
            "Review the bucket policy to ensure Principal is restricted to authorized IAM roles or accounts.",
            "Audit bucket ACLs and remove any grants to 'Everyone' or 'Any authenticated AWS user'."
        ],
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        ]
    },
    "EC2_PUBLIC_IP": {
        "title": "Restrict Public EC2 Network Exposure",
        "priority": "HIGH",
        "summary": "Compute instance is assigned a public IP address and exposed to the internet.",
        "steps": [
            "Navigate to EC2 Console -> Instances -> select the instance.",
            "Review attached Security Groups and restrict ingress rules (avoid 0.0.0.0/0 on sensitive ports like 22, 3389, 8080).",
            "If public ingress is unnecessary, move the instance to a private subnet behind a NAT gateway.",
            "Use AWS Systems Manager Session Manager for administrative access instead of direct SSH/RDP."
        ],
        "references": [
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"
        ]
    },
    "RDS_PUBLIC_EXPOSURE": {
        "title": "Disable Public Accessibility for RDS Instance",
        "priority": "CRITICAL",
        "summary": "Database instance is configured with public accessibility enabled.",
        "steps": [
            "Navigate to RDS Console -> Databases -> select the database.",
            "Click Modify -> Connectivity section.",
            "Set 'Public access' to 'Not publicly accessible'.",
            "Ensure database subnet group uses private subnets.",
            "Verify security group allows ingress only from authorized application tiers or VPC peering."
        ],
        "references": [
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"
        ]
    },
    "SECRET_ROTATION_DISABLED": {
        "title": "Enable Automatic Secret Rotation",
        "priority": "MEDIUM",
        "summary": "AWS Secrets Manager secret has automatic rotation disabled.",
        "steps": [
            "Navigate to Secrets Manager Console -> select the secret.",
            "Under 'Rotation configuration', select 'Edit rotation'.",
            "Enable automatic rotation and configure rotation schedule (e.g. 30 or 90 days).",
            "Select or deploy the appropriate Lambda rotation function.",
            "Test rotation to verify dependent applications handle rotated credentials seamlessly."
        ],
        "references": [
            "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html"
        ]
    },
    "BROAD_IAM_PERMISSION": {
        "title": "Scope Wildcard IAM Permissions",
        "priority": "HIGH",
        "summary": "IAM policy grants broad wildcard actions (* or service:*) on wildcard resources (*).",
        "steps": [
            "Review CloudTrail logs or IAM Access Advisor to identify genuinely required actions.",
            "Replace wildcard Action ('*') with specific, required API actions.",
            "Scope Resource from '*' to specific resource ARNs.",
            "Attach a Permissions Boundary to restrict the maximum permissions the principal can obtain."
        ],
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
        ]
    },
    "PASSROLE_ESCALATION": {
        "title": "Restrict iam:PassRole Permission",
        "priority": "CRITICAL",
        "summary": "Identity has iam:PassRole with wildcard or elevated target roles, enabling privilege escalation.",
        "steps": [
            "Scope the Resource element of iam:PassRole statements from '*' to specific approved role ARNs.",
            "Add Condition 'iam:PassedToService' specifying only authorized AWS services (e.g. lambda.amazonaws.com, ec2.amazonaws.com).",
            "Audit target role trust policy and attached permissions to ensure target role does not possess AdministratorAccess.",
            "Remove unused role-passing capabilities from user or non-administrative roles."
        ],
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
        ]
    },
    "ASSUMEROLE_RISK": {
        "title": "Narrow AssumeRole Trust Policy and Scope",
        "priority": "HIGH",
        "summary": "IAM role has broad trust policy (wildcard principal or missing conditions) or wide sts:AssumeRole permissions.",
        "steps": [
            "Navigate to IAM Console -> Roles -> select the affected role.",
            "Under 'Trust relationships', edit trust policy to remove wildcard ('*') Principal.",
            "Specify explicit AWS account or IAM principal ARNs.",
            "Add Condition blocks requiring MFA ('aws:MultiFactorAuthPresent': 'true') or ExternalId where applicable.",
            "Apply least privilege to attached permissions policies."
        ],
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html"
        ]
    },
    "OBSERVED_SECURITY_ACTIVITY": {
        "title": "Investigate CloudTrail Security Activity",
        "priority": "HIGH",
        "summary": "Unusual or sensitive API execution recorded in CloudTrail logs.",
        "steps": [
            "Inspect CloudTrail event details including Source IP, User Identity ARN, and Event Time.",
            "Verify whether the recorded activity matches authorized operator actions or automated deployment.",
            "If activity was unexpected, revoke active session credentials immediately.",
            "Review static IAM policies granting the principal the capability to perform this action."
        ],
        "references": [
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html"
        ]
    },
    "ATTACK_PATH_VULNERABILITY": {
        "title": "Mitigate Lateral Movement Attack Path",
        "priority": "CRITICAL",
        "summary": "Chained IAM permissions allow lateral movement from identity to sensitive cloud targets.",
        "steps": [
            "Review the attack path transition steps in CloudScope Attack Paths view.",
            "Break the chain by removing the initial assume role or policy permission.",
            "Enforce IAM Permissions Boundaries and Service Control Policies (SCPs).",
            "Audit intermediate roles to enforce least privilege access."
        ],
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
        ]
    },
    "UNENCRYPTED_DATA_STORE": {
        "title": "Enable Server-Side Encryption",
        "priority": "MEDIUM",
        "summary": "Data store is configured without server-side encryption.",
        "steps": [
            "Enable default server-side encryption using AWS KMS (SSE-KMS) or provider-managed keys (SSE-S3).",
            "Enforce bucket or storage policy denying unencrypted object/data uploads.",
            "Audit KMS key policy to restrict key decryption permissions to authorized principals."
        ],
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"
        ]
    },
    "INACTIVE_CREDENTIALS": {
        "title": "Deactivate Stale IAM Credentials",
        "priority": "LOW",
        "summary": "IAM user has inactive or unused credentials over 90 days.",
        "steps": [
            "Navigate to IAM Console -> Users -> select the user.",
            "Under 'Security credentials', deactivate unused access keys.",
            "Delete unused login profiles if console access is no longer required.",
            "Delete stale access keys after confirming no services depend on them."
        ],
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        ]
    }
}


def generate_remediation(finding_type: str, item: Optional[Dict[str, Any]] = None, context: Optional[Dict[str, Any]] = None) -> FindingRemediation:
    """Generate structured, evidence-based remediation guidance for a finding.
    
    Safe and read-only: Never alters AWS configurations.
    """
    item = item or {}
    context = context or {}
    template = REMEDIATION_TEMPLATES.get(finding_type)

    if not template:
        name = item.get("name") or item.get("username") or item.get("id") or "resource"
        return FindingRemediation(
            title=f"Apply Least Privilege to {name}",
            summary=f"Review and restrict unnecessary permissions or public access on '{name}'.",
            steps=[
                f"Review current access patterns and configuration of '{name}'.",
                "Remove broad or unneeded administrative permissions.",
                "Enforce least-privilege access and resource-specific constraints."
            ],
            priority="MEDIUM",
            references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"]
        )

    target_name = item.get("name") or item.get("username") or ""
    summary = template["summary"]
    if target_name and target_name not in summary:
        summary = f"{template['summary']} (Affects: {target_name})"

    return FindingRemediation(
        title=template["title"],
        summary=summary,
        steps=list(template["steps"]),
        priority=template["priority"],
        references=list(template["references"])
    )
