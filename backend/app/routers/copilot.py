from fastapi import APIRouter
from app.schemas import APIResponse, CopilotRequest, CopilotResponse
from datetime import datetime

router = APIRouter(tags=["Copilot"])

@router.post("/copilot", response_model=APIResponse[CopilotResponse])
def get_copilot_response(req: CopilotRequest):
    prompt = req.prompt
    
    sender = "ai"
    text = "I apologize, I could not extract details for that query. Please ask about 'Developer Path', 'Over-Privileged Users', 'Public Buckets', 'Trust Policy', or 'Compliance Summary'."
    type_str = "text"
    code_block = None
    
    if "Developer Path" in prompt or "PII S3" in prompt:
        text = "Security Analysis: The Developer Path represents a high-criticality attack vector. A compromised local developer-session allows credentials assumption of AWSAdminRole because the role lacks MFA constraints. The attacker inherits full s3:* permissions to access, download, or delete S3-Customer-PII-DB objects."
        type_str = "analysis"
        code_block = (
            "# MITRE ATT&CK Mapping:\n"
            "- T1078 (Valid Accounts): Compromised workstation credentials\n"
            "- T1548 (Abuse Elevation): sts:AssumeRole bypasses context\n"
            "- T1530 (Data from Cloud): Leakage from customer S3 store"
        )
    elif "Over-Privileged" in prompt:
        text = "Vulnerability Scan Summary: I found 2 highly over-privileged users:\n1. developer-session: Possesses wildcard inline S3 policies.\n2. ci-cd-runner: Houses credentials keys that have not been rotated in 180+ days."
        type_str = "analysis"
    elif "Public Buckets" in prompt or "S3 exposure" in prompt:
        text = "Assets Scan Findings: S3-Public-Assets has public read settings enabled (BlockPublicAccess is FALSE). The S3-Customer-PII-DB bucket has custom policy rules that permit global read access. Immediate block recommended."
        type_str = "remediation"
        code_block = (
            "aws s3api put-public-access-block \\\n"
            "  --bucket s3-customer-pii-db-production \\\n"
            "  --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        )
    elif "trust policy" in prompt or "least-privilege" in prompt:
        text = "Remediation Policy Suggested: Restrict the trust configuration document of AWSAdminRole to validate multi-factor authentication (MFA) and restrict access to internal corporate subnets:"
        type_str = "remediation"
        code_block = (
            "{\n"
            "  \"Version\": \"2012-10-17\",\n"
            "  \"Statement\": [\n"
            "    {\n"
            "      \"Effect\": \"Allow\",\n"
            "      \"Principal\": { \"AWS\": \"arn:aws:iam::123456789012:user/developer-session\" },\n"
            "      \"Action\": \"sts:AssumeRole\",\n"
            "      \"Condition\": {\n"
            "        \"Bool\": { \"aws:MultiFactorAuthPresent\": \"true\" },\n"
            "        \"IpAddress\": { \"aws:SourceIp\": \"10.0.0.0/8\" }\n"
            "      }\n"
            "    }\n"
            "  ]\n"
            "}"
        )
    elif "compliance summary" in prompt or "CIS" in prompt:
        text = (
            "Compliance Posture Status Report (CIS v1.4.0):\n"
            "- Section 1.2: Enforce MFA for Console Access -> FAIL (developer-session failed)\n"
            "- Section 1.12: Deactivate credentials key after 90 days -> FAIL (ci-cd-runner failed)\n"
            "- Section 2.1: Enforce encryption on all S3 Buckets -> PASS\n"
            "- Section 2.4: Enable CloudTrail logs in all regions -> PASS"
        )
        type_str = "analysis"

    data = CopilotResponse(
        sender=sender,
        text=text,
        type=type_str,
        codeBlock=code_block
    )

    return APIResponse(
        success=True,
        message="Copilot response constructed successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
