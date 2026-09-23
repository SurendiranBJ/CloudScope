"""
CloudScope Canonical Security Finding Service.

Provides deterministic finding identification, deduplication, structured evidence aggregation,
risk score factor binding, read-only remediation linking, and lifecycle management.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple

from app.schemas import SecurityFinding, FindingRemediation
from app.services.risk.risk_constants import (
    SEVERITY_CRITICAL_THRESHOLD,
    SEVERITY_HIGH_THRESHOLD,
    SEVERITY_MEDIUM_THRESHOLD,
    get_severity_label
)
from app.services.findings.remediation_engine import generate_remediation
from app.cache import cache

logger = logging.getLogger("scanner")

# Valid Category Taxonomy
VALID_CATEGORIES = {
    "IAM",
    "RESOURCE",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "CLOUDTRAIL",
    "CREDENTIAL",
    "CONFIGURATION",
    "DATA_ACCESS",
    "MONITORING"
}


def compute_deterministic_id(
    finding_type: str,
    principal: Optional[str] = None,
    resource: Optional[str] = None,
    policy_arn: Optional[str] = None,
    statement_sid: Optional[str] = None,
    event_id: Optional[str] = None,
    attack_path_id: Optional[str] = None,
    region: Optional[str] = None
) -> str:
    """Generate a deterministic, stable finding identity.
    
    Timestamps are never used in static finding identities.
    """
    if event_id:
        return f"find-ct-{event_id}"
    if attack_path_id:
        clean_path_id = attack_path_id.replace("path-", "")
        return f"find-path-{clean_path_id}"

    # For static findings, hash semantic identity attributes
    raw_key = (
        f"{finding_type.upper()}|"
        f"{principal or ''}|"
        f"{resource or ''}|"
        f"{policy_arn or ''}|"
        f"{statement_sid or ''}|"
        f"{region or ''}"
    )
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
    type_prefix = finding_type.lower().replace("_", "-")[:12]
    return f"find-{type_prefix}-{digest}"


class FindingService:
    def __init__(self):
        self._memory_store: Dict[str, SecurityFinding] = {}

    def get_all_findings(self) -> List[SecurityFinding]:
        """Retrieve all canonical findings from cache or in-memory store."""
        cached = cache.get("v1:findings")
        if cached:
            # Rehydrate if dicts
            return [f if isinstance(f, SecurityFinding) else SecurityFinding(**f) for f in cached]
        return list(self._memory_store.values())

    def get_finding_by_id(self, finding_id: str) -> Optional[SecurityFinding]:
        """Retrieve a single finding by its deterministic ID."""
        for f in self.get_all_findings():
            if f.id == finding_id:
                return f
        return None

    def acknowledge_finding(self, finding_id: str) -> Optional[SecurityFinding]:
        """Transition finding status to ACKNOWLEDGED."""
        findings = self.get_all_findings()
        matched = None
        for f in findings:
            if f.id == finding_id:
                f.status = "ACKNOWLEDGED"
                matched = f
                break
        if matched:
            self._save_findings(findings)
        return matched

    def resolve_finding(self, finding_id: str) -> Optional[SecurityFinding]:
        """Transition finding status to RESOLVED."""
        findings = self.get_all_findings()
        matched = None
        for f in findings:
            if f.id == finding_id:
                f.status = "RESOLVED"
                matched = f
                break
        if matched:
            self._save_findings(findings)
        return matched

    def suppress_finding(self, finding_id: str) -> Optional[SecurityFinding]:
        """Transition finding status to SUPPRESSED."""
        findings = self.get_all_findings()
        matched = None
        for f in findings:
            if f.id == finding_id:
                f.status = "SUPPRESSED"
                matched = f
                break
        if matched:
            self._save_findings(findings)
        return matched

    def _save_findings(self, findings: List[SecurityFinding]):
        """Persist findings to in-memory store and cache."""
        self._memory_store = {f.id: f for f in findings}
        cache.set("v1:findings", [f.model_dump() for f in findings])

    def extract_findings_from_scan(
        self,
        inventory: Any,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        correlated_findings: Optional[List[Dict[str, Any]]] = None,
        scan_timestamp: Optional[str] = None
    ) -> List[SecurityFinding]:
        """Extract canonical findings from current scan inventory, attack paths, and runtime activity."""
        ts = scan_timestamp or (datetime.utcnow().isoformat() + "Z")
        findings: List[SecurityFinding] = []

        users = getattr(inventory, "users", [])
        roles = getattr(inventory, "roles", [])
        s3 = getattr(inventory, "s3", [])
        ec2 = getattr(inventory, "ec2", [])
        secrets = getattr(inventory, "secrets", [])
        rds = getattr(inventory, "rds", [])
        dynamodb = getattr(inventory, "dynamodb", [])

        # -------------------------------------------------------------
        # 1. IAM Users Findings
        # -------------------------------------------------------------
        for u in users:
            uname = u.get("name") or u.get("username") or "unknown"
            uarn = u.get("arn", "")
            risk_assessment = u.get("riskAssessment", {})
            factors = risk_assessment.get("factors", [])
            score = u.get("riskScore", 0)

            # A. No MFA
            if not u.get("mfaEnabled", True):
                fid = compute_deterministic_id("NO_MFA", principal=uarn or uname)
                mfa_score = max(score, 70)
                sev = get_severity_label(mfa_score)
                remediation = generate_remediation("NO_MFA", u)
                evidence = {
                    "mfa_enabled": False,
                    "principal_arn": uarn,
                    "user_name": uname
                }
                findings.append(SecurityFinding(
                    id=fid,
                    type="NO_MFA",
                    category="CREDENTIAL",
                    title=f"MFA Not Enabled for User '{uname}'",
                    description=f"IAM user '{uname}' does not have Multi-Factor Authentication (MFA) configured.",
                    severity=sev,
                    riskScore=mfa_score,
                    riskFactors=[{"code": "NO_MFA", "points": 25, "reason": "User credentials lack MFA enforcement."}],
                    principal=uname,
                    principalType="User",
                    resource=uname,
                    resourceType="User",
                    resourceArn=uarn,
                    region="global",
                    evidence=evidence,
                    impact="If password or access keys are compromised, an attacker can directly authenticate without a second factor.",
                    remediation=remediation,
                    status="OPEN",
                    source="STATIC_IAM",
                    tags=["iam", "mfa", "credential"],
                    identity=uname,
                    identityType="User",
                    issue="Multi-Factor Authentication (MFA) is not enabled on this user account.",
                    recommendation=remediation.title
                ))

            # B. Inactive / Stale Credentials
            if u.get("lastActive") == "Never" or u.get("inactive_days", 0) > 90:
                fid = compute_deterministic_id("INACTIVE_CREDENTIALS", principal=uarn or uname)
                remediation = generate_remediation("INACTIVE_CREDENTIALS", u)
                findings.append(SecurityFinding(
                    id=fid,
                    type="INACTIVE_CREDENTIALS",
                    category="CREDENTIAL",
                    title=f"Stale Credentials on User '{uname}'",
                    description=f"IAM user '{uname}' has inactive or never-used credentials (last active: {u.get('lastActive')}).",
                    severity="low",
                    riskScore=25,
                    riskFactors=[{"code": "INACTIVE_CREDENTIALS", "points": 10, "reason": "User credentials have not been used recently."}],
                    principal=uname,
                    principalType="User",
                    resource=uname,
                    resourceType="User",
                    resourceArn=uarn,
                    region="global",
                    evidence={"last_active": u.get("lastActive"), "user_arn": uarn},
                    impact="Unmonitored and unused accounts remain a dormant attack vector for unauthorized access.",
                    remediation=remediation,
                    status="OPEN",
                    source="STATIC_IAM",
                    tags=["iam", "credentials", "hygiene"],
                    identity=uname,
                    identityType="User",
                    issue=f"User credentials appear inactive or have never been used (last active: {u.get('lastActive')}).",
                    recommendation=remediation.title
                ))

            # C. Broad User Permissions (score >= 60)
            if score >= SEVERITY_HIGH_THRESHOLD:
                fid = compute_deterministic_id("BROAD_IAM_PERMISSION", principal=uarn or uname)
                remediation = generate_remediation("BROAD_IAM_PERMISSION", u)
                findings.append(SecurityFinding(
                    id=fid,
                    type="BROAD_IAM_PERMISSION",
                    category="IAM",
                    title=f"Elevated IAM Privileges on User '{uname}'",
                    description=f"IAM user '{uname}' has broad administrative or privilege-escalating IAM policies.",
                    severity=get_severity_label(score),
                    riskScore=score,
                    riskFactors=factors or [{"code": "ELEVATED_USER", "points": score, "reason": "Elevated IAM policy attachment."}],
                    principal=uname,
                    principalType="User",
                    resource=uname,
                    resourceType="User",
                    resourceArn=uarn,
                    region="global",
                    evidence={"attached_policies": u.get("policies", []), "risk_factors": factors},
                    impact="Excessive IAM permissions violate least-privilege principles and increase blast radius upon compromise.",
                    remediation=remediation,
                    status="OPEN",
                    source="STATIC_IAM",
                    tags=["iam", "least-privilege"],
                    identity=uname,
                    identityType="User",
                    issue="User has elevated administrative permissions.",
                    recommendation=remediation.title
                ))

        # -------------------------------------------------------------
        # 2. IAM Roles Findings
        # -------------------------------------------------------------
        for r in roles:
            rname = r.get("name") or "unknown"
            rarn = r.get("arn", "")
            score = r.get("riskScore", 0)
            trust_policy = str(r.get("trustPolicy", ""))
            factors = r.get("riskAssessment", {}).get("factors", [])

            # A. Wildcard AssumeRole Trust
            if "*" in trust_policy:
                fid = compute_deterministic_id("ASSUMEROLE_RISK", principal=rarn or rname)
                trust_score = max(score, 75)
                remediation = generate_remediation("ASSUMEROLE_RISK", r)
                findings.append(SecurityFinding(
                    id=fid,
                    type="ASSUMEROLE_RISK",
                    category="IAM",
                    title=f"Broad AssumeRole Trust Policy on Role '{rname}'",
                    description=f"IAM role '{rname}' allows wildcard or cross-account principals to assume it.",
                    severity=get_severity_label(trust_score),
                    riskScore=trust_score,
                    riskFactors=[{"code": "WILDCARD_TRUST_PRINCIPAL", "points": 25, "reason": "Trust policy contains wildcard Principal."}],
                    principal=rname,
                    principalType="Role",
                    resource=rname,
                    resourceType="Role",
                    resourceArn=rarn,
                    region="global",
                    evidence={"trust_policy": trust_policy, "role_arn": rarn},
                    impact="Any external entity or account may assume this role if trust conditions are insufficiently constrained.",
                    remediation=remediation,
                    status="OPEN",
                    source="STATIC_IAM",
                    tags=["iam", "trust-policy", "assumerole"],
                    identity=rname,
                    identityType="Role",
                    issue="Broad trust policy allows untrusted or wildcard principals to assume role.",
                    recommendation=remediation.title
                ))

            # B. Broad Role Permissions (score >= 60)
            elif score >= SEVERITY_HIGH_THRESHOLD:
                fid = compute_deterministic_id("BROAD_IAM_PERMISSION", principal=rarn or rname)
                remediation = generate_remediation("BROAD_IAM_PERMISSION", r)
                findings.append(SecurityFinding(
                    id=fid,
                    type="BROAD_IAM_PERMISSION",
                    category="IAM",
                    title=f"Elevated Privileges on Role '{rname}'",
                    description=f"IAM role '{rname}' possesses high-privilege administrative permissions.",
                    severity=get_severity_label(score),
                    riskScore=score,
                    riskFactors=factors or [{"code": "HIGH_PRIVILEGE_ROLE", "points": score, "reason": "Role attached policies grant broad access."}],
                    principal=rname,
                    principalType="Role",
                    resource=rname,
                    resourceType="Role",
                    resourceArn=rarn,
                    region="global",
                    evidence={"policies": r.get("attachedPolicies", []), "risk_factors": factors},
                    impact="High-privilege roles present major escalation vectors if assumed by compromised workload profiles.",
                    remediation=remediation,
                    status="OPEN",
                    source="STATIC_IAM",
                    tags=["iam", "least-privilege"],
                    identity=rname,
                    identityType="Role",
                    issue="Role has elevated administrative permissions.",
                    recommendation=remediation.title
                ))

        # -------------------------------------------------------------
        # 3. Cloud Resources Findings
        # -------------------------------------------------------------
        # A. S3 Buckets
        for b in s3:
            bname = b.get("name") or "unknown"
            barn = b.get("arn") or f"arn:aws:s3:::{bname}"
            bregion = b.get("region") or "us-east-1"
            details = b.get("details", {})
            bscore = b.get("riskScore", 0)

            if not details.get("public_blocked", True):
                fid = compute_deterministic_id("S3_PUBLIC_EXPOSURE", resource=barn, region=bregion)
                remediation = generate_remediation("S3_PUBLIC_EXPOSURE", b)
                findings.append(SecurityFinding(
                    id=fid,
                    type="S3_PUBLIC_EXPOSURE",
                    category="DATA_ACCESS",
                    title=f"Public S3 Bucket Exposure: '{bname}'",
                    description=f"S3 bucket '{bname}' does not have Block Public Access fully enabled.",
                    severity="critical",
                    riskScore=max(bscore, 85),
                    riskFactors=[{"code": "S3_PUBLIC_EXPOSURE", "points": 30, "reason": "Public access block is disabled."}],
                    resource=bname,
                    resourceType="S3",
                    resourceArn=barn,
                    region=bregion,
                    evidence={"public_blocked": False, "bucket_name": bname, "region": bregion},
                    impact="Unauthorized internet users can read or upload files, risking data exfiltration or malware staging.",
                    remediation=remediation,
                    status="OPEN",
                    source="RESOURCE_CONFIGURATION",
                    tags=["s3", "public-exposure", "data-protection"],
                    identity=bname,
                    identityType="EC2",  # Frontend expects 'User' | 'Role' | 'EC2' | 'Lambda'
                    issue="Public access not blocked (potential data exposure)",
                    recommendation=remediation.title
                ))

            if not details.get("encrypted", True):
                fid = compute_deterministic_id("UNENCRYPTED_DATA_STORE", resource=barn, region=bregion)
                remediation = generate_remediation("UNENCRYPTED_DATA_STORE", b)
                findings.append(SecurityFinding(
                    id=fid,
                    type="UNENCRYPTED_DATA_STORE",
                    category="CONFIGURATION",
                    title=f"Unencrypted S3 Bucket: '{bname}'",
                    description=f"S3 bucket '{bname}' does not have default server-side encryption enabled.",
                    severity="medium",
                    riskScore=max(bscore, 45),
                    riskFactors=[{"code": "UNENCRYPTED_STORAGE", "points": 15, "reason": "Default server-side encryption missing."}],
                    resource=bname,
                    resourceType="S3",
                    resourceArn=barn,
                    region=bregion,
                    evidence={"encrypted": False, "bucket_name": bname},
                    impact="Data stored at rest is not protected by AES-256 or AWS KMS encryption.",
                    remediation=remediation,
                    status="OPEN",
                    source="RESOURCE_CONFIGURATION",
                    tags=["s3", "encryption"],
                    identity=bname,
                    identityType="EC2",
                    issue="Server-side encryption not configured",
                    recommendation=remediation.title
                ))

        # B. EC2 Instances
        for inst in ec2:
            iname = inst.get("name") or inst.get("id") or "unknown"
            iarn = inst.get("arn") or iname
            iregion = inst.get("region") or "us-east-1"
            details = inst.get("details", {})
            pub_ip = details.get("public_ip")
            iscore = inst.get("riskScore", 0)

            if pub_ip and pub_ip != "None":
                fid = compute_deterministic_id("EC2_PUBLIC_IP", resource=iarn, region=iregion)
                remediation = generate_remediation("EC2_PUBLIC_IP", inst)
                findings.append(SecurityFinding(
                    id=fid,
                    type="EC2_PUBLIC_IP",
                    category="RESOURCE",
                    title=f"Publicly Accessible EC2 Instance: '{iname}'",
                    description=f"EC2 instance '{iname}' has public IP address '{pub_ip}' exposed to the internet.",
                    severity="high" if iscore >= 60 else "medium",
                    riskScore=max(iscore, 65),
                    riskFactors=[{"code": "EC2_PUBLIC_EXPOSURE", "points": 20, "reason": f"Direct public IP address ({pub_ip})."}],
                    resource=iname,
                    resourceType="EC2",
                    resourceArn=iarn,
                    region=iregion,
                    evidence={"public_ip": pub_ip, "instance_id": iname, "region": iregion},
                    impact="Workload is directly accessible from public IP space and subject to network scanning and brute force.",
                    remediation=remediation,
                    status="OPEN",
                    source="RESOURCE_CONFIGURATION",
                    tags=["ec2", "network", "public-ip"],
                    identity=iname,
                    identityType="EC2",
                    issue=f"Publicly accessible instance ({pub_ip})",
                    recommendation=remediation.title
                ))

        # C. RDS Databases
        for db in rds:
            dname = db.get("name") or db.get("id") or "unknown"
            darn = db.get("arn") or dname
            dregion = db.get("region") or "us-east-1"
            details = db.get("details", {})
            dscore = db.get("riskScore", 0)

            if details.get("publicly_accessible", False):
                fid = compute_deterministic_id("RDS_PUBLIC_EXPOSURE", resource=darn, region=dregion)
                remediation = generate_remediation("RDS_PUBLIC_EXPOSURE", db)
                findings.append(SecurityFinding(
                    id=fid,
                    type="RDS_PUBLIC_EXPOSURE",
                    category="DATA_ACCESS",
                    title=f"Public RDS Database: '{dname}'",
                    description=f"RDS database '{dname}' is publicly accessible over the internet.",
                    severity="critical",
                    riskScore=max(dscore, 85),
                    riskFactors=[{"code": "RDS_PUBLIC_EXPOSURE", "points": 30, "reason": "Database is publicly accessible."}],
                    resource=dname,
                    resourceType="RDS",
                    resourceArn=darn,
                    region=dregion,
                    evidence={"publicly_accessible": True, "db_name": dname, "region": dregion},
                    impact="Database endpoint resolves to a public IP and may be directly targeted for database credential exploits.",
                    remediation=remediation,
                    status="OPEN",
                    source="RESOURCE_CONFIGURATION",
                    tags=["rds", "database", "public-exposure"],
                    identity=dname,
                    identityType="EC2",
                    issue="Publicly accessible database",
                    recommendation=remediation.title
                ))

            if not details.get("storage_encrypted", True):
                fid = compute_deterministic_id("UNENCRYPTED_DATA_STORE", resource=darn, region=dregion)
                remediation = generate_remediation("UNENCRYPTED_DATA_STORE", db)
                findings.append(SecurityFinding(
                    id=fid,
                    type="UNENCRYPTED_DATA_STORE",
                    category="CONFIGURATION",
                    title=f"Unencrypted RDS Storage: '{dname}'",
                    description=f"RDS instance '{dname}' storage volumes are not encrypted.",
                    severity="medium",
                    riskScore=max(dscore, 45),
                    riskFactors=[{"code": "UNENCRYPTED_STORAGE", "points": 15, "reason": "Storage encryption is disabled."}],
                    resource=dname,
                    resourceType="RDS",
                    resourceArn=darn,
                    region=dregion,
                    evidence={"storage_encrypted": False, "db_name": dname},
                    impact="Unencrypted database volumes fail compliance requirements and data-at-rest protection standards.",
                    remediation=remediation,
                    status="OPEN",
                    source="RESOURCE_CONFIGURATION",
                    tags=["rds", "encryption"],
                    identity=dname,
                    identityType="EC2",
                    issue="Storage volume unencrypted",
                    recommendation=remediation.title
                ))

        # D. Secrets Manager
        for sec in secrets:
            sname = sec.get("name") or "unknown"
            sarn = sec.get("arn") or sname
            sregion = sec.get("region") or "us-east-1"
            details = sec.get("details", {})
            sscore = sec.get("riskScore", 0)

            if not details.get("rotation_enabled", False):
                fid = compute_deterministic_id("SECRET_ROTATION_DISABLED", resource=sarn, region=sregion)
                remediation = generate_remediation("SECRET_ROTATION_DISABLED", sec)
                findings.append(SecurityFinding(
                    id=fid,
                    type="SECRET_ROTATION_DISABLED",
                    category="CREDENTIAL",
                    title=f"Secret Rotation Disabled: '{sname}'",
                    description=f"AWS Secrets Manager secret '{sname}' does not have automatic rotation enabled.",
                    severity="medium",
                    riskScore=max(sscore, 40),
                    riskFactors=[{"code": "SECRET_ROTATION_DISABLED", "points": 10, "reason": "Automatic secret rotation is not configured."}],
                    resource=sname,
                    resourceType="Secrets",
                    resourceArn=sarn,
                    region=sregion,
                    evidence={"rotation_enabled": False, "secret_name": sname, "region": sregion},
                    impact="Static, unrotated credentials increase exposure window if credentials are leaked or captured in logs.",
                    remediation=remediation,
                    status="OPEN",
                    source="RESOURCE_CONFIGURATION",
                    tags=["secrets", "credentials", "rotation"],
                    identity=sname,
                    identityType="EC2",
                    issue="Automatic secret rotation is not enabled",
                    recommendation=remediation.title
                ))

        # -------------------------------------------------------------
        # 4. Attack Path Findings
        # -------------------------------------------------------------
        for p in (attack_paths or []):
            pid = p.get("id", "path-unknown")
            pname = p.get("name") or pid
            pscore = p.get("riskScore") or p.get("risk_score") or 75
            psev = p.get("severity", "high")
            pdesc = p.get("description", "")
            preason = p.get("reason", "")
            source_principal = p.get("source") or (p.get("nodes", [{}])[0].get("name") if p.get("nodes") else "unknown")
            dest_resource = p.get("target") or p.get("destination") or (p.get("nodes", [{}])[-1].get("name") if p.get("nodes") else "unknown")
            is_passrole = "passrole" in pname.lower() or "passrole" in pdesc.lower()
            
            ftype = "PASSROLE_ESCALATION" if is_passrole else "ATTACK_PATH_VULNERABILITY"
            fcat = "PRIVILEGE_ESCALATION" if is_passrole or "privilege" in pname.lower() else "LATERAL_MOVEMENT"
            
            fid = compute_deterministic_id(ftype, attack_path_id=pid)
            remediation = generate_remediation(ftype, p)
            evidence = {
                "attack_path_id": pid,
                "path_name": pname,
                "source": source_principal,
                "target": dest_resource,
                "ordered_relationships": p.get("orderedRelationships") or p.get("ordered_relationships", []),
                "blast_radius": p.get("blastRadius") or p.get("blast_radius", "")
            }

            findings.append(SecurityFinding(
                id=fid,
                type=ftype,
                category=fcat,
                title=f"Attack Vector: {pname}",
                description=pdesc or f"Chained lateral movement path from '{source_principal}' to '{dest_resource}'.",
                severity=psev,
                riskScore=pscore,
                riskFactors=[{"code": "LATERAL_ATTACK_PATH", "points": pscore, "reason": preason or "Multi-step lateral movement path verified."}],
                principal=source_principal,
                principalType="Identity",
                resource=dest_resource,
                resourceType="TargetResource",
                attackPathId=pid,
                evidence=evidence,
                impact=f"Attacker compromising '{source_principal}' can laterally escalate privileges to reach '{dest_resource}'.",
                remediation=remediation,
                status="OPEN",
                source="ATTACK_PATH",
                tags=["attack-path", fcat.lower()],
                identity=source_principal,
                identityType="Role",
                issue=pdesc or f"Lateral movement path to {dest_resource}",
                recommendation=remediation.title
            ))

        # -------------------------------------------------------------
        # 5. CloudTrail Correlated & Runtime Findings
        # -------------------------------------------------------------
        for cf in (correlated_findings or []):
            eid = cf.get("eventId") or cf.get("event_id") or cf.get("id") or ""
            ev_name = cf.get("eventName") or cf.get("event_name") or ""
            actor = cf.get("actor") or cf.get("actor_name") or "Unknown"
            target = cf.get("target") or cf.get("target_name") or "Unknown"
            cscore = cf.get("risk_score") or cf.get("riskScore") or 80
            csev = cf.get("severity") or "high"
            creason = cf.get("reason") or "Observed CloudTrail management activity."
            ev_time = cf.get("event_time") or cf.get("eventTime") or ""
            matched_rel = cf.get("matched_static_relationship") or "NONE"

            fid = compute_deterministic_id("OBSERVED_SECURITY_ACTIVITY", event_id=eid or f"{actor}_{ev_name}")
            remediation = generate_remediation("OBSERVED_SECURITY_ACTIVITY", cf)

            findings.append(SecurityFinding(
                id=fid,
                type="OBSERVED_SECURITY_ACTIVITY",
                category="CLOUDTRAIL" if matched_rel == "NONE" else "MONITORING",
                title=f"Observed Activity: {ev_name} by '{actor}'",
                description=creason,
                severity=csev,
                riskScore=cscore,
                riskFactors=[{"code": "RUNTIME_ACTIVITY", "points": cscore, "reason": creason}],
                principal=actor,
                principalType="Actor",
                resource=target,
                resourceType="Target",
                eventId=eid,
                eventName=ev_name,
                eventTime=ev_time,
                evidence={
                    "event_id": eid,
                    "event_name": ev_name,
                    "event_time": ev_time,
                    "actor": actor,
                    "target": target,
                    "matched_static_relationship": matched_rel,
                    "source_ip": cf.get("source_ip") or cf.get("sourceIp")
                },
                impact=f"Sensitive runtime operation '{ev_name}' was recorded in CloudTrail against target '{target}'.",
                remediation=remediation,
                status="OPEN",
                source="CORRELATION" if matched_rel != "NONE" else "CLOUDTRAIL",
                tags=["cloudtrail", "runtime", "activity"],
                identity=actor,
                identityType="User",
                issue=creason,
                recommendation=remediation.title
            ))

        return findings

    def reconcile_scan_findings(
        self,
        inventory: Any,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        correlated_findings: Optional[List[Dict[str, Any]]] = None,
        successful_regions: Optional[List[str]] = None,
        failed_regions: Optional[List[str]] = None,
        scan_timestamp: Optional[str] = None
    ) -> List[SecurityFinding]:
        """Perform deterministic finding lifecycle reconciliation across scans.
        
        Preserves user-acknowledged / suppressed states.
        Preserves original firstSeen timestamp.
        Implements Regional Failure Isolation: Failed regions do NOT resolve existing findings.
        """
        scan_ts = scan_timestamp or (datetime.utcnow().isoformat() + "Z")
        succ_regs = set(successful_regions or [])
        fail_regs = set(failed_regions or [])

        # 1. Extract newly detected findings from current scan snapshot
        new_findings = self.extract_findings_from_scan(
            inventory=inventory,
            attack_paths=attack_paths,
            correlated_findings=correlated_findings,
            scan_timestamp=scan_ts
        )

        new_findings_map = {f.id: f for f in new_findings}

        # 2. Load historical findings
        historical_findings = self.get_all_findings()
        historical_map = {f.id: f for f in historical_findings}

        reconciled: List[SecurityFinding] = []

        # 3. Process all active findings from current scan
        for fid, n_find in new_findings_map.items():
            if fid in historical_map:
                h_find = historical_map[fid]
                # Preserve original firstSeen
                n_find.firstSeen = h_find.firstSeen or scan_ts
                n_find.lastSeen = scan_ts

                # Preserve user lifecycle decisions
                if h_find.status in ["ACKNOWLEDGED", "SUPPRESSED"]:
                    n_find.status = h_find.status
                elif h_find.status == "RESOLVED":
                    # Reopen if vulnerability reappeared
                    n_find.status = "OPEN"
                else:
                    n_find.status = "OPEN"
            else:
                n_find.firstSeen = scan_ts
                n_find.lastSeen = scan_ts
                n_find.status = "OPEN"

            reconciled.append(n_find)

        # 4. Process historical findings not present in current scan
        for fid, h_find in historical_map.items():
            if fid not in new_findings_map:
                f_region = h_find.region or "global"

                # REGIONAL FAILURE ISOLATION CHECK:
                # If finding was in a region that failed during the scan, DO NOT resolve it!
                if f_region in fail_regs:
                    # Region failed, keep finding active in historical state
                    reconciled.append(h_find)
                elif f_region in succ_regs or f_region == "global":
                    # Successful scan verified the condition no longer exists -> Transition to RESOLVED
                    h_find.status = "RESOLVED"
                    h_find.lastSeen = scan_ts
                    reconciled.append(h_find)
                else:
                    # Region wasn't evaluated in this scan, retain current state
                    reconciled.append(h_find)

        # Save to store and cache
        self._save_findings(reconciled)
        return reconciled


finding_service = FindingService()
