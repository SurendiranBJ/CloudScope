from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, RiskFinding
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Risk"])

@router.get("/risk-assessment", response_model=APIResponse[List[RiskFinding]])
def get_risk_assessment_findings():
    data = cache.get("v1:risks")
    if not data:
        # Fall back to canonical findings store
        findings = cache.get("v1:findings")
        if findings:
            data = [
                RiskFinding(
                    id=f.get("id", ""),
                    identity=f.get("principal") or f.get("resource") or "unknown",
                    identityType=f.get("principalType") or f.get("resourceType") or "Resource",
                    issue=f.get("description") or f.get("title", ""),
                    severity=f.get("severity", "medium"),
                    riskScore=f.get("riskScore", 0),
                    recommendation=f.get("remediation", {}).get("title") if isinstance(f.get("remediation"), dict) else (f.get("recommendation") or "Review configuration")
                )
                for f in findings
                if f.get("status") == "OPEN" and f.get("riskScore", 0) >= 40
            ]
            data.sort(key=lambda x: x.riskScore, reverse=True)
        elif not scan_manager.is_running:
            scan_manager.trigger_async_scan()
            data = []
        else:
            data = []
        
    return APIResponse(
        success=True,
        message="Risk assessment findings retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
