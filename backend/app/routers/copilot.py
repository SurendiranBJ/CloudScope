from app.utils.time import utc_now_iso
"""
CloudScope AI Security Copilot Router.

Provides evidence-grounded AI security explanations, investigation assistance,
and remediation guidance powered by Gemini.
No hardcoded mock responses; all insights are grounded in authoritative CloudScope security data.
"""

import logging
import json
import time
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Depends, Request

from app.config import settings
from app.schemas import (
    APIResponse,
    CopilotRequest,
    CopilotResponse,
    ExplainFindingRequest,
    ExplainAttackPathRequest,
    ExplainAlertRequest,
)
from app.services.ai.context_builder import SecurityContextBuilder
from app.services.ai.provider import get_ai_provider
from app.services.ai.base import (
    CopilotAIResponse,
    AIProviderError,
    AIAuthenticationError,
    AITimeoutError,
    AIRateLimitError,
    AIConfigurationError,
    AIResponseValidationError,
    AIUnavailableError,
)
from app.services.findings.finding_service import finding_service
from app.cache import cache
from app.security.dependencies import require_analyst
from app.security.models import AuthenticatedUser
from app.security.rate_limiter import rate_limit
from app.services.audit.audit_service import audit_service
from app.metrics import copilot_requests_total, copilot_latency_seconds
from app.services.scanner.current_snapshot import (
    get_current_alerts,
    get_current_resources,
    get_current_attack_paths,
    get_current_correlated_risks,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
)
from app.services.aws.cloudtrail_service import _redact_cloudtrail_payload
from app.services.scanner.snapshot_store import snapshot_store
from app.persistence.repository import get_snapshot_id_at_or_before

logger = logging.getLogger("backend")
router = APIRouter(tags=["Copilot"], dependencies=[Depends(require_analyst), Depends(rate_limit("copilot"))])
context_builder = SecurityContextBuilder()
MAX_PROMPT_CHARS = 10000


def _format_code_block(ai_resp: CopilotAIResponse) -> Optional[str]:
    """Format technical recommendations or evidence references into a code block."""
    lines = []
    if ai_resp.recommendations:
        lines.append("# Recommended Remediations:")
        for r in ai_resp.recommendations:
            lines.append(f"- {r}")
    if ai_resp.evidence:
        if lines:
            lines.append("")
        lines.append("# Verified Technical Evidence:")
        for e in ai_resp.evidence:
            lines.append(f"- {e}")
    return "\n".join(lines) if lines else None


def _build_no_scan_response() -> CopilotResponse:
    """Return explicit, honest state when no security scan has completed."""
    return CopilotResponse(
        sender="ai",
        text="CloudScope does not have a completed security scan yet, so I cannot provide an evidence-based security analysis.",
        suggestions=["Run a security scan first."],
        type="analysis",
        summary="No completed security scan available.",
        analysis="CloudScope requires at least one completed security scan to analyze IAM topology, effective access, attack paths, and cloud resources.",
        severity="UNKNOWN",
        riskScore=None,
        affectedEntities=[],
        evidence=[],
        recommendations=["Initiate a CloudScope security scan to discover and analyze cloud assets."],
        limitations=["Analysis cannot proceed without scan evidence."],
        provider=settings.AI_PROVIDER,
        model=settings.GEMINI_MODEL,
    )


def _map_to_copilot_response(ai_resp: CopilotAIResponse) -> CopilotResponse:
    """Map internal CopilotAIResponse to API CopilotResponse schema."""
    return CopilotResponse(
        sender="ai",
        text=ai_resp.analysis or ai_resp.summary,
        suggestions=ai_resp.suggested_questions or [],
        type="analysis",
        codeBlock=_format_code_block(ai_resp),
        summary=ai_resp.summary,
        analysis=ai_resp.analysis,
        severity=ai_resp.severity,
        riskScore=ai_resp.risk_score,
        affectedEntities=ai_resp.affected_entities or [],
        evidence=ai_resp.evidence or [],
        recommendations=ai_resp.recommendations or [],
        limitations=ai_resp.limitations or [],
        provider=settings.AI_PROVIDER,
        model=settings.GEMINI_MODEL,
    )


def _handle_ai_exception(e: Exception) -> None:
    """Map AI provider exceptions to standard HTTP response codes."""
    if isinstance(e, AIAuthenticationError):
        logger.error("AI Authentication Error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.user_friendly_message
        )
    elif isinstance(e, AITimeoutError):
        logger.warning("AI Timeout: %s", e)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.user_friendly_message
        )
    elif isinstance(e, AIRateLimitError):
        logger.warning("AI Rate Limit: %s", e)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=e.user_friendly_message
        )
    elif isinstance(e, (AIConfigurationError, AIUnavailableError, AIResponseValidationError, AIProviderError)):
        logger.error("AI Provider Error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.user_friendly_message
        )
    else:
        logger.error("Unexpected Copilot error: %s", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while generating the security analysis."
        )


@router.post("/copilot", response_model=APIResponse[CopilotResponse])
async def get_copilot_response(
    req: CopilotRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_analyst)
):
    """
    Generate an evidence-grounded AI response for general security questions,
    entity investigations, or simulation results.
    """
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Prompt cannot be empty."
        )

    if len(prompt) > MAX_PROMPT_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Prompt exceeds maximum allowed length of {MAX_PROMPT_CHARS} characters."
        )

    # 1. Verify scan state — never invent posture if no scan has run
    if not context_builder.has_completed_scan():
        logger.info("Copilot query received but no completed scan exists")
        return APIResponse(
            success=True,
            message="No completed scan available",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=_build_no_scan_response()
        )

    # 2. Build structured security context
    context = context_builder.build_context(
        prompt=prompt,
        context_type=req.context_type,
        entity_id=req.entity_id,
        entity_type=req.entity_type,
        attack_path_id=req.attack_path_id,
        finding_id=req.finding_id,
        simulation_context=req.simulation_context,
    )

    # 3. Call AI provider with metrics and telemetry
    start_time = time.perf_counter()
    try:
        provider = get_ai_provider()
        ai_resp = await provider.generate_security_response(prompt=prompt, security_context=context)
        latency = time.perf_counter() - start_time
        copilot_latency_seconds.observe(latency)
        copilot_requests_total.labels(status="success").inc()

        data = _map_to_copilot_response(ai_resp)

        client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else None)
        audit_service.log(
            action="COPILOT_REQUESTED",
            actor_id=current_user.subject,
            actor_role=current_user.highest_role.value if current_user.highest_role else "UNKNOWN",
            resource_type="copilot",
            resource_id=req.context_type or "general",
            result="SUCCESS",
            ip_address=client_ip,
            metadata={"latency_seconds": round(latency, 2), "model": settings.GEMINI_MODEL}
        )

        return APIResponse(
            success=True,
            message="AI Copilot analysis generated successfully",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data
        )
    except Exception as e:
        copilot_requests_total.labels(status="error").inc()
        _handle_ai_exception(e)


@router.post("/copilot/explain-finding", response_model=APIResponse[CopilotResponse])
async def explain_finding(req: ExplainFindingRequest):
    """
    Explain a specific authoritative security finding using its verified evidence.
    """
    finding_id = (req.finding_id or "").strip()
    if not finding_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="finding_id is required."
        )

    finding = finding_service.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found."
        )

    prompt = (
        f"Explain security finding '{finding.title}' (ID: {finding.id}, Severity: {finding.severity}, Risk Score: {finding.riskScore}). "
        f"Affected Principal/Resource: {finding.principal or finding.resource}. "
        "Detail why this was flagged, examine the technical evidence, and provide least-privilege remediation advice."
    )

    context = context_builder.build_context(
        prompt=prompt,
        context_type="finding",
        finding_id=finding_id,
        supplementary_metadata=finding.model_dump(by_alias=True)
    )

    try:
        provider = get_ai_provider()
        ai_resp = await provider.generate_security_response(prompt=prompt, security_context=context)
        data = _map_to_copilot_response(ai_resp)

        return APIResponse(
            success=True,
            message=f"Explanation for finding '{finding_id}' generated successfully",
            timestamp=utc_now_iso(),
            data=data
        )
    except Exception as e:
        _handle_ai_exception(e)


@router.post("/copilot/explain-attack-path", response_model=APIResponse[CopilotResponse])
async def explain_attack_path(req: ExplainAttackPathRequest):
    """
    Explain a specific lateral movement or privilege escalation attack path.
    """
    attack_path_id = (req.attack_path_id or "").strip()
    if not attack_path_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="attack_path_id is required."
        )

    # Fetch path from authoritative cache
    all_paths = cache.get("v1:attack-paths") or []
    target_path = next((p for p in all_paths if isinstance(p, dict) and p.get("id") == attack_path_id), None)

    if not target_path and not req.supplementary_metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path '{attack_path_id}' not found."
        )

    effective_path = target_path or req.supplementary_metadata or {}
    source = effective_path.get("source", "Identity")
    target = effective_path.get("target", "Cloud Resource")
    target_type = effective_path.get("target_type", "Resource")
    severity = effective_path.get("severity", "HIGH")
    risk_score = effective_path.get("risk_score")
    blast_radius = effective_path.get("blast_radius", "")
    relationships = " → ".join(effective_path.get("ordered_relationships", [])) or "direct execution"

    prompt = (
        f"Explain the discovered lateral attack path '{attack_path_id}' from source '{source}' to target '{target}' ({target_type}). "
        f"Permission chain: {relationships}. Severity: {severity}, Risk Score: {risk_score}, Blast Radius: {blast_radius}. "
        "Explain step-by-step how each authorization hop functions, the potential impact on reachable assets, "
        "and concrete IAM policy remediations to sever this attack chain."
    )

    context = context_builder.build_context(
        prompt=prompt,
        context_type="attack_path",
        attack_path_id=attack_path_id,
        supplementary_metadata=effective_path
    )

    try:
        provider = get_ai_provider()
        ai_resp = await provider.generate_security_response(prompt=prompt, security_context=context)
        data = _map_to_copilot_response(ai_resp)

        return APIResponse(
            success=True,
            message=f"Explanation for attack path '{attack_path_id}' generated successfully",
            timestamp=utc_now_iso(),
            data=data
        )
    except Exception as e:
        _handle_ai_exception(e)


@router.post("/copilot/explain-alert", response_model=APIResponse[CopilotResponse])
async def explain_security_alert(
    req: ExplainAlertRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_analyst),
):
    """Explain a recent CloudTrail alert against current inventory and path evidence."""
    alert_id = (req.alert_id or "").strip()
    if not alert_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="alert_id is required.")

    alert = next((a for a in get_current_alerts() if isinstance(a, dict) and a.get("id") == alert_id), None)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This alert is no longer in the latest scan. Refresh the alert list and try again.")

    try:
        raw_event = alert.get("details") or "{}"
        event = json.loads(raw_event) if isinstance(raw_event, str) else raw_event
        event = _redact_cloudtrail_payload(event if isinstance(event, dict) else {})
    except (TypeError, ValueError):
        event = {}

    identity = event.get("userIdentity") or {}
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    actor = identity.get("arn") or issuer.get("arn") or identity.get("principalId") or alert.get("actor") or "Unknown actor"
    event_name = event.get("eventName") or "Unknown AWS action"
    resource_entries = event.get("resources") or []
    resource_arns = [item.get("ARN") or item.get("arn") for item in resource_entries if isinstance(item, dict)]
    resource_arns = [arn for arn in resource_arns if arn]

    inventory = get_current_resources()
    event_time = event.get("eventTime") or alert.get("timestamp") or ""
    baseline_id = get_snapshot_id_at_or_before(str(event_time))
    baseline = snapshot_store.get_snapshot(baseline_id) if baseline_id else None
    baseline_resources = list(baseline.resources) if baseline else []

    def matches_event_resource(item):
        return isinstance(item, dict) and any(
            arn.lower() in str(item.get("arn", "")).lower()
            or str(item.get("arn", "")).lower() in arn.lower()
            for arn in resource_arns
        )

    current_affected = [item for item in inventory if matches_event_resource(item)][:30]
    before_after = []
    for current in current_affected:
        arn = str(current.get("arn", "")).lower()
        before = next((item for item in baseline_resources if isinstance(item, dict) and str(item.get("arn", "")).lower() == arn), None)
        before_after.append({
            "resource": {key: current.get(key) for key in ("id", "name", "type", "arn", "region") if current.get(key) is not None},
            "before_event": {key: before.get(key) for key in ("status", "state", "riskScore", "risk_score", "details") if before and before.get(key) is not None} if before else None,
            "latest_scan_state": {key: current.get(key) for key in ("status", "state", "riskScore", "risk_score", "details") if current.get(key) is not None},
            "baseline_snapshot_id": baseline_id,
        })

    match_terms = [str(actor).lower(), *(str(arn).lower() for arn in resource_arns)]
    paths = []
    for path in get_current_attack_paths():
        if not isinstance(path, dict):
            continue
        path_text = json.dumps(path, default=str).lower()
        if any(term and term in path_text for term in match_terms):
            paths.append({key: path.get(key) for key in (
                "id", "name", "source", "target", "target_type", "severity", "risk_score",
                "riskScore", "blast_radius", "blastRadius", "description", "ordered_relationships",
            ) if path.get(key) is not None})
        if len(paths) >= 10:
            break

    correlated = [
        item for item in get_current_correlated_risks()
        if isinstance(item, dict) and (item.get("id") == alert_id or item.get("event_name") == event_name)
    ][:10]
    evidence = {
        "alert": {
            "id": alert_id,
            "timestamp": alert.get("timestamp"),
            "severity": alert.get("severity"),
            "description": alert.get("description"),
            "event_name": event_name,
            "event_source": event.get("eventSource"),
            "region": event.get("awsRegion"),
            "actor": actor,
            "source_ip": event.get("sourceIPAddress"),
            "read_only": event.get("readOnly"),
            "error_code": event.get("errorCode"),
            "error_message": event.get("errorMessage"),
            "request_parameters": event.get("requestParameters"),
            "response_elements": event.get("responseElements"),
            "resources": resource_entries,
        },
        "resource_before_after_comparison": before_after,
        "current_inventory_match_count": len(current_affected),
        "prior_snapshot_id": baseline_id,
        "prior_snapshot_published_at": baseline.published_at if baseline else None,
        "latest_snapshot_id": get_current_snapshot_id(),
        "latest_snapshot_published_at": get_current_snapshot_published_at(),
        "related_static_attack_paths": paths,
        "correlated_observed_activity": correlated,
    }
    prompt = (
        f"Explain CloudTrail alert {alert_id} for AWS action {event_name}. Give an administrator-ready incident brief: "
        "what happened and when; the actor and whether AWS recorded success or failure; what the request asked AWS to do; "
        "the before and after state by comparing the latest snapshot published before the event with the latest inventory snapshot. "
        "Only call a state 'after' if the latest snapshot timestamp is later than the event timestamp; otherwise say after-state evidence is not available. "
        "Include the snapshot timestamps and directly affected resources; "
        "any related static attack paths or correlated observed activity; possible confidentiality, integrity, and availability impact; "
        "recommended validation steps and prioritized containment/remediation. Clearly separate confirmed facts from inferred impact. "
        "CloudTrail does not necessarily contain the prior configuration or prove downstream access, so state those limits explicitly. "
        "Do not claim that a static path was exercised unless the supplied correlated activity proves it."
    )
    context = context_builder.build_context(
        prompt=prompt,
        context_type="alert",
        entity_id=str(actor),
        entity_type="principal",
        simulation_context=evidence,
    )

    started = time.perf_counter()
    try:
        ai_resp = await get_ai_provider().generate_security_response(prompt=prompt, security_context=context)
        latency = time.perf_counter() - started
        copilot_latency_seconds.observe(latency)
        copilot_requests_total.labels(status="success").inc()
        client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else None)
        audit_service.log(
            action="COPILOT_ALERT_EXPLAINED",
            actor_id=current_user.subject,
            actor_role=current_user.highest_role.value if current_user.highest_role else "UNKNOWN",
            resource_type="security_alert",
            resource_id=alert_id,
            result="SUCCESS",
            ip_address=client_ip,
            metadata={"latency_seconds": round(latency, 2), "model": settings.GEMINI_MODEL},
        )
        return APIResponse(
            success=True,
            message="AI alert analysis generated successfully",
            timestamp=utc_now_iso(),
            data=_map_to_copilot_response(ai_resp),
        )
    except Exception as e:
        copilot_requests_total.labels(status="error").inc()
        _handle_ai_exception(e)
