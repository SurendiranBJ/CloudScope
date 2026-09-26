"""
CloudScope AI Security Copilot Router.

Provides evidence-grounded AI security explanations, investigation assistance,
and remediation guidance powered by Gemini.
No hardcoded mock responses; all insights are grounded in authoritative CloudScope security data.
"""

import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, status

from app.config import settings
from app.schemas import (
    APIResponse,
    CopilotRequest,
    CopilotResponse,
    ExplainFindingRequest,
    ExplainAttackPathRequest,
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

logger = logging.getLogger("backend")
router = APIRouter(tags=["Copilot"])
context_builder = SecurityContextBuilder()


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


@router.post("/copilot", response_model=APIResponse[CopilotResponse])
async def get_copilot_response(req: CopilotRequest):
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

    # 1. Verify scan state — never invent posture if no scan has run
    if not context_builder.has_completed_scan():
        logger.info("Copilot query received but no completed scan exists")
        return APIResponse(
            success=True,
            message="No completed scan available",
            timestamp=datetime.utcnow().isoformat() + "Z",
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

    # 3. Call AI provider
    try:
        provider = get_ai_provider()
        ai_resp = await provider.generate_security_response(prompt=prompt, security_context=context)
        data = _map_to_copilot_response(ai_resp)

        return APIResponse(
            success=True,
            message="AI Copilot analysis generated successfully",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=data
        )
    except AIAuthenticationError as e:
        logger.error("AI Authentication Error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.user_friendly_message
        )
    except AITimeoutError as e:
        logger.warning("AI Timeout: %s", e)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.user_friendly_message
        )
    except AIRateLimitError as e:
        logger.warning("AI Rate Limit: %s", e)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=e.user_friendly_message
        )
    except (AIConfigurationError, AIUnavailableError, AIResponseValidationError, AIProviderError) as e:
        logger.error("AI Provider Error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.user_friendly_message
        )
    except Exception as e:
        logger.error("Unexpected Copilot error: %s", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while generating the security analysis."
        )


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
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=data
        )
    except AIProviderError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.user_friendly_message
        )


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
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=data
        )
    except AIProviderError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.user_friendly_message
        )
