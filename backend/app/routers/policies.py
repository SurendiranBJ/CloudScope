"""
CloudScope Policies Router.

GET  /api/v1/policies           — Full browsable policy catalog (metadata + risk)
GET  /api/v1/policies/{policy_id} — Rich single policy detail with document + risk analysis

Two-level design (matching iam_service):
  Level 1: List endpoint returns metadata from cache (no documents by default).
  Level 2: Detail endpoint fetches/returns full policy document + risk analysis.
"""

import json
import logging
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime

from app.schemas import APIResponse, PolicyCatalogEntry
from app.cache import cache
from app.services.attack.policy_evaluator import evaluate_policy_document_risk

logger = logging.getLogger("scanner")

router = APIRouter(tags=["Policies"])


@router.get("/policies", response_model=APIResponse[List[dict]])
def get_policy_catalog(
    type_filter: Optional[str] = Query(None, description="Filter by type: aws-managed | customer-managed | inline"),
    search: Optional[str] = Query(None, description="Search by policy name"),
    limit: int = Query(500, ge=1, le=2000),
):
    """Return the full policy catalog from cache (Level 1 — metadata without documents).

    Documents are not included unless already cached (e.g., policies that have
    been opened in the detail view or were fetched during a scan).
    """
    catalog = cache.get("v1:policy_catalog") or []

    # Also include policies discovered during scan (from v1:policies)
    scan_policies = cache.get("v1:policies") or []
    catalog_arns = {p.get("arn", "") for p in catalog}
    for sp in scan_policies:
        if sp.get("arn", "") not in catalog_arns:
            catalog.append({
                "name": sp.get("name", ""),
                "arn": sp.get("arn", ""),
                "type": sp.get("type", "customer-managed"),
                "attachmentCount": 0,
                "isAttachable": True,
                "description": "",
                "document": sp.get("document"),
                "riskScore": sp.get("riskScore", 0),
                "severity": _score_to_severity(sp.get("riskScore", 0)),
                "findings": [],
            })

    # Apply filters
    if type_filter:
        catalog = [p for p in catalog if p.get("type", "").lower() == type_filter.lower()]
    if search:
        q = search.lower()
        catalog = [p for p in catalog if q in p.get("name", "").lower()]

    # Return risk-scored entries (use cached scores if present)
    result = []
    for p in catalog[:limit]:
        entry = dict(p)
        # Compute risk if document available and score not yet set
        if entry.get("riskScore", 0) == 0 and entry.get("document"):
            risk = _score_policy(entry.get("document", "{}"))
            entry["riskScore"] = risk["score"]
            entry["severity"] = risk["severity"]
            entry["findings"] = risk["findings"]
        elif entry.get("riskScore", 0) == 0:
            entry["severity"] = "unknown"
        else:
            entry["severity"] = _score_to_severity(entry.get("riskScore", 0))
        # Never return None document in list view — omit it
        entry.pop("document", None)
        result.append(entry)

    return APIResponse(
        success=True,
        message=f"Policy catalog: {len(result)} policies returned",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=result,
    )


@router.get("/policies/{policy_id}", response_model=APIResponse[dict])
def get_policy_detail(policy_id: str):
    """Return rich policy details including document and risk analysis (Level 2).

    policy_id can be:
      - policy name (e.g. AdministratorAccess)
      - URL-encoded policy ARN

    If the document is not cached, attempts to fetch from AWS.
    """
    # Search catalog cache first
    catalog = cache.get("v1:policy_catalog") or []
    scan_policies = cache.get("v1:policies") or []
    all_policies = catalog + scan_policies

    entry = _find_policy(all_policies, policy_id)

    if not entry:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found in catalog")

    entry = dict(entry)

    # Level 2: Fetch document if not already available
    doc = entry.get("document")
    if not doc or doc == "{}":
        arn = entry.get("arn", "")
        if arn:
            # Check document cache
            cached_doc = cache.get(f"v1:policy_doc:{arn}")
            if cached_doc:
                doc = cached_doc
            else:
                try:
                    from app.services.aws.iam_service import fetch_policy_document_by_arn
                    fetched = fetch_policy_document_by_arn(arn)
                    if fetched:
                        doc = fetched["document"]
                        cache.set(f"v1:policy_doc:{arn}", doc)
                    else:
                        doc = None
                except Exception as e:
                    logger.warning(f"Could not fetch policy document for {arn}: {e}")
                    doc = None
    
    entry["document"] = doc

    # Run risk analysis if document available
    if doc:
        risk = _score_policy(doc)
        entry["riskScore"] = risk["score"]
        entry["severity"] = risk["severity"]
        entry["findings"] = risk["findings"]
        # Parse document for display
        try:
            entry["documentParsed"] = json.loads(doc)
        except Exception:
            entry["documentParsed"] = None
    else:
        entry["riskScore"] = entry.get("riskScore", 0)
        entry["severity"] = _score_to_severity(entry.get("riskScore", 0))
        entry["findings"] = []
        entry["documentParsed"] = None
        entry["documentUnavailable"] = True

    # Find attachment locations
    users = cache.get("v1:users") or []
    roles = cache.get("v1:roles") or []
    pol_name = entry.get("name", "")
    attached_to: List[dict] = []
    for u in users:
        if pol_name in u.get("policies", []):
            attached_to.append({"type": "User", "name": u["name"], "arn": u.get("arn", "")})
    for r in roles:
        if pol_name in r.get("attachedPolicies", []):
            attached_to.append({"type": "Role", "name": r["name"], "arn": r.get("arn", "")})
    entry["attachedTo"] = attached_to

    return APIResponse(
        success=True,
        message=f"Policy details for '{pol_name}'",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=entry,
    )


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _find_policy(policies: List[dict], policy_id: str) -> Optional[dict]:
    """Search by name or ARN."""
    for p in policies:
        if p.get("name") == policy_id or p.get("arn") == policy_id:
            return p
    # Try partial ARN match (URL-decoded)
    import urllib.parse
    decoded = urllib.parse.unquote(policy_id)
    for p in policies:
        if p.get("arn") == decoded or p.get("name") == decoded:
            return p
    return None


def _score_policy(doc_str: str) -> dict:
    """Return risk score, severity and findings for a policy document."""
    try:
        result = evaluate_policy_document_risk([doc_str])
        score = min(100, sum(f.get("points", 0) for f in result.get("factors", [])))
        severity = _score_to_severity(score)
        findings = [{"code": f["code"], "points": f["points"], "reason": f["reason"]} for f in result.get("factors", [])]
        return {"score": score, "severity": severity, "findings": findings}
    except Exception as e:
        logger.debug(f"Policy risk scoring failed: {e}")
        return {"score": 0, "severity": "unknown", "findings": []}


def _score_to_severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"
