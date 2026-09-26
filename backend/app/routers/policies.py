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

from app.schemas import APIResponse, PolicyCatalogEntry, PaginatedPolicyCatalog
from app.cache import cache
from app.services.attack.policy_evaluator import evaluate_policy_document_risk

logger = logging.getLogger("scanner")

router = APIRouter(tags=["Policies"])


@router.get("/policies", response_model=APIResponse[PaginatedPolicyCatalog])
def get_policy_catalog(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(100, ge=1, le=1000, description="Items per page"),
    type_filter: Optional[str] = Query(None, description="Filter by type: aws-managed | customer-managed | inline"),
    search: Optional[str] = Query(None, description="Search by policy name or ARN"),
    limit: Optional[int] = Query(None, ge=1, le=2000, description="Legacy limit override"),
):
    """Return the paginated policy catalog from cache (Level 1 — metadata without documents).

    The search and type filters operate across the COMPLETE cached catalog.
    Documents are never loaded or fetched during catalog listing to ensure high performance.
    """
    from app.services.scanner.scan_manager import scan_manager

    # Ensure scan data availability if cache is empty
    scan_policies = cache.get("v1:policies")
    catalog_cached = cache.get("v1:policy_catalog")

    if scan_policies is None and catalog_cached is None:
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        scan_policies = cache.get("v1:policies")
        catalog_cached = cache.get("v1:policy_catalog")

    # Authoritative primary source is v1:policies
    scan_policies = scan_policies or []
    catalog = list(catalog_cached or [])

    # Pre-calculate entity attachments from authoritative cache/inventory
    users = cache.get("v1:users") or getattr(scan_manager.inventory, "users", []) or []
    roles = cache.get("v1:roles") or getattr(scan_manager.inventory, "roles", []) or []
    groups = cache.get("v1:groups") or getattr(scan_manager.inventory, "groups", []) or []

    # Map policy identifier (name and ARN) to attachment counts
    attachment_counts: dict = {}
    for u in users:
        u_pols = set(u.get("policies", []) + u.get("attachedPolicies", []))
        for p in u_pols:
            clean = p.replace("[inline] ", "")
            attachment_counts[clean] = attachment_counts.get(clean, 0) + 1
        for p_arn in u.get("attachedPolicyArns", {}).values():
            attachment_counts[p_arn] = attachment_counts.get(p_arn, 0) + 1

    for r in roles:
        r_pols = set(r.get("attachedPolicies", []) + r.get("policies", []))
        for p in r_pols:
            clean = p.replace("[inline] ", "")
            attachment_counts[clean] = attachment_counts.get(clean, 0) + 1
        for p_arn in r.get("attachedPolicyArns", {}).values():
            attachment_counts[p_arn] = attachment_counts.get(p_arn, 0) + 1

    for g in groups:
        g_pols = set(g.get("attachedPolicies", []) + g.get("policies", []))
        for p in g_pols:
            clean = p.replace("[inline] ", "")
            attachment_counts[clean] = attachment_counts.get(clean, 0) + 1
        for p_arn in g.get("attachedPolicyArns", {}).values():
            attachment_counts[p_arn] = attachment_counts.get(p_arn, 0) + 1

    # Merge authoritative scan_policies into catalog
    catalog_arns = {p.get("arn", "") for p in catalog if p.get("arn")}
    catalog_names = {p.get("name", "") for p in catalog if p.get("name")}

    for sp in scan_policies:
        sp_arn = sp.get("arn", "")
        sp_name = sp.get("name", "")
        if (sp_arn and sp_arn in catalog_arns) or (sp_name and sp_name in catalog_names):
            continue

        raw_type = sp.get("type", "customer-managed")
        if raw_type in ("custom", "customer-managed"):
            norm_type = "customer-managed"
            is_attachable = True
        elif raw_type in ("aws-managed", "managed") or "::aws:policy/" in sp_arn:
            norm_type = "aws-managed"
            is_attachable = True
        elif raw_type == "inline" or sp_name.startswith("[inline] "):
            norm_type = "inline"
            is_attachable = False
        else:
            norm_type = raw_type
            is_attachable = True

        clean_name = sp_name.replace("[inline] ", "")
        att_count = max(attachment_counts.get(clean_name, 0), attachment_counts.get(sp_arn, 0))

        catalog.append({
            "name": sp_name,
            "arn": sp_arn,
            "type": norm_type,
            "attachmentCount": att_count,
            "isAttachable": is_attachable,
            "description": sp.get("description", ""),
            "document": sp.get("document"),
            "riskScore": sp.get("riskScore", 0),
            "severity": _score_to_severity(sp.get("riskScore", 0)),
            "findings": [],
        })

    # Normalize existing catalog entries
    for entry in catalog:
        raw_type = entry.get("type", "customer-managed")
        if raw_type in ("custom", "customer-managed"):
            entry["type"] = "customer-managed"
            entry["isAttachable"] = True
        elif raw_type in ("aws-managed", "managed") or "::aws:policy/" in entry.get("arn", ""):
            entry["type"] = "aws-managed"
            entry["isAttachable"] = True
        elif raw_type == "inline" or entry.get("name", "").startswith("[inline] "):
            entry["type"] = "inline"
            entry["isAttachable"] = False

        c_name = entry.get("name", "").replace("[inline] ", "")
        if not entry.get("attachmentCount"):
            entry["attachmentCount"] = max(
                attachment_counts.get(c_name, 0),
                attachment_counts.get(entry.get("arn", ""), 0)
            )

    # Apply type filtering across the complete catalog
    if type_filter:
        tf = type_filter.strip().lower()
        if tf in ("customer-managed", "custom"):
            target_types = {"customer-managed", "custom"}
        elif tf in ("aws-managed", "managed"):
            target_types = {"aws-managed", "managed"}
        elif tf == "inline":
            target_types = {"inline"}
        else:
            target_types = {tf}
        catalog = [p for p in catalog if p.get("type", "").lower() in target_types]

    # Apply search across the complete catalog
    if search:
        q = search.strip().lower()
        catalog = [
            p for p in catalog
            if q in p.get("name", "").lower() or q in p.get("arn", "").lower()
        ]

    total = len(catalog)
    effective_page_size = limit if limit is not None else page_size
    total_pages = max(1, (total + effective_page_size - 1) // effective_page_size) if total > 0 else 1

    start_idx = (page - 1) * effective_page_size
    end_idx = start_idx + effective_page_size
    page_items = catalog[start_idx:end_idx]

    # Return risk-scored entries (use cached scores if present)
    # Never fetch documents from AWS in list view
    result = []
    for p in page_items:
        entry = dict(p)
        # Compute risk ONLY if document already in entry or cached
        if entry.get("riskScore", 0) == 0 and entry.get("document"):
            risk = _score_policy(entry.get("document", "{}"))
            entry["riskScore"] = risk["score"]
            entry["severity"] = risk["severity"]
            entry["findings"] = risk["findings"]
        elif entry.get("riskScore", 0) == 0:
            entry["severity"] = "unknown"
        else:
            entry["severity"] = _score_to_severity(entry.get("riskScore", 0))

        # Ensure required frontend fields exist with valid defaults
        entry.setdefault("attachmentCount", 0)
        entry.setdefault("isAttachable", entry.get("type") != "inline")
        entry.setdefault("findings", [])

        # Omit document in list view to enforce Level 1 metadata-only
        entry.pop("document", None)
        result.append(entry)

    data = {
        "items": result,
        "page": page,
        "page_size": effective_page_size,
        "total": total,
        "total_pages": total_pages,
    }

    return APIResponse(
        success=True,
        message=f"Policy catalog: {len(result)} of {total} policies returned (page {page}/{total_pages})",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data,
    )


@router.get("/policies/explain", response_model=APIResponse[dict])
def explain_access(
    principal: str = Query(..., description="Principal username or role name"),
    resource: str = Query(..., description="Resource ID, name, or ARN"),
    action: Optional[str] = Query(None, description="Optional IAM action to evaluate"),
):
    """Explain WHY a principal has access to a target resource based on actual policy evidence.

    Uses real scanned policy documents and effective-access calculations without faking values.
    """
    from app.services.scanner.scan_manager import scan_manager
    from app.services.simulation.effective_access import explain_principal_access

    inv = scan_manager.inventory
    policies = cache.get("v1:policies") or []
    policy_doc_map = {}
    for p in policies:
        doc = p.get("document")
        if doc and doc != "{}":
            policy_doc_map[p["name"]] = doc

    explanation = explain_principal_access(
        principal_name=principal,
        target_resource_id_or_arn=resource,
        inventory=inv,
        policy_doc_map=policy_doc_map,
        target_action=action,
    )

    return APIResponse(
        success=True,
        message=f"Access explanation for '{principal}' targeting '{resource}'",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=explanation,
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
    from app.services.scanner.scan_manager import scan_manager
    inv_policies = getattr(scan_manager.inventory, "policies", []) or []
    all_policies = catalog + scan_policies + inv_policies

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

    # Find attachment locations across users, roles, and groups
    users = cache.get("v1:users") or getattr(scan_manager.inventory, "users", []) or []
    roles = cache.get("v1:roles") or getattr(scan_manager.inventory, "roles", []) or []
    groups = cache.get("v1:groups") or getattr(scan_manager.inventory, "groups", []) or []
    pol_name = entry.get("name", "")
    pol_arn = entry.get("arn", "")
    clean_pol_name = pol_name.replace("[inline] ", "")

    attached_to: List[dict] = []
    seen_attachments = set()

    def _matches_policy(policy_list: list, policy_arn_map: dict) -> bool:
        for p in policy_list:
            if p == pol_name or p == clean_pol_name or p == f"[inline] {clean_pol_name}":
                return True
            if p.replace("[inline] ", "") == clean_pol_name:
                return True
        if pol_arn:
            if pol_arn in policy_arn_map.values():
                return True
            if policy_arn_map.get(pol_name) == pol_arn or policy_arn_map.get(clean_pol_name) == pol_arn:
                return True
        return False

    for u in users:
        u_pols = u.get("policies", []) + u.get("attachedPolicies", [])
        u_arns = u.get("attachedPolicyArns", {})
        if _matches_policy(u_pols, u_arns):
            key = ("User", u.get("name", ""))
            if key not in seen_attachments:
                seen_attachments.add(key)
                attached_to.append({"type": "User", "name": u["name"], "arn": u.get("arn", "")})

    for r in roles:
        r_pols = r.get("attachedPolicies", []) + r.get("policies", [])
        r_arns = r.get("attachedPolicyArns", {})
        if _matches_policy(r_pols, r_arns):
            key = ("Role", r.get("name", ""))
            if key not in seen_attachments:
                seen_attachments.add(key)
                attached_to.append({"type": "Role", "name": r["name"], "arn": r.get("arn", "")})

    for g in groups:
        g_pols = g.get("attachedPolicies", []) + g.get("policies", [])
        g_arns = g.get("attachedPolicyArns", {})
        if _matches_policy(g_pols, g_arns):
            key = ("Group", g.get("name", ""))
            if key not in seen_attachments:
                seen_attachments.add(key)
                attached_to.append({"type": "Group", "name": g["name"], "arn": g.get("arn", "")})

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
