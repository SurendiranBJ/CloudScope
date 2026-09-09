"""
CloudScope Simulation Analyzer.

Runs the exact same security analysis pipeline (risk engine, attack paths,
blast radius, effective access) against the DESIRED inventory and compares
results to the CURRENT state.

Uses existing engines — no duplicated logic, no contradictory definitions.
"""

import logging
import networkx as nx
from typing import Any, Dict, List, Optional, Set, Tuple

from app.services.graph.graph_loader import build_local_graph
from app.services.attack.path_engine import find_attack_paths
from app.services.attack.risk_engine import (
    get_user_risk_assessment,
    get_role_risk_assessment,
    compute_global_security_score,
)
from app.services.attack.blast_radius import calculate_blast_radius
from app.services.attack.policy_evaluator import evaluate_policy_document_risk
from app.services.risk.risk_constants import get_severity_label
from app.services.simulation.diff_engine import (
    compute_graph_diff,
    compare_attack_paths,
    compare_reachable_resources,
)
from app.services.simulation.effective_access import (
    compute_effective_access,
    compute_reachable_resources,
)

logger = logging.getLogger("scanner")


def build_desired_analysis(
    desired_inventory: Any,
    desired_policy_doc_map: Dict[str, str],
    current_inventory: Any,
    current_policy_doc_map: Dict[str, str],
    current_attack_paths: List[Dict[str, Any]],
    current_global_posture: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the full analysis pipeline against the desired state and compare to current.

    Args:
        desired_inventory: AWSInventory derived from simulation changes.
        desired_policy_doc_map: Policy document map for desired inventory.
        current_inventory: Real AWS inventory (from cache).
        current_policy_doc_map: Policy document map for current inventory.
        current_attack_paths: Real current attack paths (from cache).
        current_global_posture: Current global security score (from cache).

    Returns:
        Full analysis result dict containing:
            graph_diff, risk_comparison, attack_path_comparison,
            blast_radius_comparison, new_reachable_resources,
            removed_reachable_resources, summary
    """
    logger.info("[SIMULATION] Building desired-state graph and analysis")

    # ── 1. Score desired identities using the same risk engine ────────────────
    for u in desired_inventory.users:
        eval_res = get_user_risk_assessment(u, desired_policy_doc_map)
        u["riskScore"] = eval_res["score"]
        u["riskAssessment"] = eval_res

    for r in desired_inventory.roles:
        eval_res = get_role_risk_assessment(r, desired_policy_doc_map)
        r["riskScore"] = eval_res["score"]
        r["riskAssessment"] = eval_res

    # ── 2. Build desired NetworkX graph using existing local graph builder ─────
    G_desired = build_local_graph(desired_inventory)

    # ── 3. Build current NetworkX graph ───────────────────────────────────────
    G_current = build_local_graph(current_inventory)

    # ── 4. Graph diff ─────────────────────────────────────────────────────────
    graph_diff = compute_graph_diff(G_current, G_desired)

    # ── 5. Attack path comparison ─────────────────────────────────────────────
    desired_attack_paths = find_attack_paths(G_desired)
    attack_path_comparison = compare_attack_paths(current_attack_paths, desired_attack_paths)

    # ── 6. Global risk comparison ─────────────────────────────────────────────
    desired_global_posture = compute_global_security_score(
        desired_inventory,
        desired_attack_paths,
        desired_inventory.alerts,
    )
    desired_global_score = desired_global_posture["overall_score"]

    current_global_score = (
        current_global_posture.get("overall_score", 0)
        if current_global_posture
        else 0
    )

    risk_delta = desired_global_score - current_global_score
    top_reasons = _build_risk_reasons(
        attack_path_comparison,
        graph_diff,
        desired_global_posture,
        current_global_posture,
    )

    risk_comparison = {
        "current_score": current_global_score,
        "desired_score": desired_global_score,
        "delta": risk_delta,
        "current_severity": get_severity_label(current_global_score),
        "desired_severity": get_severity_label(desired_global_score),
        "top_reasons": top_reasons,
        "simulation_active": True,
    }

    # ── 7. Effective access / reachable resource comparison ───────────────────
    all_resources = _all_resources(current_inventory)
    all_desired_resources = _all_resources(desired_inventory)

    current_reach = compute_reachable_resources(
        current_inventory, current_policy_doc_map, all_resources
    )
    desired_reach = compute_reachable_resources(
        desired_inventory, desired_policy_doc_map, all_desired_resources
    )
    resource_diff = compare_reachable_resources(current_reach, desired_reach)

    # ── 8. Desired Cytoscape elements for frontend visualization ─────────────
    desired_elements = []
    if G_desired:
        for nid, attr in G_desired.nodes(data=True):
            desired_elements.append({
                "data": {
                    "id": nid,
                    "label": attr.get("label", nid),
                    "type": attr.get("type", "Resource"),
                    "riskScore": attr.get("riskScore", 0),
                    "arn": attr.get("arn", ""),
                    "description": attr.get("description", ""),
                }
            })
        for s, t, attr in G_desired.edges(data=True):
            desired_elements.append({
                "data": {
                    "id": f"e-{s}-{t}",
                    "source": s,
                    "target": t,
                    "label": attr.get("label", "UNKNOWN"),
                }
            })

    # ── 9. Blast radius (accurate unique identities and reachable resources) ──
    blast_comparison = _compute_blast_comparison(
        G_current,
        G_desired,
        current_inventory,
        desired_inventory,
        current_policy_doc_map,
        desired_policy_doc_map,
    )

    summary = _build_summary(attack_path_comparison, resource_diff, risk_comparison)

    return {
        "simulation_active": True,
        "graph_diff": graph_diff,
        "desired_elements": desired_elements,
        "risk_comparison": risk_comparison,
        "attack_path_comparison": attack_path_comparison,
        "blast_radius_comparison": blast_comparison,
        "new_reachable_resources": resource_diff["new_reachable"],
        "removed_reachable_resources": resource_diff["removed_reachable"],
        "desired_attack_paths": desired_attack_paths,
        "summary": summary,
    }


def build_policy_preview_analysis(
    proposed_change: Dict[str, Any],
    current_inventory: Any,
    current_policy_doc_map: Dict[str, str],
    current_attack_paths: List[Dict[str, Any]],
    current_global_posture: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Preview the security impact of a SINGLE proposed change WITHOUT persisting it.

    Args:
        proposed_change: dict with action, principal_type, principal_id, policy_arn
        current_inventory: current AWS inventory from cache
        current_policy_doc_map: current policy document map
        current_attack_paths: current attack paths from cache
        current_global_posture: current global security score from cache

    Returns:
        Preview analysis dict with risk_comparison, new_reachable_resources, etc.
    """
    from app.services.simulation.simulation_state import (
        SimulationStateManager,
        _apply_policy_change,
        _name_from_arn,
    )
    import copy

    logger.info(f"[SIMULATION PREVIEW] Analyzing proposed change: {proposed_change}")

    # Create a temporary single-change simulation manager
    temp_mgr = SimulationStateManager()

    action = proposed_change.get("action", "")
    ptype = proposed_change.get("principal_type", "")
    pid = proposed_change.get("principal_id", "")
    parn = proposed_change.get("policy_arn", "")

    if action == "ATTACH_POLICY":
        temp_mgr.attach_policy(ptype, pid, parn)
    elif action == "DETACH_POLICY":
        temp_mgr.detach_policy(ptype, pid, parn)
    else:
        return {"error": f"Unsupported action: {action}"}

    desired_inventory = temp_mgr.get_desired_inventory(current_inventory)

    # Ensure the proposed policy document is available
    desired_policy_doc_map = dict(current_policy_doc_map)
    if parn and _name_from_arn(parn) not in desired_policy_doc_map:
        # Try to fetch document for preview
        try:
            from app.services.aws.iam_service import fetch_policy_document_by_arn
            doc_result = fetch_policy_document_by_arn(parn)
            if doc_result:
                desired_policy_doc_map[doc_result["name"]] = doc_result["document"]
                # Also add to desired inventory policies
                pol_name = doc_result["name"]
                if not any(p["name"] == pol_name for p in desired_inventory.policies):
                    desired_inventory.policies.append({
                        "name": pol_name,
                        "arn": parn,
                        "type": doc_result.get("type", "aws-managed"),
                        "document": doc_result["document"],
                        "riskScore": 0,
                    })
        except Exception as e:
            logger.warning(f"[SIMULATION PREVIEW] Could not fetch policy document {parn}: {e}")

    return build_desired_analysis(
        desired_inventory=desired_inventory,
        desired_policy_doc_map=desired_policy_doc_map,
        current_inventory=current_inventory,
        current_policy_doc_map=current_policy_doc_map,
        current_attack_paths=current_attack_paths,
        current_global_posture=current_global_posture,
    )


# ─── Private helpers ─────────────────────────────────────────────────────────

def _all_resources(inventory: Any) -> List[Dict[str, Any]]:
    return (
        getattr(inventory, "s3", []) +
        getattr(inventory, "ec2", []) +
        getattr(inventory, "lambdas", []) +
        getattr(inventory, "secrets", []) +
        getattr(inventory, "rds", []) +
        getattr(inventory, "dynamodb", [])
    )


def _build_risk_reasons(
    attack_path_comparison: dict,
    graph_diff: dict,
    desired_posture: dict,
    current_posture: Optional[dict],
) -> List[str]:
    reasons = []
    new_count = len(attack_path_comparison.get("new_paths", []))
    removed_count = len(attack_path_comparison.get("removed_paths", []))
    added_edges = len(graph_diff.get("added_edges", []))
    new_res = len([
        e for e in graph_diff.get("added_edges", [])
        if e.get("label") == "ALLOWS"
    ])

    if new_count > 0:
        reasons.append(f"{new_count} new attack path(s) introduced by simulation change")
    if removed_count > 0:
        reasons.append(f"{removed_count} attack path(s) removed by simulation change")
    if new_res > 0:
        reasons.append(f"{new_res} new policy-to-resource access relationship(s) added")
    if added_edges > 0:
        reasons.append(f"{added_edges} new graph relationship(s) in desired state")

    # Add category deltas from posture
    if current_posture and desired_posture:
        for cat, info in desired_posture.get("categories", {}).items():
            current_cat = current_posture.get("categories", {}).get(cat, {})
            delta = info.get("score", 0) - current_cat.get("score", 0)
            if delta < -5:
                reasons.append(f"{info.get('name', cat)}: score decreased by {abs(delta)} points")
            elif delta > 5:
                reasons.append(f"{info.get('name', cat)}: score improved by {delta} points")

    return reasons[:8]  # Cap at 8 reasons for display


def _classify_resource(res: Dict[str, Any]) -> Tuple[bool, bool]:
    """Deterministically classify a resource as sensitive and/or critical.

    Supported categories: S3, EC2, Lambda, RDS, DynamoDB, Secrets Manager.
    Returns: (is_sensitive, is_critical)
    """
    rtype = str(res.get("type", "")).strip()
    rname = str(res.get("name") or res.get("id") or res.get("label") or "").lower()
    rrisk = res.get("riskScore", 0)
    rsev = str(res.get("severity", "")).lower()

    sensitive_types = {"Secrets", "Secret", "RDS", "DynamoDB"}
    is_sensitive = (
        rtype in sensitive_types
        or "pii" in rname
        or "secret" in rname
        or "credential" in rname
        or "token" in rname
        or "confidential" in rname
        or rrisk >= 60
    )

    critical_types = {"Secrets", "Secret", "RDS"}
    is_critical = (
        rtype in critical_types
        or rsev == "critical"
        or rrisk >= 70
        or ("prod" in rname and is_sensitive)
    )

    return is_sensitive, is_critical


def _compute_blast_metrics(
    G: Any,
    inventory: Any,
    policy_doc_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Calculate blast radius metrics representing actual reachable impact across all identities.

    Uses the authoritative EFFECTIVE ACCESS ENGINE when inventory and policy documents
    are available, calculating unique affected identities and unique reachable resources.
    Falls back gracefully to graph reachability if inventory is None (e.g. graph-only unit tests).
    """
    cloud_resource_types = {"S3", "EC2", "Lambda", "Secrets", "Secret", "RDS", "DynamoDB"}

    affected_identities: Set[str] = set()
    reachable_resources: Set[str] = set()
    sensitive_resources: Set[str] = set()
    critical_resources: Set[str] = set()
    resource_types: Dict[str, int] = {}
    resource_details_map: Dict[str, Dict[str, Any]] = {}

    all_res = _all_resources(inventory) if inventory else []
    for r in all_res:
        rid = r.get("id") or r.get("name", "")
        if rid:
            resource_details_map[rid] = r
            if r.get("name"):
                resource_details_map[r["name"]] = r

    # 1. Authoritative Effective Access Engine if inventory and policies are available
    if inventory and (all_res or getattr(inventory, "policies", [])):
        p_map = policy_doc_map or {}
        access_records = compute_effective_access(inventory, p_map, all_res)

        has_users = bool(getattr(inventory, "users", []))
        for rec in access_records:
            rid = rec.get("target_resource_id") or rec.get("target_resource_name")
            if not rid:
                continue

            rtype = rec.get("target_resource_type", "Resource")
            # Track unique reachable resource
            if rid not in reachable_resources:
                reachable_resources.add(rid)
                resource_types[rtype] = resource_types.get(rtype, 0) + 1

                res_obj = resource_details_map.get(rid) or {
                    "id": rid,
                    "name": rec.get("target_resource_name", rid),
                    "type": rtype,
                }
                is_sens, is_crit = _classify_resource(res_obj)
                if is_sens:
                    sensitive_resources.add(rid)
                if is_crit:
                    critical_resources.add(rid)

            # Track affected identities (unique users or roles that have reachability)
            if has_users:
                if rec.get("identity_type") == "User":
                    affected_identities.add(rec["identity_name"])
            else:
                affected_identities.add(rec["identity_name"])

    # 2. Graph topology fallback if inventory was not provided or had no records
    elif G:
        all_identities = []
        for nid, data in G.nodes(data=True):
            if data.get("type") in {"User", "Role"}:
                all_identities.append(nid)

        for ident in all_identities:
            try:
                descendants = nx.descendants(G, ident)
            except Exception:
                descendants = set()

            ident_has_resource = False
            for d in descendants:
                if not G.has_node(d):
                    continue
                d_data = G.nodes[d]
                d_type = d_data.get("type", "Resource")
                if d_type in cloud_resource_types:
                    ident_has_resource = True
                    if d not in reachable_resources:
                        reachable_resources.add(d)
                        resource_types[d_type] = resource_types.get(d_type, 0) + 1

                        is_sens, is_crit = _classify_resource({
                            "id": d,
                            "name": d_data.get("label", d),
                            "type": d_type,
                            "riskScore": d_data.get("riskScore", 0),
                            "severity": d_data.get("severity", ""),
                        })
                        if is_sens:
                            sensitive_resources.add(d)
                        if is_crit:
                            critical_resources.add(d)

            if ident_has_resource:
                affected_identities.add(ident)

    # Blast score based on unique reachable assets, sensitive/critical weighting, and affected identities
    # Deterministic 0-100 score; no probability, no likelihood, no randomness
    raw_score = (
        len(reachable_resources) * 8
        + len(sensitive_resources) * 15
        + len(critical_resources) * 10
        + len(affected_identities) * 4
    )
    blast_score = min(100, max(0, raw_score))

    return {
        "blast_score": blast_score,
        "affected_identities_count": len(affected_identities),
        "affected_identity_ids": affected_identities,
        "reachable_resource_count": len(reachable_resources),
        "reachable_resource_ids": reachable_resources,
        "sensitive_resource_count": len(sensitive_resources),
        "sensitive_resource_ids": sensitive_resources,
        "critical_resource_count": len(critical_resources),
        "critical_resource_ids": critical_resources,
        "resource_types": resource_types,
    }


def _compute_blast_comparison(
    G_current: Any,
    G_desired: Any,
    current_inventory: Any,
    desired_inventory: Any,
    current_policy_doc_map: Optional[Dict[str, str]] = None,
    desired_policy_doc_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Calculate blast radius comparison between current and desired state.

    Uses authoritative effective access results, unique affected identities, and
    unique reachable resources across all paths to accurately measure simulation impact
    without double-counting duplicate paths or fabricating heuristics.
    """
    c_metrics = _compute_blast_metrics(G_current, current_inventory, current_policy_doc_map)
    d_metrics = _compute_blast_metrics(G_desired, desired_inventory, desired_policy_doc_map)

    new_res_ids = d_metrics["reachable_resource_ids"] - c_metrics["reachable_resource_ids"]
    rem_res_ids = c_metrics["reachable_resource_ids"] - d_metrics["reachable_resource_ids"]

    # Collect resource lookup metadata
    all_cur = _all_resources(current_inventory) if current_inventory else []
    all_des = _all_resources(desired_inventory) if desired_inventory else []

    cur_res_map = {r.get("id") or r.get("name", ""): r for r in all_cur}
    des_res_map = {r.get("id") or r.get("name", ""): r for r in all_des}

    new_reachable = []
    for rid in sorted(new_res_ids):
        res_info = des_res_map.get(rid)
        name = rid
        rtype = "Resource"
        risk = 0
        sev = "unknown"
        if res_info:
            name = res_info.get("name", rid)
            rtype = res_info.get("type", "Resource")
            risk = res_info.get("riskScore", 0)
            sev = res_info.get("severity", "unknown")
        elif G_desired and G_desired.has_node(rid):
            name = G_desired.nodes[rid].get("label", rid)
            rtype = G_desired.nodes[rid].get("type", "Resource")
            risk = G_desired.nodes[rid].get("riskScore", 0)
            sev = G_desired.nodes[rid].get("severity", "unknown")

        is_sens, is_crit = _classify_resource({"id": rid, "name": name, "type": rtype, "riskScore": risk, "severity": sev})
        new_reachable.append({
            "id": rid,
            "name": name,
            "type": rtype,
            "riskScore": risk,
            "severity": sev,
            "isSensitive": is_sens,
            "isCritical": is_crit,
        })

    rem_reachable = []
    for rid in sorted(rem_res_ids):
        res_info = cur_res_map.get(rid)
        name = rid
        rtype = "Resource"
        risk = 0
        sev = "unknown"
        if res_info:
            name = res_info.get("name", rid)
            rtype = res_info.get("type", "Resource")
            risk = res_info.get("riskScore", 0)
            sev = res_info.get("severity", "unknown")
        elif G_current and G_current.has_node(rid):
            name = G_current.nodes[rid].get("label", rid)
            rtype = G_current.nodes[rid].get("type", "Resource")
            risk = G_current.nodes[rid].get("riskScore", 0)
            sev = G_current.nodes[rid].get("severity", "unknown")

        is_sens, is_crit = _classify_resource({"id": rid, "name": name, "type": rtype, "riskScore": risk, "severity": sev})
        rem_reachable.append({
            "id": rid,
            "name": name,
            "type": rtype,
            "riskScore": risk,
            "severity": sev,
            "isSensitive": is_sens,
            "isCritical": is_crit,
        })

    # Track affected identities by comparing effective reachable sets
    impacted_identities: List[str] = []
    newly_affected_identities: List[str] = []
    no_longer_affected_identities: List[str] = []
    changed_access_identities: List[str] = []

    if current_inventory and desired_inventory:
        cur_reach = compute_reachable_resources(current_inventory, current_policy_doc_map or {}, all_cur)
        des_reach = compute_reachable_resources(desired_inventory, desired_policy_doc_map or {}, all_des)
        all_keys = sorted(set(cur_reach.keys()) | set(des_reach.keys()))

        for ikey in all_keys:
            c_set = cur_reach.get(ikey, set())
            d_set = des_reach.get(ikey, set())
            if c_set != d_set:
                iname = ikey.split(":", 1)[1] if ":" in ikey else ikey
                impacted_identities.append(iname)
                if not c_set and d_set:
                    newly_affected_identities.append(iname)
                elif c_set and not d_set:
                    no_longer_affected_identities.append(iname)
                else:
                    changed_access_identities.append(iname)

    return {
        "current_blast_score": c_metrics["blast_score"],
        "desired_blast_score": d_metrics["blast_score"],
        "delta": d_metrics["blast_score"] - c_metrics["blast_score"],
        "current_resource_count": c_metrics["reachable_resource_count"],
        "desired_resource_count": d_metrics["reachable_resource_count"],
        "resources_delta": d_metrics["reachable_resource_count"] - c_metrics["reachable_resource_count"],
        "current_identities_count": c_metrics["affected_identities_count"],
        "desired_identities_count": d_metrics["affected_identities_count"],
        "identities_delta": d_metrics["affected_identities_count"] - c_metrics["affected_identities_count"],
        "current_sensitive_count": c_metrics["sensitive_resource_count"],
        "desired_sensitive_count": d_metrics["sensitive_resource_count"],
        "sensitive_delta": d_metrics["sensitive_resource_count"] - c_metrics["sensitive_resource_count"],
        "current_critical_count": c_metrics["critical_resource_count"],
        "desired_critical_count": d_metrics["critical_resource_count"],
        "critical_delta": d_metrics["critical_resource_count"] - c_metrics["critical_resource_count"],
        "current_resource_types": c_metrics["resource_types"],
        "desired_resource_types": d_metrics["resource_types"],
        "new_reachable_resources": new_reachable,
        "removed_reachable_resources": rem_reachable,
        "impacted_identities": impacted_identities,
        "newly_affected_identities": newly_affected_identities,
        "no_longer_affected_identities": no_longer_affected_identities,
        "changed_access_identities": changed_access_identities,
    }


def _build_summary(
    attack_path_comparison: dict,
    resource_diff: dict,
    risk_comparison: dict,
) -> str:
    new_paths = len(attack_path_comparison.get("new_paths", []))
    removed_paths = len(attack_path_comparison.get("removed_paths", []))
    new_res = len(resource_diff.get("new_reachable", []))
    removed_res = len(resource_diff.get("removed_reachable", []))
    delta = risk_comparison.get("delta", 0)
    desired_sev = risk_comparison.get("desired_severity", "unknown")

    parts = []
    if delta > 0:
        parts.append(f"Risk increased by {delta} points to {desired_sev.upper()}.")
    elif delta < 0:
        parts.append(f"Risk decreased by {abs(delta)} points to {desired_sev.upper()}.")
    else:
        parts.append(f"Risk unchanged ({desired_sev.upper()}).")

    if new_paths:
        parts.append(f"{new_paths} new attack path(s) introduced.")
    if removed_paths:
        parts.append(f"{removed_paths} attack path(s) removed.")
    if new_res:
        parts.append(f"{new_res} new resource(s) become reachable.")
    if removed_res:
        parts.append(f"{removed_res} resource(s) become unreachable.")

    return " ".join(parts) if parts else "No significant security impact detected."
