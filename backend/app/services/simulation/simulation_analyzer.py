"""
CloudScope Simulation Analyzer.

Runs the exact same security analysis pipeline (risk engine, attack paths,
blast radius, effective access) against the DESIRED inventory and compares
results to the CURRENT state.

Uses existing engines — no duplicated logic, no contradictory definitions.
"""

import logging
from typing import Any, Dict, List, Optional

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
from app.services.simulation.effective_access import compute_reachable_resources

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

    # ── 8. Blast radius (aggregate for highest-risk identity) ─────────────────
    blast_comparison = _compute_blast_comparison(
        G_current, G_desired, current_inventory, desired_inventory
    )

    summary = _build_summary(attack_path_comparison, resource_diff, risk_comparison)

    return {
        "simulation_active": True,
        "graph_diff": graph_diff,
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


def _compute_blast_comparison(
    G_current: Any,
    G_desired: Any,
    current_inventory: Any,
    desired_inventory: Any,
) -> Dict[str, Any]:
    """Calculate blast radius for highest-risk user in current vs desired."""
    # Use top-risk user as representative
    all_current = getattr(current_inventory, "users", []) + getattr(current_inventory, "roles", [])
    all_desired = getattr(desired_inventory, "users", []) + getattr(desired_inventory, "roles", [])

    def top_node_id(entities, G):
        best_id = None
        best_score = -1
        for e in entities:
            nid = f"aws:user:{e['name']}" if "mfaEnabled" in e else f"aws:role:{e['name']}"
            if G.has_node(nid) and e.get("riskScore", 0) > best_score:
                best_score = e.get("riskScore", 0)
                best_id = nid
        return best_id

    c_nid = top_node_id(all_current, G_current)
    d_nid = top_node_id(all_desired, G_desired)

    c_blast = calculate_blast_radius(G_current, c_nid) if c_nid else {"blast_score": 0, "reachable_resource_count": 0}
    d_blast = calculate_blast_radius(G_desired, d_nid) if d_nid else {"blast_score": 0, "reachable_resource_count": 0}

    return {
        "current_blast_score": c_blast.get("blast_score", 0),
        "desired_blast_score": d_blast.get("blast_score", 0),
        "delta": d_blast.get("blast_score", 0) - c_blast.get("blast_score", 0),
        "current_resource_count": c_blast.get("reachable_resource_count", 0),
        "desired_resource_count": d_blast.get("reachable_resource_count", 0),
        "new_reachable_resources": [],
        "removed_reachable_resources": [],
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
