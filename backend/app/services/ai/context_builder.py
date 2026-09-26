"""
CloudScope AI Security Context Builder.

Extracts, prioritizes, and bounds authoritative security evidence from CloudScope's
scanners, graph engines, finding services, and simulation state.
Never invents data. Sanitizes secrets and enforces deterministic size limits.
"""

import json
import logging
from typing import Dict, Any, Optional, List
from app.config import settings
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from app.services.findings.finding_service import finding_service
from app.services.ai.sanitizer import sanitize_data

logger = logging.getLogger("backend")


class SecurityContextBuilder:
    """Builds bounded, sanitized, evidence-grounded security context for AI analysis."""

    def __init__(self, max_chars: Optional[int] = None):
        self.max_chars = max_chars or settings.AI_CONTEXT_MAX_CHARS

    def has_completed_scan(self) -> bool:
        """Check if at least one successful scan has completed."""
        if getattr(scan_manager, "_last_successful_scan_at", None):
            return True
        # Check cache indicators
        if cache.get("v1:findings") or cache.get("v1:attack-paths") or cache.get("v1:users"):
            return True
        return False

    def build_context(
        self,
        prompt: str,
        context_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        attack_path_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        simulation_context: Optional[Dict[str, Any]] = None,
        supplementary_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Assemble relevant, authoritative CloudScope security evidence.
        """
        context: Dict[str, Any] = {
            "scan_metadata": self._get_scan_metadata(),
            "target_focus": {},
            "findings": [],
            "attack_paths": [],
            "correlated_activity": [],
            "simulation": None,
        }

        # 1. Target Focus (Finding or Attack Path or Entity)
        if finding_id or context_type == "finding":
            fid = finding_id or entity_id
            if fid:
                finding = finding_service.get_finding_by_id(fid)
                if finding:
                    context["target_focus"]["type"] = "finding"
                    context["target_focus"]["data"] = finding.model_dump(by_alias=True)
                elif supplementary_metadata:
                    context["target_focus"]["type"] = "finding"
                    context["target_focus"]["data"] = supplementary_metadata

        if attack_path_id or context_type == "attack_path":
            ap_id = attack_path_id or entity_id
            path = self._get_attack_path_by_id(ap_id)
            if path:
                context["target_focus"]["type"] = "attack_path"
                context["target_focus"]["data"] = path
            elif supplementary_metadata:
                context["target_focus"]["type"] = "attack_path"
                context["target_focus"]["data"] = supplementary_metadata

        if entity_id and not context["target_focus"]:
            context["target_focus"]["type"] = entity_type or "entity"
            context["target_focus"]["id"] = entity_id
            entity_details = self._get_entity_details(entity_id, entity_type)
            if entity_details:
                context["target_focus"]["data"] = entity_details

        # 2. Simulation State (if provided or present)
        if simulation_context:
            context["simulation"] = simulation_context
        elif context_type == "simulation" or "simulation" in prompt.lower() or "detach" in prompt.lower() or "attach" in prompt.lower():
            sim_diff = cache.get("v1:simulation:diff")
            sim_risk = cache.get("v1:simulation:risk")
            if sim_diff or sim_risk:
                context["simulation"] = {
                    "diff": sim_diff,
                    "risk": sim_risk,
                }

        # 3. Relevant Findings (prioritize high/critical or keyword matches)
        all_findings = finding_service.get_all_findings()
        context["findings"] = self._prioritize_findings(all_findings, prompt, entity_id)

        # 4. Relevant Attack Paths
        all_paths = cache.get("v1:attack-paths") or []
        context["attack_paths"] = self._prioritize_attack_paths(all_paths, prompt, entity_id)

        # 5. Relevant CloudTrail / Correlated Activity
        corr_risks = cache.get("v1:correlated_risks") or []
        context["correlated_activity"] = self._prioritize_correlated(corr_risks, prompt, entity_id)

        # Sanitize secrets/credentials across all fields
        sanitized = sanitize_data(context, [settings.GEMINI_API_KEY] if settings.GEMINI_API_KEY else None)

        # Enforce deterministic size cap
        bounded = self._enforce_size_limit(sanitized)
        return bounded

    def _get_scan_metadata(self) -> Dict[str, Any]:
        """Retrieve high-level scan status and account context."""
        return {
            "last_successful_scan_at": getattr(scan_manager, "_last_successful_scan_at", None),
            "last_successful_scan_id": getattr(scan_manager, "_last_successful_scan_id", None),
            "is_running": getattr(scan_manager, "is_running", False),
        }

    def _get_attack_path_by_id(self, path_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """Look up attack path by ID from authoritative cache."""
        if not path_id:
            return None
        paths = cache.get("v1:attack-paths") or []
        for p in paths:
            if isinstance(p, dict) and p.get("id") == path_id:
                return p
        return None

    def _get_entity_details(self, entity_id: str, entity_type: Optional[str]) -> Optional[Dict[str, Any]]:
        """Look up basic entity details from cached inventory."""
        etype = (entity_type or "").lower()
        if "user" in etype:
            users = cache.get("v1:users") or []
            for u in users:
                if isinstance(u, dict) and (u.get("name") == entity_id or u.get("arn") == entity_id):
                    return u
        elif "role" in etype:
            roles = cache.get("v1:roles") or []
            for r in roles:
                if isinstance(r, dict) and (r.get("name") == entity_id or r.get("arn") == entity_id):
                    return r
        elif "resource" in etype or "s3" in etype or "lambda" in etype or "ec2" in etype:
            resources = cache.get("v1:resources") or []
            for res in resources:
                if isinstance(res, dict) and (res.get("name") == entity_id or res.get("arn") == entity_id or res.get("id") == entity_id):
                    return res
        return None

    def _prioritize_findings(self, findings: List[Any], prompt: str, entity_id: Optional[str]) -> List[Dict[str, Any]]:
        """Select top relevant findings, prioritized by relevance and risk score."""
        if not findings:
            return []

        prompt_terms = [t.lower() for t in prompt.split() if len(t) > 3]
        serialized: List[Dict[str, Any]] = []

        for f in findings:
            fd = f.model_dump(by_alias=True) if hasattr(f, "model_dump") else f
            score = fd.get("riskScore", 0)
            relevance = 0

            # Match entity ID
            if entity_id:
                p_val = str(fd.get("principal", "")).lower()
                r_val = str(fd.get("resource", "")).lower()
                if entity_id.lower() in p_val or entity_id.lower() in r_val:
                    relevance += 50

            # Match prompt terms
            f_text = f"{fd.get('title', '')} {fd.get('description', '')} {fd.get('category', '')}".lower()
            for term in prompt_terms:
                if term in f_text:
                    relevance += 10

            serialized.append({
                "data": {
                    "id": fd.get("id"),
                    "title": fd.get("title"),
                    "category": fd.get("category"),
                    "severity": fd.get("severity"),
                    "riskScore": fd.get("riskScore"),
                    "principal": fd.get("principal"),
                    "resource": fd.get("resource"),
                    "description": fd.get("description", "")[:250],
                    "remediation": fd.get("remediation", {}).get("recommendation", "") if isinstance(fd.get("remediation"), dict) else "",
                },
                "priority": relevance + score,
            })

        serialized.sort(key=lambda x: x["priority"], reverse=True)
        return [item["data"] for item in serialized[:8]]

    def _prioritize_attack_paths(self, paths: List[Any], prompt: str, entity_id: Optional[str]) -> List[Dict[str, Any]]:
        """Select top relevant attack paths."""
        if not paths:
            return []

        prompt_terms = [t.lower() for t in prompt.split() if len(t) > 3]
        scored_paths = []

        for p in paths:
            if not isinstance(p, dict):
                continue
            score = p.get("risk_score", 0)
            relevance = 0

            p_str = json.dumps(p).lower()
            if entity_id and entity_id.lower() in p_str:
                relevance += 50

            for term in prompt_terms:
                if term in p_str:
                    relevance += 10

            # Compact representation of attack path
            compact_path = {
                "id": p.get("id"),
                "source": p.get("source"),
                "destination": p.get("destination"),
                "target": p.get("target"),
                "target_type": p.get("target_type"),
                "severity": p.get("severity"),
                "risk_score": p.get("risk_score"),
                "blast_radius": p.get("blast_radius"),
                "ordered_relationships": p.get("ordered_relationships", []),
                "downstream_reachable_assets": (p.get("downstream_reachable_assets") or [])[:5],
                "downstream_summary": p.get("downstream_summary"),
                "cloudtrail_corroborated": p.get("cloudtrail_corroborated", False),
            }

            scored_paths.append({
                "data": compact_path,
                "priority": relevance + score,
            })

        scored_paths.sort(key=lambda x: x["priority"], reverse=True)
        return [item["data"] for item in scored_paths[:5]]

    def _prioritize_correlated(self, correlated: List[Any], prompt: str, entity_id: Optional[str]) -> List[Dict[str, Any]]:
        """Select top correlated CloudTrail events."""
        if not correlated:
            return []

        compact = []
        for c in correlated[:5]:
            if isinstance(c, dict):
                compact.append({
                    "event_name": c.get("event_name") or c.get("eventName"),
                    "principal": c.get("principal"),
                    "resource": c.get("resource"),
                    "classification": c.get("classification"),
                    "timestamp": c.get("timestamp") or c.get("eventTime"),
                    "error_code": c.get("error_code") or c.get("errorCode"),
                })
        return compact

    def _enforce_size_limit(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deterministically bound serialized context within max_chars without corrupting JSON.
        """
        dumped = json.dumps(context)
        if len(dumped) <= self.max_chars:
            return context

        # Step 1: Reduce number of general findings
        if len(context.get("findings", [])) > 3:
            context["findings"] = context["findings"][:3]
            dumped = json.dumps(context)
            if len(dumped) <= self.max_chars:
                return context

        # Step 2: Reduce number of general attack paths
        if len(context.get("attack_paths", [])) > 2:
            context["attack_paths"] = context["attack_paths"][:2]
            dumped = json.dumps(context)
            if len(dumped) <= self.max_chars:
                return context

        # Step 3: Reduce correlated activity
        if len(context.get("correlated_activity", [])) > 2:
            context["correlated_activity"] = context["correlated_activity"][:2]
            dumped = json.dumps(context)
            if len(dumped) <= self.max_chars:
                return context

        # Step 4: Truncate finding descriptions if still oversized
        for f in context.get("findings", []):
            if isinstance(f, dict) and "description" in f:
                f["description"] = f["description"][:80]
        dumped = json.dumps(context)
        if len(dumped) <= self.max_chars:
            return context

        # Step 5: Truncate descriptions in target focus if still oversized
        if "target_focus" in context and "data" in context["target_focus"]:
            tf_data = context["target_focus"]["data"]
            if isinstance(tf_data, dict) and "description" in tf_data:
                tf_data["description"] = tf_data["description"][:100]

        return context
