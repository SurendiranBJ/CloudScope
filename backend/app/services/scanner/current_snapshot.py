"""
Central authoritative published-snapshot reader for CloudScope.

Resolution strategy:
1. Use SnapshotStore authoritative immutable snapshot.
2. Fall back to authoritative published cache data (stored under persistent keys without TTL).
3. Fall back to ScanManager's published_snapshot.
4. NEVER use the currently building working inventory as published data.
5. NEVER fall back from a valid empty collection ([]) to stale inventory.
6. NEVER return an empty list merely because a new scan is currently running when a previous published snapshot exists.
"""

from typing import List, Dict, Any, Optional
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.snapshot_store import snapshot_store


def get_current_snapshot_id() -> Optional[str]:
    """Retrieve authoritative current published snapshot identifier."""
    snap = snapshot_store.get_current()
    if snap and snap.snapshot_id:
        return snap.snapshot_id

    cached_curr_id = cache.get("v1:current_snapshot_id")
    if cached_curr_id:
        return cached_curr_id

    cached_id = cache.get("v1:last_published_scan_id")
    if cached_id:
        return cached_id

    snap_id = scan_manager.last_published_scan_id
    if snap_id:
        return snap_id

    cached_meta = cache.get("v1:scan_metadata")
    if isinstance(cached_meta, dict):
        meta_id = (
            cached_meta.get("snapshot_id")
            or cached_meta.get("last_published_scan_id")
            or cached_meta.get("scanId")
            or cached_meta.get("scan_id")
        )
        if meta_id:
            return meta_id

    return scan_manager.current_snapshot_id


def get_current_snapshot_published_at() -> Optional[str]:
    """Retrieve authoritative current published snapshot timestamp."""
    snap = snapshot_store.get_current()
    if snap and snap.published_at:
        return snap.published_at

    cached_at = cache.get("v1:last_published_at")
    if cached_at:
        return cached_at

    pub_at = scan_manager.last_published_at
    if pub_at:
        return pub_at

    cached_meta = cache.get("v1:scan_metadata")
    if isinstance(cached_meta, dict):
        meta_at = (
            cached_meta.get("snapshot_published_at")
            or cached_meta.get("last_published_at")
            or cached_meta.get("scanTimestamp")
            or cached_meta.get("timestamp")
        )
        if meta_at:
            return meta_at

    status = scan_manager.get_status()
    return status.get("snapshot_published_at") or status.get("last_published_at") or status.get("last_successful_scan_at")


def has_published_snapshot() -> bool:
    """Return True if at least one verified published snapshot exists."""
    if snapshot_store.has_snapshot():
        return True
    if cache.get("v1:current_snapshot_id") or cache.get("v1:last_published_scan_id"):
        return True
    snap = getattr(scan_manager, "published_snapshot", None)
    if snap and isinstance(snap, dict) and any(bool(v) for v in snap.values()):
        return True
    return False


def get_current_snapshot_metadata() -> Dict[str, Any]:
    """Return complete metadata dictionary for the currently published snapshot."""
    snap = snapshot_store.get_current()
    if snap and snap.scan_metadata:
        meta = dict(snap.scan_metadata)
    else:
        cached_meta = cache.get("v1:scan_metadata")
        meta = dict(cached_meta) if isinstance(cached_meta, dict) else {}

    snap_id = get_current_snapshot_id()
    pub_at = get_current_snapshot_published_at()

    meta["snapshot_id"] = snap_id
    meta["snapshot_published_at"] = pub_at
    meta["has_published_snapshot"] = bool(snap_id)

    status = scan_manager.get_status()
    meta["scan_mode"] = meta.get("scan_mode") or status.get("scan_mode") or "global"
    meta["resolved_regions"] = meta.get("resolved_regions") or status.get("resolved_regions") or []
    meta["failed_regions"] = meta.get("failed_regions") or status.get("failed_regions") or []
    meta["successful_regions"] = meta.get("successful_regions") or status.get("successful_regions") or []

    if snap:
        meta["region_metadata"] = snap.region_metadata
        meta["collection_completeness"] = snap.collection_completeness

    return meta


def get_current_users() -> List[dict]:
    """Retrieve IAM users from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.users)

    cached = cache.get("v1:users")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "users" in psnap and isinstance(psnap["users"], list):
            return list(psnap["users"])
        if "v1:users" in psnap and isinstance(psnap["v1:users"], list):
            return list(psnap["v1:users"])

    return []


def get_current_roles() -> List[dict]:
    """Retrieve IAM roles from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.roles)

    cached = cache.get("v1:roles")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "roles" in psnap and isinstance(psnap["roles"], list):
            return list(psnap["roles"])
        if "v1:roles" in psnap and isinstance(psnap["v1:roles"], list):
            return list(psnap["v1:roles"])

    return []


def get_current_groups() -> List[dict]:
    """Retrieve IAM groups from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.groups)

    cached = cache.get("v1:groups")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "groups" in psnap and isinstance(psnap["groups"], list):
            return list(psnap["groups"])
        if "v1:groups" in psnap and isinstance(psnap["v1:groups"], list):
            return list(psnap["v1:groups"])

    return []


def get_current_policies() -> List[dict]:
    """Retrieve IAM policies from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.policies)

    cached = cache.get("v1:policies")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "policies" in psnap and isinstance(psnap["policies"], list):
            return list(psnap["policies"])
        if "v1:policies" in psnap and isinstance(psnap["v1:policies"], list):
            return list(psnap["v1:policies"])

    return []


def get_current_resources() -> List[dict]:
    """Retrieve cloud resources from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.resources)

    cached = cache.get("v1:resources")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "resources" in psnap and isinstance(psnap["resources"], list):
            return list(psnap["resources"])
        if "v1:resources" in psnap and isinstance(psnap["v1:resources"], list):
            return list(psnap["v1:resources"])

    return []


def get_current_alerts() -> List[dict]:
    """Retrieve security alerts from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.alerts)

    cached = cache.get("v1:alerts")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "alerts" in psnap and isinstance(psnap["alerts"], list):
            return list(psnap["alerts"])
        if "v1:alerts" in psnap and isinstance(psnap["v1:alerts"], list):
            return list(psnap["v1:alerts"])

    return []


def get_current_findings() -> List[dict]:
    """Retrieve security findings from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.findings)

    cached = cache.get("v1:findings")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "findings" in psnap and isinstance(psnap["findings"], list):
            return list(psnap["findings"])
        if "v1:findings" in psnap and isinstance(psnap["v1:findings"], list):
            return list(psnap["v1:findings"])

    return []


def get_current_risks() -> List[dict]:
    """Retrieve risk findings from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.risks)

    cached = cache.get("v1:risks")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict):
        if "risks" in psnap and isinstance(psnap["risks"], list):
            return list(psnap["risks"])
        if "v1:risks" in psnap and isinstance(psnap["v1:risks"], list):
            return list(psnap["v1:risks"])

    findings = get_current_findings()
    if findings:
        risks = [
            {
                "id": f.get("id", ""),
                "identity": f.get("principal") or f.get("resource") or "unknown",
                "identityType": f.get("principalType") or f.get("resourceType") or "Resource",
                "issue": f.get("description") or f.get("title", ""),
                "severity": f.get("severity", "medium"),
                "riskScore": f.get("riskScore", 0),
                "recommendation": (
                    f.get("remediation", {}).get("title")
                    if isinstance(f.get("remediation"), dict)
                    else (f.get("recommendation") or "Review configuration")
                ),
            }
            for f in findings
            if f.get("status") == "OPEN" and f.get("riskScore", 0) >= 40
        ]
        risks.sort(key=lambda x: x["riskScore"], reverse=True)
        return risks

    return []


def get_current_attack_paths() -> List[dict]:
    """Retrieve attack paths from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.attack_paths)

    cached = cache.get("v1:attack-paths")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict) and "v1:attack-paths" in psnap and isinstance(psnap["v1:attack-paths"], list):
        return list(psnap["v1:attack-paths"])

    return []


def get_current_graph() -> List[dict]:
    """Retrieve cytoscape graph elements from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.graph)

    cached = cache.get("v1:graph")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict) and "v1:graph" in psnap and isinstance(psnap["v1:graph"], list):
        return list(psnap["v1:graph"])

    return []


def get_current_effective_access() -> List[dict]:
    """Retrieve effective access records from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None:
        return list(snap.effective_access)

    cached = cache.get("v1:effective_access")
    if isinstance(cached, list):
        return list(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict) and "v1:effective_access" in psnap and isinstance(psnap["v1:effective_access"], list):
        return list(psnap["v1:effective_access"])

    return []


def get_current_dashboard() -> Dict[str, Any]:
    """Retrieve dashboard summary from the authoritative published snapshot."""
    snap = snapshot_store.get_current()
    if snap is not None and snap.dashboard:
        return dict(snap.dashboard)

    cached = cache.get("v1:dashboard")
    if isinstance(cached, dict):
        return dict(cached)

    psnap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(psnap, dict) and "v1:dashboard" in psnap and isinstance(psnap["v1:dashboard"], dict):
        return dict(psnap["v1:dashboard"])

    return {}


def get_current_relationship_inputs() -> Dict[str, Any]:
    """Retrieve all entity collections from the single authoritative current published snapshot."""
    snap_id = get_current_snapshot_id()
    pub_at = get_current_snapshot_published_at()

    return {
        "users": get_current_users(),
        "roles": get_current_roles(),
        "groups": get_current_groups(),
        "policies": get_current_policies(),
        "resources": get_current_resources(),
        "snapshot_id": snap_id,
        "snapshot_published_at": pub_at,
    }

