"""
Central published-snapshot helper for CloudScope.

Resolution strategy:
1. Use published cache data when available.
2. Fall back to ScanManager's last published/current inventory or stored published snapshot.
3. NEVER use the currently building working inventory as published data.
4. NEVER return an empty list merely because a new scan is currently running when a previous published snapshot exists.
"""

from typing import List, Dict, Any, Optional
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager


def get_current_snapshot_id() -> Optional[str]:
    """Retrieve authoritative current published snapshot identifier."""
    cached_id = cache.get("v1:last_published_scan_id")
    if cached_id:
        return cached_id

    snap_id = scan_manager.last_published_scan_id
    if snap_id:
        return snap_id

    cached_meta = cache.get("v1:scan_metadata")
    if isinstance(cached_meta, dict):
        meta_id = cached_meta.get("snapshot_id") or cached_meta.get("last_published_scan_id") or cached_meta.get("scanId") or cached_meta.get("scan_id")
        if meta_id:
            return meta_id

    return scan_manager.current_snapshot_id


def get_current_snapshot_published_at() -> Optional[str]:
    """Retrieve authoritative current published snapshot timestamp."""
    cached_at = cache.get("v1:last_published_at")
    if cached_at:
        return cached_at

    pub_at = scan_manager.last_published_at
    if pub_at:
        return pub_at

    cached_meta = cache.get("v1:scan_metadata")
    if isinstance(cached_meta, dict):
        meta_at = cached_meta.get("snapshot_published_at") or cached_meta.get("last_published_at") or cached_meta.get("scanTimestamp") or cached_meta.get("timestamp")
        if meta_at:
            return meta_at

    status = scan_manager.get_status()
    return status.get("snapshot_published_at") or status.get("last_published_at") or status.get("last_successful_scan_at")


def has_published_snapshot() -> bool:
    """Return True if at least one verified published snapshot exists."""
    if cache.get("v1:last_published_scan_id") and (
        cache.get("v1:policies") is not None
        or cache.get("v1:policy_catalog") is not None
        or cache.get("v1:users") is not None
        or cache.get("v1:resources") is not None
    ):
        return True
    snap = getattr(scan_manager, "published_snapshot", None)
    if snap and isinstance(snap, dict) and any(bool(v) for v in snap.values()):
        return True
    if (
        cache.get("v1:policies") is not None
        or cache.get("v1:policy_catalog") is not None
        or cache.get("v1:users") is not None
        or cache.get("v1:roles") is not None
    ):
        return True
    return False


def get_current_snapshot_metadata() -> Dict[str, Any]:
    """Return complete metadata dictionary for the currently published snapshot."""
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

    return meta


def get_current_users() -> List[dict]:
    """Retrieve IAM users from the authoritative published snapshot."""
    cached = cache.get("v1:users")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(snap, dict):
        if snap.get("users"):
            return list(snap["users"])
        if snap.get("v1:users"):
            return list(snap["v1:users"])

    return []


def get_current_roles() -> List[dict]:
    """Retrieve IAM roles from the authoritative published snapshot."""
    cached = cache.get("v1:roles")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(snap, dict):
        if snap.get("roles"):
            return list(snap["roles"])
        if snap.get("v1:roles"):
            return list(snap["v1:roles"])

    return []


def get_current_groups() -> List[dict]:
    """Retrieve IAM groups from the authoritative published snapshot."""
    cached = cache.get("v1:groups")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(snap, dict):
        if snap.get("groups"):
            return list(snap["groups"])
        if snap.get("v1:groups"):
            return list(snap["v1:groups"])

    return []


def get_current_policies() -> List[dict]:
    """Retrieve IAM policies from the authoritative published snapshot."""
    cached = cache.get("v1:policies")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(snap, dict):
        if snap.get("policies"):
            return list(snap["policies"])
        if snap.get("v1:policies"):
            return list(snap["v1:policies"])

    return []


def get_current_resources() -> List[dict]:
    """Retrieve cloud resources from the authoritative published snapshot."""
    cached = cache.get("v1:resources")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(snap, dict):
        if snap.get("resources"):
            return list(snap["resources"])
        if snap.get("v1:resources"):
            return list(snap["v1:resources"])

    return []


def get_current_alerts() -> List[dict]:
    """Retrieve security alerts from the authoritative published snapshot."""
    cached = cache.get("v1:alerts")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if isinstance(snap, dict):
        if snap.get("alerts"):
            return list(snap["alerts"])
        if snap.get("v1:alerts"):
            return list(snap["v1:alerts"])

    return []


def get_current_findings() -> List[dict]:
    """Retrieve security findings from the authoritative published snapshot."""
    cached = cache.get("v1:findings")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if snap.get("v1:findings"):
        return list(snap["v1:findings"])

    return list(cached) if isinstance(cached, list) else []


def get_current_risks() -> List[dict]:
    """Retrieve risk findings from the authoritative published snapshot."""
    cached = cache.get("v1:risks")
    if isinstance(cached, list) and len(cached) > 0:
        return list(cached)

    snap = getattr(scan_manager, "published_snapshot", {})
    if snap.get("v1:risks"):
        return list(snap["v1:risks"])

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
                "recommendation": f.get("remediation", {}).get("title") if isinstance(f.get("remediation"), dict) else (f.get("recommendation") or "Review configuration")
            }
            for f in findings
            if f.get("status") == "OPEN" and f.get("riskScore", 0) >= 40
        ]
        risks.sort(key=lambda x: x["riskScore"], reverse=True)
        return risks

    return list(cached) if isinstance(cached, list) else []


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
