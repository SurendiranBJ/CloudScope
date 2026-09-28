"""
CloudScope Immutable SnapshotStore.

Manages authoritative published snapshots with:
- snapshot_id
- published_at
- status
- region_metadata
- collection_completeness

Authoritative snapshots are stored under versioned keys with NO TTL expiration
and switched atomically by updating current_snapshot_id.
"""

import copy
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.cache import cache

logger = logging.getLogger("scanner")


@dataclass(frozen=True)
class PublishedSnapshot:
    """Immutable representation of a published security snapshot."""
    snapshot_id: str
    published_at: str
    status: str
    region_metadata: Dict[str, Any] = field(default_factory=dict)
    collection_completeness: Dict[str, Any] = field(default_factory=dict)
    users: tuple = field(default_factory=tuple)
    roles: tuple = field(default_factory=tuple)
    groups: tuple = field(default_factory=tuple)
    policies: tuple = field(default_factory=tuple)
    resources: tuple = field(default_factory=tuple)
    alerts: tuple = field(default_factory=tuple)
    findings: tuple = field(default_factory=tuple)
    risks: tuple = field(default_factory=tuple)
    attack_paths: tuple = field(default_factory=tuple)
    graph: tuple = field(default_factory=tuple)
    effective_access: tuple = field(default_factory=tuple)
    dashboard: Dict[str, Any] = field(default_factory=dict)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "published_at": self.published_at,
            "status": self.status,
            "region_metadata": copy.deepcopy(self.region_metadata),
            "collection_completeness": copy.deepcopy(self.collection_completeness),
            "users": list(self.users),
            "roles": list(self.roles),
            "groups": list(self.groups),
            "policies": list(self.policies),
            "resources": list(self.resources),
            "alerts": list(self.alerts),
            "findings": list(self.findings),
            "risks": list(self.risks),
            "attack_paths": list(self.attack_paths),
            "graph": list(self.graph),
            "effective_access": list(self.effective_access),
            "dashboard": copy.deepcopy(self.dashboard),
            "scan_metadata": copy.deepcopy(self.scan_metadata),
        }


class SnapshotStore:
    """Thread-safe, immutable snapshot store managing versioned published snapshots."""

    def __init__(self):
        self._lock = threading.Lock()
        self._current_snapshot: Optional[PublishedSnapshot] = None
        self._history: Dict[str, PublishedSnapshot] = {}

    def publish(
        self,
        snapshot_id: str,
        status: str,
        published_at: Optional[str] = None,
        region_metadata: Optional[Dict[str, Any]] = None,
        collection_completeness: Optional[Dict[str, Any]] = None,
        users: Optional[List[dict]] = None,
        roles: Optional[List[dict]] = None,
        groups: Optional[List[dict]] = None,
        policies: Optional[List[dict]] = None,
        resources: Optional[List[dict]] = None,
        alerts: Optional[List[dict]] = None,
        findings: Optional[List[dict]] = None,
        risks: Optional[List[dict]] = None,
        attack_paths: Optional[List[dict]] = None,
        graph: Optional[List[dict]] = None,
        effective_access: Optional[List[dict]] = None,
        dashboard: Optional[Dict[str, Any]] = None,
        scan_metadata: Optional[Dict[str, Any]] = None,
    ) -> PublishedSnapshot:
        """Atomically publish a new immutable snapshot under versioned keys with NO TTL."""
        pub_at = published_at or (datetime.now(timezone.utc).isoformat() + "Z")
        reg_meta = dict(region_metadata or {})
        comp = dict(collection_completeness or {})
        meta = dict(scan_metadata or {})

        meta["snapshot_id"] = snapshot_id
        meta["snapshot_published_at"] = pub_at
        meta["last_published_scan_id"] = snapshot_id
        meta["last_published_at"] = pub_at
        meta["status"] = status
        meta["region_metadata"] = reg_meta
        meta["collection_completeness"] = comp

        snap = PublishedSnapshot(
            snapshot_id=snapshot_id,
            published_at=pub_at,
            status=status,
            region_metadata=reg_meta,
            collection_completeness=comp,
            users=tuple(copy.deepcopy(users or [])),
            roles=tuple(copy.deepcopy(roles or [])),
            groups=tuple(copy.deepcopy(groups or [])),
            policies=tuple(copy.deepcopy(policies or [])),
            resources=tuple(copy.deepcopy(resources or [])),
            alerts=tuple(copy.deepcopy(alerts or [])),
            findings=tuple(copy.deepcopy(findings or [])),
            risks=tuple(copy.deepcopy(risks or [])),
            attack_paths=tuple(copy.deepcopy(attack_paths or [])),
            graph=tuple(copy.deepcopy(graph or [])),
            effective_access=tuple(copy.deepcopy(effective_access or [])),
            dashboard=dict(dashboard or {}),
            scan_metadata=meta,
        )

        with self._lock:
            self._current_snapshot = snap
            self._history[snapshot_id] = snap

        # Publish versioned keys and active keys atomically without TTL (ttl_seconds=None)
        cache_payload = {
            # Versioned snapshot bundle
            f"v1:snapshot:{snapshot_id}": snap.to_dict(),
            # Atomic pointer to current snapshot
            "v1:current_snapshot_id": snapshot_id,
            "v1:last_published_scan_id": snapshot_id,
            "v1:last_published_at": pub_at,
            # Active collections (all guaranteed to match the exact same snapshot_id)
            "v1:users": list(snap.users),
            "v1:roles": list(snap.roles),
            "v1:groups": list(snap.groups),
            "v1:policies": list(snap.policies),
            "v1:resources": list(snap.resources),
            "v1:alerts": list(snap.alerts),
            "v1:findings": list(snap.findings),
            "v1:risks": list(snap.risks),
            "v1:attack-paths": list(snap.attack_paths),
            "v1:graph": list(snap.graph),
            "v1:effective_access": list(snap.effective_access),
            "v1:dashboard": snap.dashboard,
            "v1:scan_metadata": meta,
        }

        # Stored persistently without TTL
        cache.set_many(cache_payload, ttl_seconds=None)
        logger.info(
            f"[SNAPSHOT_STORE] Published snapshot {snapshot_id} atomically (status={status}, at={pub_at})"
        )
        return snap

    def get_current(self) -> Optional[PublishedSnapshot]:
        """Return the current immutable published snapshot."""
        with self._lock:
            if self._current_snapshot is not None:
                return self._current_snapshot

        # Fallback to cache restoration
        curr_id = cache.get("v1:current_snapshot_id") or cache.get("v1:last_published_scan_id")
        if curr_id:
            snap_dict = cache.get(f"v1:snapshot:{curr_id}")
            if isinstance(snap_dict, dict):
                snap = self._dict_to_snapshot(snap_dict)
                with self._lock:
                    self._current_snapshot = snap
                    self._history[snap.snapshot_id] = snap
                return snap

        return None

    def get_snapshot(self, snapshot_id: str) -> Optional[PublishedSnapshot]:
        """Retrieve a specific versioned snapshot by ID."""
        with self._lock:
            if snapshot_id in self._history:
                return self._history[snapshot_id]

        snap_dict = cache.get(f"v1:snapshot:{snapshot_id}")
        if isinstance(snap_dict, dict):
            return self._dict_to_snapshot(snap_dict)
        return None

    def has_snapshot(self) -> bool:
        """Check if any valid published snapshot exists."""
        curr = self.get_current()
        if curr is not None:
            return True
        if cache.get("v1:current_snapshot_id"):
            return True
        if cache.get("v1:last_published_scan_id") and (
            cache.get("v1:policies") is not None
            or cache.get("v1:users") is not None
            or cache.get("v1:resources") is not None
        ):
            return True
        return False

    def clear(self):
        """Clear all in-memory snapshot state (e.g., during tests)."""
        with self._lock:
            self._current_snapshot = None
            self._history.clear()

    def _dict_to_snapshot(self, d: dict) -> PublishedSnapshot:
        return PublishedSnapshot(
            snapshot_id=d.get("snapshot_id", ""),
            published_at=d.get("published_at", ""),
            status=d.get("status", "SUCCESS"),
            region_metadata=d.get("region_metadata", {}),
            collection_completeness=d.get("collection_completeness", {}),
            users=tuple(d.get("users", [])),
            roles=tuple(d.get("roles", [])),
            groups=tuple(d.get("groups", [])),
            policies=tuple(d.get("policies", [])),
            resources=tuple(d.get("resources", [])),
            alerts=tuple(d.get("alerts", [])),
            findings=tuple(d.get("findings", [])),
            risks=tuple(d.get("risks", [])),
            attack_paths=tuple(d.get("attack_paths", [])),
            graph=tuple(d.get("graph", [])),
            effective_access=tuple(d.get("effective_access", [])),
            dashboard=d.get("dashboard", {}),
            scan_metadata=d.get("scan_metadata", {}),
        )


snapshot_store = SnapshotStore()
