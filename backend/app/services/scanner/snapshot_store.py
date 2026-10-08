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
    correlated_risks: tuple = field(default_factory=tuple)
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
            "correlated_risks": copy.deepcopy(self.correlated_risks),
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
        correlated_risks: Optional[List[dict]] = None,
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
            correlated_risks=tuple(copy.deepcopy(correlated_risks or [])),
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

        # Persist before making the snapshot visible to readers. If durable
        # publication fails, the previous in-memory snapshot and pointer remain
        # current and callers can fail the scan without exposing partial state.
        try:
            from app.persistence.repository import save_authoritative_snapshot
            saved = save_authoritative_snapshot(
                snapshot_id=snapshot_id,
                scan_id=meta.get("scan_id", snapshot_id),
                published_at=pub_at,
                status=status,
                duration_seconds=float(meta.get("duration_seconds", 0.0) or 0.0),
                region_metadata=reg_meta,
                collection_completeness=comp,
                users=list(snap.users),
                roles=list(snap.roles),
                groups=list(snap.groups),
                policies=list(snap.policies),
                resources=list(snap.resources),
                alerts=list(snap.alerts),
                correlated_risks=list(snap.correlated_risks),
                findings=list(snap.findings),
                risks=list(snap.risks),
                attack_paths=list(snap.attack_paths),
                graph=list(snap.graph),
                effective_access=list(snap.effective_access),
                dashboard=snap.dashboard,
                scan_metadata=meta,
            )
            if not saved:
                raise RuntimeError(f"SQL persistence returned False for snapshot {snapshot_id}")
        except Exception as e:
            logger.error(f"[SNAPSHOT_STORE] SQL persistence exception for snapshot {snapshot_id}: {e}")
            raise RuntimeError(f"Could not durably publish snapshot {snapshot_id}") from e

        with self._lock:
            self._current_snapshot = snap
            self._history[snapshot_id] = snap

        # Redis is a hot cache; SQL and the in-process immutable object remain
        # authoritative if the cache is unavailable.
        self._sync_to_cache(snap)

        logger.info(
            f"[SNAPSHOT_STORE] Published snapshot {snapshot_id} atomically (status={status}, at={pub_at})"
        )
        return snap

    def _sync_to_cache(self, snap: PublishedSnapshot) -> None:
        """Synchronize published snapshot to Redis hot cache without TTL."""
        try:
            cache_payload = {
                # Versioned snapshot bundle
                f"v1:snapshot:{snap.snapshot_id}": snap.to_dict(),
                # Atomic pointer to current snapshot
                "v1:current_snapshot_id": snap.snapshot_id,
                "v1:last_published_scan_id": snap.snapshot_id,
                "v1:last_published_at": snap.published_at,
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
                "v1:correlated_risks": list(snap.correlated_risks),
                "v1:dashboard": snap.dashboard,
                "v1:scan_metadata": snap.scan_metadata,
            }
            cache.set_many(cache_payload, ttl_seconds=None)
        except Exception as e:
            logger.warning(f"[SNAPSHOT_STORE] Redis sync failed for {snap.snapshot_id}: {e}")

    def recover_from_sql(self) -> Optional[PublishedSnapshot]:
        """
        Recover the authoritative published snapshot from durable SQL persistence.
        Restores in-memory state and warms the Redis cache.
        """
        try:
            from app.persistence.repository import load_authoritative_snapshot
            data = load_authoritative_snapshot()
            if not data:
                return None

            snap = self._dict_to_snapshot(data)
            with self._lock:
                self._current_snapshot = snap
                self._history[snap.snapshot_id] = snap

            # Warm cache
            self._sync_to_cache(snap)
            logger.info(f"[SNAPSHOT_STORE] Recovered authoritative snapshot {snap.snapshot_id} from SQL.")
            return snap
        except Exception as e:
            logger.error(f"[SNAPSHOT_STORE] Failed to recover snapshot from SQL: {e}")
            return None

    def get_current(self) -> Optional[PublishedSnapshot]:
        """Return the current immutable published snapshot."""
        # SQL owns the pointer. Redis can be flushed, stale, or unavailable, so
        # it is only a hint; consult SQL before accepting the local hot object.
        try:
            from app.persistence.repository import get_authoritative_current_snapshot_pointer
            sql_pointer = get_authoritative_current_snapshot_pointer()
            if sql_pointer and sql_pointer.get("snapshot_id"):
                sql_id = sql_pointer["snapshot_id"]
                with self._lock:
                    if self._current_snapshot and self._current_snapshot.snapshot_id == sql_id:
                        return self._current_snapshot
                from app.persistence.repository import load_authoritative_snapshot
                sql_data = load_authoritative_snapshot(snapshot_id=sql_id)
                if sql_data:
                    snapshot = self._dict_to_snapshot(sql_data)
                    with self._lock:
                        self._current_snapshot = snapshot
                        self._history[snapshot.snapshot_id] = snapshot
                    return snapshot
                return None
            if __import__("os").getenv("ENVIRONMENT", "development").lower() == "production":
                # A valid SQL database with no pointer means there is no
                # published snapshot; never resurrect one from a stale cache.
                return None
        except Exception as e:
            logger.error(f"[SNAPSHOT_STORE] SQL pointer lookup failed: {e}")
            # Do not accept a Redis/local pointer when the authoritative SQL
            # pointer cannot be read in production.
            if __import__("os").getenv("ENVIRONMENT", "development").lower() == "production":
                return None

        curr_id = cache.get("v1:current_snapshot_id") or cache.get("v1:last_published_scan_id")

        # Fallback / Override: If explicit raw cache keys exist without an active snapshot pointer
        # (e.g. unit tests mocking v1:policies / v1:users / v1:resources directly)
        if curr_id is None and (
            cache.get("v1:policies") is not None
            or cache.get("v1:users") is not None
            or cache.get("v1:resources") is not None
            or cache.get("v1:dashboard") is not None
        ):
            return None

        with self._lock:
            if self._current_snapshot is not None:
                if curr_id:
                    if self._current_snapshot.snapshot_id == curr_id:
                        return self._current_snapshot
                else:
                    return self._current_snapshot

        # Fallback 1: cache restoration
        if curr_id:
            snap_dict = cache.get(f"v1:snapshot:{curr_id}")
            if isinstance(snap_dict, dict):
                snap = self._dict_to_snapshot(snap_dict)
                with self._lock:
                    self._current_snapshot = snap
                    self._history[snap.snapshot_id] = snap
                return snap
            try:
                from app.persistence.repository import load_authoritative_snapshot
                sql_data = load_authoritative_snapshot(snapshot_id=curr_id)
                if sql_data:
                    snap = self._dict_to_snapshot(sql_data)
                    with self._lock:
                        self._current_snapshot = snap
                        self._history[snap.snapshot_id] = snap
                    return snap
            except Exception:
                pass

        # Fallback 2: SQL durable recovery
        return self.recover_from_sql()


    def get_snapshot(self, snapshot_id: str) -> Optional[PublishedSnapshot]:
        """Retrieve a specific versioned snapshot by ID."""
        with self._lock:
            if snapshot_id in self._history:
                return self._history[snapshot_id]

        snap_dict = cache.get(f"v1:snapshot:{snapshot_id}")
        if isinstance(snap_dict, dict):
            snap = self._dict_to_snapshot(snap_dict)
            with self._lock:
                self._history[snap.snapshot_id] = snap
            return snap

        # Fallback to SQL
        try:
            from app.persistence.repository import load_authoritative_snapshot
            data = load_authoritative_snapshot(snapshot_id=snapshot_id)
            if data:
                snap = self._dict_to_snapshot(data)
                with self._lock:
                    self._history[snap.snapshot_id] = snap
                return snap
        except Exception:
            pass

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
            correlated_risks=tuple(d.get("correlated_risks", (d.get("scan_metadata") or {}).get("correlated_risks", []))),
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

