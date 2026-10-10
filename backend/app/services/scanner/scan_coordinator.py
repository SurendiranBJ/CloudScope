from app.config import settings
"""
CloudScope Unified Scan Coordinator.

Single orchestration path for both manual and scheduled scans across multi-worker deployments.
Enforces distributed locking, heartbeat lease renewal, durable state logging, and audit tracking.
"""

import logging
import threading
import time
import uuid
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.scanner.distributed_lock import distributed_scan_lock
from app.services.scanner.scan_manager import scan_manager
from app.cache import cache
from app.persistence.repository import (
    record_scan_run_start,
    record_scan_run_finish,
    record_audit_event,
)

logger = logging.getLogger("cloudscope.coordinator")


class ScanCoordinator:
    """Coordinates manual and scheduled scans with distributed locking and durable state tracking."""

    def __init__(self):
        self._lock = threading.Lock()

    def request_scan(
        self,
        trigger_type: str = "MANUAL",
        actor_id: str = "system",
        actor_role: str = "SYSTEM",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request a new security scan execution. Returns immediately with STARTED or ALREADY_RUNNING."""
        if created_by:
            actor_id = created_by

        with self._lock:
            # 1. Local process check
            if scan_manager.is_running:
                active_id = scan_manager.get_status().get("scan_id") or "active"
                return {
                    "status": "ALREADY_RUNNING",
                    "scan_id": active_id,
                    "message": "A scan is already running on this worker",
                }

            # 2. Distributed cross-worker lock check
            owner_token = distributed_scan_lock.acquire(lease_seconds=180)
            if not owner_token:
                if (
                    settings.is_production
                    and not cache.check_redis()
                ):
                    return {
                        "status": "UNAVAILABLE",
                        "scan_id": None,
                        "message": "Redis is unavailable; production scan locking fails closed",
                    }
                curr_status = scan_manager.get_status()
                active_id = curr_status.get("scan_id") or "remote-worker-scan"
                logger.info(f"[COORDINATOR] Scan request declined: lock held by another worker instance")
                return {
                    "status": "ALREADY_RUNNING",
                    "scan_id": active_id,
                    "message": "Scan is already running on another worker node",
                }

            # 3. Generate scan_id and mark in-memory state
            scan_id = str(uuid.uuid4())
            now_iso = datetime.now(timezone.utc).isoformat() + "Z"

            # 4. Record durable state & audit log
            record_scan_run_start(
                scan_id=scan_id,
                started_at=now_iso,
                scan_mode="global",
                created_by=actor_id,
                trigger_type=trigger_type,
            )

            record_audit_event(
                event_id=str(uuid.uuid4()),
                timestamp=now_iso,
                actor_id=actor_id,
                actor_role=actor_role,
                action="SCAN_TRIGGERED",
                resource_type="SCAN",
                resource_id=scan_id,
                scan_id=scan_id,
                result="SUCCESS",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"trigger_type": trigger_type},
            )

            # 5. Launch execution thread with lease renewal heartbeat
            scan_thread = threading.Thread(
                target=self._run_scan_worker,
                args=(scan_id, owner_token, actor_id, actor_role),
                daemon=True,
                name=f"ScanWorker-{scan_id[:8]}"
            )
            scan_thread.start()

            return {
                "status": "STARTED",
                "scan_id": scan_id,
                "message": "Scan started successfully",
            }

    def get_status(self) -> Dict[str, Any]:
        """Aggregate current scan status from scan_manager and current snapshot."""
        mgr_status = scan_manager.get_status()
        from app.services.scanner.current_snapshot import get_current_snapshot_id
        return {
            **mgr_status,
            "is_scanning": mgr_status.get("is_scanning", False),
            "current_scan_id": mgr_status.get("scan_id"),
            "current_snapshot_id": get_current_snapshot_id(),
            "active_phase": mgr_status.get("active_phase"),
        }

    def _run_scan_worker(
        self,
        scan_id: str,
        owner_token: str,
        actor_id: str,
        actor_role: str,
    ) -> None:
        """Worker thread executing scan pipeline while continuously maintaining heartbeat."""
        stop_heartbeat = threading.Event()
        lease_lost = threading.Event()

        def heartbeat_loop():
            while not stop_heartbeat.wait(timeout=30.0):
                renewed = distributed_scan_lock.renew(owner_token, lease_seconds=180)
                if not renewed:
                    logger.warning(f"[COORDINATOR] Warning: Heartbeat lease renewal failed for {scan_id}")
                    lease_lost.set()
                    return

        heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True, name=f"Heartbeat-{scan_id[:8]}")
        heartbeat_thread.start()

        start_time = time.time()
        result_status = "FAILED"
        err_summary = None

        try:
            logger.info(f"[COORDINATOR] Worker starting scan pipeline execution (scan_id={scan_id})")
            scan_manager._scan_lease_valid = lambda: (
                not lease_lost.is_set()
                and distributed_scan_lock.renew(owner_token, lease_seconds=180)
            )
            # Set scan manager attributes for the scan run
            scan_manager._scan_id = scan_id
            scan_manager._scan_started_at = datetime.now(timezone.utc).isoformat() + "Z"
            scan_manager._scan_started_perf = time.perf_counter()
            scan_manager._completed_collectors = 0
            scan_manager._total_collectors = 12
            scan_manager._is_running = True
            scan_manager._scan_status = "SCANNING"

            res = scan_manager._execute_scan(scan_id)
            result_status = res.get("scan_status") or ("SUCCESS" if res.get("status") == "success" else "FAILED")
            err_summary = res.get("error")
        except Exception as e:
            logger.error(f"[COORDINATOR] Unexpected error executing scan {scan_id}: {e}", exc_info=True)
            result_status = "FAILED"
            err_summary = str(e)
            scan_manager._scan_status = "FAILED"
            scan_manager._last_error = str(e)
        finally:
            duration = max(0.0, round(time.time() - start_time, 2))
            completed_iso = datetime.now(timezone.utc).isoformat() + "Z"

            # 1. Stop heartbeat
            stop_heartbeat.set()

            # 2. Release distributed lock
            distributed_scan_lock.release(owner_token)

            # 3. Update durable scan run record
            record_scan_run_finish(
                scan_id=scan_id,
                status=result_status,
                completed_at=completed_iso,
                duration_seconds=duration,
                snapshot_id=scan_id if result_status in ("SUCCESS", "PARTIAL") else None,
                resolved_regions=getattr(scan_manager, "_resolved_regions", []),
                successful_regions=getattr(scan_manager, "_successful_regions", []),
                failed_regions=getattr(scan_manager, "_failed_regions", []),
                error_summary=err_summary,
            )

            # SnapshotStore already atomically persisted the complete snapshot and
            # current pointer. Do not perform a second metadata-only pointer write.
            scan_manager._scan_lease_valid = None

            # 5. Record completion audit event
            record_audit_event(
                event_id=str(uuid.uuid4()),
                timestamp=completed_iso,
                actor_id=actor_id,
                actor_role=actor_role,
                action="SCAN_COMPLETED" if result_status in ("SUCCESS", "PARTIAL") else "SCAN_FAILED",
                resource_type="SCAN",
                resource_id=scan_id,
                scan_id=scan_id,
                snapshot_id=scan_id if result_status in ("SUCCESS", "PARTIAL") else None,
                result="SUCCESS" if result_status in ("SUCCESS", "PARTIAL") else "FAILURE",
                metadata={"duration_seconds": duration, "error": err_summary, "status": result_status},
            )

            logger.info(f"[COORDINATOR] Worker finished scan {scan_id} with status={result_status} in {duration}s")


scan_coordinator = ScanCoordinator()
