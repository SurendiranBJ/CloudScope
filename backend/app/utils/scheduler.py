import logging
import threading
import time
from apscheduler.schedulers.background import BackgroundScheduler
from app.config import settings

logger = logging.getLogger("backend")

_scheduler = BackgroundScheduler()


_current_interval: int | None = None


def _get_connected_project_ids() -> list[str]:
    """Return active account projects whose AWS roles have passed verification."""
    from app.persistence.database import get_db_session
    from app.persistence.models import CloudProjectModel

    with get_db_session() as session:
        projects = (
            session.query(CloudProjectModel)
            .filter_by(status="ACTIVE", verification_status="CONNECTED")
            .all()
        )
        return [project.project_id for project in projects if project.role_arn]


def _wait_for_scan(scan_id: str, timeout_seconds: float = 12 * 60 * 60) -> bool:
    """Wait for the durable scan run to reach a terminal state before queuing the next."""
    from app.persistence.database import get_db_session
    from app.persistence.models import ScanRunModel

    terminal_statuses = {"SUCCESS", "PARTIAL", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with get_db_session() as session:
                run = session.query(ScanRunModel).filter_by(scan_id=scan_id).first()
                if run is None:
                    logger.error("Scheduled scan %s has no durable run record", scan_id)
                    return False
                if run.status in terminal_statuses:
                    return True
        except Exception:
            logger.exception("Could not read scheduled scan status for %s", scan_id)
            return False
        time.sleep(1)
    logger.error("Scheduled scan %s did not finish before the 12-hour wait limit", scan_id)
    return False


def _run_scheduled_scans(trigger_type: str) -> None:
    """Run connected account projects serially through the shared scan coordinator."""
    from app.services.scanner.scan_coordinator import scan_coordinator

    try:
        project_ids = _get_connected_project_ids()
    except Exception:
        logger.exception("Could not load connected projects for %s scans", trigger_type.lower())
        return

    # Retain the single-account profile scan when no verified project is registered.
    if not project_ids:
        result = scan_coordinator.request_scan(
            trigger_type=trigger_type,
            actor_id="scheduler" if trigger_type == "SCHEDULED" else "startup",
            actor_role="SYSTEM",
        )
        logger.info("%s profile scan request: %s", trigger_type, result.get("status"))
        return

    for project_id in project_ids:
        result = scan_coordinator.request_scan(
            trigger_type=trigger_type,
            actor_id="scheduler" if trigger_type == "SCHEDULED" else "startup",
            actor_role="SYSTEM",
            project_id=project_id,
        )
        status = result.get("status")
        if status == "STARTED":
            logger.info("Started %s scan for project %s", trigger_type.lower(), project_id)
            if not _wait_for_scan(result["scan_id"]):
                # Do not queue another project while the prior scan may still run.
                return
        elif status == "ALREADY_RUNNING":
            logger.info("Skipping remaining %s projects because another scan is already running", trigger_type.lower())
            return
        else:
            logger.warning(
                "Could not start %s scan for project %s: %s",
                trigger_type.lower(), project_id, result.get("message", status),
            )


def _trigger_scheduled_scan():
    _run_scheduled_scans("SCHEDULED")


def start_scheduler():
    global _current_interval
    interval = settings.SCAN_INTERVAL_MINUTES
    _current_interval = interval
    logger.info(f"Starting background scanner scheduler job (Interval: {interval} minutes)")

    # Run first scan via coordinator in a daemon thread so server boot is not blocked
    threading.Thread(
        target=lambda: _run_scheduled_scans("STARTUP"),
        daemon=True
    ).start()

    # Schedule interval scanning with max_instances=1 to prevent pile-ups
    _scheduler.add_job(
        func=_trigger_scheduled_scan,
        trigger="interval",
        minutes=interval,
        id="aws_sync_scan_job",
        max_instances=1,
        replace_existing=True,
        coalesce=True
    )
    _scheduler.start()


def stop_scheduler():
    logger.info("Stopping background scanner scheduler job")
    if _scheduler.running:
        _scheduler.shutdown()


def reschedule_scan_job(minutes: int) -> None:
    """Update the running APScheduler job's interval at runtime."""
    global _current_interval
    if not _scheduler.running:
        raise ValueError("Scheduler is not running")
    logger.info(f"Rescheduling aws_sync_scan_job to {minutes} minute(s)")
    _scheduler.reschedule_job(
        job_id="aws_sync_scan_job",
        trigger="interval",
        minutes=minutes
    )
    _current_interval = minutes


def get_scheduler_status() -> dict:
    """Return scheduler status including current interval and next run timestamp."""
    interval = _current_interval or settings.SCAN_INTERVAL_MINUTES
    next_run = None
    try:
        if _scheduler.running:
            job = _scheduler.get_job("aws_sync_scan_job")
            if job and job.next_run_time:
                next_run = job.next_run_time.isoformat()
    except Exception:
        pass
    return {
        "scheduled_scan_interval_minutes": interval,
        "next_scheduled_scan_at": next_run
    }
