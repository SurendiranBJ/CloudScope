import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from app.config import settings

logger = logging.getLogger("backend")

_scheduler = BackgroundScheduler()


_current_interval: int | None = None


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
    """Run one scan and schedule the next run after it reaches a terminal state."""
    from app.services.scanner.scan_coordinator import scan_coordinator

    result = scan_coordinator.request_scan(
        trigger_type=trigger_type,
        actor_id="scheduler" if trigger_type == "SCHEDULED" else "startup",
        actor_role="SYSTEM",
    )
    status = result.get("status")
    logger.info("%s configured-account scan request: %s", trigger_type, status)
    scan_id = result.get("scan_id")
    if status in {"STARTED", "ALREADY_RUNNING"} and scan_id:
        if not _wait_for_scan(scan_id):
            logger.error("%s configured-account scan %s did not complete", trigger_type, scan_id)
    elif status not in {"STARTED", "ALREADY_RUNNING"}:
        logger.warning("Could not start %s configured-account scan: %s", trigger_type.lower(), result.get("message", status))
    _schedule_next_scan(_current_interval or settings.SCAN_INTERVAL_MINUTES)


def _trigger_scheduled_scan():
    _run_scheduled_scans("SCHEDULED")


def _schedule_next_scan(minutes: int) -> None:
    """Use fixed-delay scheduling so scan duration does not consume the idle interval."""
    if not _scheduler.running:
        return
    next_run = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    _scheduler.add_job(
        func=_trigger_scheduled_scan,
        trigger="date",
        run_date=next_run,
        id="aws_sync_scan_job",
        replace_existing=True,
        max_instances=1,
    )


def start_scheduler():
    global _current_interval
    interval = settings.SCAN_INTERVAL_MINUTES
    _current_interval = interval
    logger.info(f"Starting background scanner scheduler job (Interval: {interval} minutes)")

    _scheduler.start()
    # Run the startup scan without blocking server boot. The worker schedules the
    # next scan only after this one finishes, then waits the full configured interval.
    threading.Thread(
        target=lambda: _run_scheduled_scans("STARTUP"),
        daemon=True,
        name="CloudScopeStartupScan",
    ).start()


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
    _current_interval = minutes
    _schedule_next_scan(minutes)


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
