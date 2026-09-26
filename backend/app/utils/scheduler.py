import logging
import threading
from apscheduler.schedulers.background import BackgroundScheduler
from app.services.scanner.scan_manager import scan_manager
from app.config import settings

logger = logging.getLogger("backend")

_scheduler = BackgroundScheduler()


_current_interval: int | None = None


def start_scheduler():
    global _current_interval
    interval = settings.SCAN_INTERVAL_MINUTES
    _current_interval = interval
    logger.info(f"Starting background scanner scheduler job (Interval: {interval} minutes)")

    # Run first scan immediately in a daemon thread so server boot is not blocked
    threading.Thread(target=scan_manager.run_scan, daemon=True).start()

    # Schedule interval scanning with max_instances=1 to prevent pile-ups
    _scheduler.add_job(
        func=scan_manager.run_scan,
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
