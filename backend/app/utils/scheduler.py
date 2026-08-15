import logging
import threading
from apscheduler.schedulers.background import BackgroundScheduler
from app.services.scanner.scan_manager import scan_manager
from app.config import settings

logger = logging.getLogger("backend")

_scheduler = BackgroundScheduler()


def start_scheduler():
    interval = settings.SCAN_INTERVAL_MINUTES
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
    """Update the running APScheduler job's interval at runtime.

    Uses reschedule_job() which atomically replaces the trigger on the
    existing job without cancelling it or creating a duplicate job.

    Args:
        minutes: New interval in minutes. Must be >= 1.

    Raises:
        ValueError: If the scheduler is not running or the job is not found.
    """
    if not _scheduler.running:
        raise ValueError("Scheduler is not running")
    logger.info(f"Rescheduling aws_sync_scan_job to {minutes} minute(s)")
    _scheduler.reschedule_job(
        job_id="aws_sync_scan_job",
        trigger="interval",
        minutes=minutes
    )
