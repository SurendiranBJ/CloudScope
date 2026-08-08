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
