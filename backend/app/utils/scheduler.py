import logging
from apscheduler.schedulers.background import BackgroundScheduler
from app.services.scanner.scan_manager import scan_manager
from app.config import settings

logger = logging.getLogger("backend")

_scheduler = BackgroundScheduler()

import threading

def start_scheduler():
    interval = settings.SCAN_INTERVAL_MINUTES
    logger.info(f"Starting background scanner scheduler job (Interval: {interval} minutes)")
    
    # Run scan immediately on startup in a separate daemon thread to avoid blocking server boot
    threading.Thread(target=scan_manager.run_scan, daemon=True).start()
    
    # Schedule interval scanning
    _scheduler.add_job(
        func=scan_manager.run_scan,
        trigger="interval",
        minutes=interval,
        id="aws_sync_scan_job"
    )
    _scheduler.start()

def stop_scheduler():
    logger.info("Stopping background scanner scheduler job")
    if _scheduler.running:
        _scheduler.shutdown()
