import os
import logging
from logging.handlers import RotatingFileHandler
from app.config import settings

# Create logs directory
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

# Formatters
default_formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def setup_logger(name: str, log_file: str, level=logging.INFO) -> logging.Logger:
    handler = RotatingFileHandler(
        os.path.join(LOGS_DIR, log_file),
        maxBytes=5 * 1024 * 1024, # 5MB
        backupCount=3
    )
    handler.setFormatter(default_formatter)
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(default_formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers if setup multiple times
    if not logger.handlers:
        logger.addHandler(handler)
        logger.addHandler(console_handler)
        
    return logger

# Initialize main loggers
api_logger = setup_logger("backend", "backend.log", level=settings.LOG_LEVEL)
scan_logger = setup_logger("scanner", "scan.log", level=settings.LOG_LEVEL)
error_logger = setup_logger("errors", "errors.log", level=logging.ERROR)
