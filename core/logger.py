"""
Structured Logging Utility.
Provides a standardized logging factory for the application.
"""
import logging
import sys
from typing import Optional
from config.settings import get_settings

_LOG_FORMAT: str = "%(asctime)s | %(name)s | %(levelname)-8s | %(message)s"
_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """Creates or retrieves a logger with standardized formatting."""
    settings = get_settings()
    effective_level: str = (level or settings.LOG_LEVEL).upper()

    logger = logging.getLogger(name)
    
    # Ensure handlers are added only once
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT))
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, effective_level, logging.INFO))
    return logger
