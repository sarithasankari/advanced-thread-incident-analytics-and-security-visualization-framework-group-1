"""
Logging Module
Configures multi-channel logging for application, API, database, auth, and predictions.
"""

import os
import logging
from typing import Dict
from src.config import settings

# Global cache to prevent adding duplicate handlers
_loggers: Dict[str, logging.Logger] = {}

def _setup_logger(name: str, log_filename: str, level: int = logging.INFO) -> logging.Logger:
    """Configures a custom logger with file and console handlers."""
    if name in _loggers:
        return _loggers[name]

    log_dir = settings.LOG_DIR
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, log_filename)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False # Prevent double logging to root

    formatter = logging.Formatter(
        fmt='[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File Handler
    file_handler = logging.FileHandler(log_path, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console Handler (Only for main app/API and error channels to keep terminal output clean)
    if name in ["app", "api", "error"]:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # If this is not the error logger itself, register a secondary error handler
    # so that error-level logs from this channel are also routed to error.log
    if name != "error":
        error_log_path = os.path.join(log_dir, "error.log")
        error_file_handler = logging.FileHandler(error_log_path, encoding='utf-8')
        error_file_handler.setLevel(logging.ERROR)
        error_file_handler.setFormatter(formatter)
        logger.addHandler(error_file_handler)

    _loggers[name] = logger
    return logger

def get_logger(name: str = "app") -> logging.Logger:
    """Returns a general application logger writing to app.log."""
    return _setup_logger(name, "app.log")

def get_prediction_logger() -> logging.Logger:
    """Returns a logger dedicated to inference and threat predictions writing to prediction.log."""
    return _setup_logger("prediction", "prediction.log")

def get_api_logger() -> logging.Logger:
    """Returns a logger dedicated to API request-response patterns writing to api.log."""
    return _setup_logger("api", "api.log")

def get_auth_logger() -> logging.Logger:
    """Returns a logger dedicated to JWT validation and role accesses writing to auth.log."""
    return _setup_logger("auth", "auth.log")

def get_db_logger() -> logging.Logger:
    """Returns a logger dedicated to SQLAlchemy database activities writing to database.log."""
    return _setup_logger("database", "database.log")

def get_error_logger() -> logging.Logger:
    """Returns a logger dedicated exclusively to traceback dumps writing to error.log."""
    return _setup_logger("error", "error.log", logging.ERROR)
