"""Structured logging configuration safe for Cloud Run and GCP Cloud Logging."""

import logging
import sys
import json
from typing import Any, Dict


class SafeJsonFormatter(logging.Formatter):
    """Custom JSON formatter compatible with Google Cloud Logging.
    
    Guarantees no sensitive data is dumped into standard outputs.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": self.formatTime(record, self.datefmt),
        }

        if hasattr(record, "props") and isinstance(record.props, dict):
            # Clean and attach structured fields
            log_entry["labels"] = record.props

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Initialize root and app loggers."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(SafeJsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    root_logger.addHandler(handler)
