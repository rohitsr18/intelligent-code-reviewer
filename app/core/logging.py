import json
import logging
import sys
from typing import Any, Dict


class SafeJsonFormatter(logging.Formatter):
    """Outputs JSON logs in Google Cloud Logging format without leaking sensitive fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry: Dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": self.formatTime(record, self.datefmt),
        }

        if hasattr(record, "props") and isinstance(record.props, dict):
            entry["labels"] = record.props

        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry)


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())

    for handler in root.handlers[:]:
        root.removeHandler(handler)

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

    root.addHandler(handler)
