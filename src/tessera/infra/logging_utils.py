"""
Shared logging configuration helpers.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone


class JsonLogFormatter(logging.Formatter):
    """Format records as JSON for machine-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra_fields = getattr(record, "fields", None)
        if isinstance(extra_fields, dict):
            payload.update(extra_fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


def configure_logging(*, level: str = "INFO", json_logs: bool = False) -> None:
    """Configure the TESSERA logger tree once."""
    logger = logging.getLogger("tessera")
    if getattr(logger, "_tessera_configured", False):
        return

    handler = logging.StreamHandler()
    if json_logs:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    logger._tessera_configured = True  # type: ignore[attr-defined]
