"""Structured logging utilities for production output."""

import json
import logging
from datetime import UTC, datetime

from .request_context import current_request_id


class RequestContextFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "request_id"):
            record.request_id = current_request_id.get() or "-"
        return True


class JSONFormatter(logging.Formatter):
    metadata_fields = (
        "request_id",
        "http_method",
        "http_route",
        "http_status",
        "duration_ms",
    )

    def format(self, record):
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for field in self.metadata_fields:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)
