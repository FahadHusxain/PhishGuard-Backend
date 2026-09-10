"""Request metadata and safe HTTP access logging."""

import logging
import re
import time
import uuid

from backend.request_context import current_request_id

request_logger = logging.getLogger("phishguard.requests")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class RequestIDMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        supplied_request_id = request.headers.get("X-Request-ID", "")
        if REQUEST_ID_PATTERN.fullmatch(supplied_request_id):
            request_id = supplied_request_id
        else:
            request_id = str(uuid.uuid4())

        request.request_id = request_id
        started_at = time.perf_counter()
        context_token = current_request_id.set(request_id)
        try:
            response = self.get_response(request)
            duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
            response["X-Request-ID"] = request_id

            resolver_match = getattr(request, "resolver_match", None)
            route = getattr(resolver_match, "route", None) or "unmatched"
            request_logger.info(
                "request_completed",
                extra={
                    "http_method": request.method,
                    "http_route": route,
                    "http_status": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
            return response
        finally:
            current_request_id.reset(context_token)
