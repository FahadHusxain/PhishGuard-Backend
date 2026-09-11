"""Request metadata and safe HTTP access logging."""

import logging
import re
import time
import uuid

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse

from backend.request_context import current_request_id

request_logger = logging.getLogger("phishguard.requests")


class BrowserSecurityHeadersMiddleware:
    """Apply a strict browser policy to application responses."""

    CONTENT_SECURITY_POLICY = "; ".join(
        (
            "default-src 'self'",
            "base-uri 'self'",
            "connect-src 'self'",
            "font-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "img-src 'self' data:",
            "object-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
        )
    )
    DOCUMENTATION_POLICY = CONTENT_SECURITY_POLICY.replace(
        "script-src 'self'",
        "script-src 'self' 'unsafe-inline'",
    ).replace(
        "style-src 'self'",
        "style-src 'self' 'unsafe-inline'",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        policy = (
            self.DOCUMENTATION_POLICY
            if request.path == "/api/docs/"
            else self.CONTENT_SECURITY_POLICY
        )
        response.setdefault("Content-Security-Policy", policy)
        response.setdefault(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=()",
        )
        response.setdefault("Referrer-Policy", "same-origin")
        return response


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


class APIRequestLimitsMiddleware:
    """Reject oversized API requests early and disable sensitive response caching."""

    _BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/") and request.method in self._BODY_METHODS:
            content_length = request.META.get("CONTENT_LENGTH", "")
            try:
                declared_size = int(content_length) if content_length else 0
            except ValueError:
                declared_size = settings.DATA_UPLOAD_MAX_MEMORY_SIZE + 1
            if declared_size > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
                return self._too_large_response(request)

        try:
            response = self.get_response(request)
        except RequestDataTooBig:
            response = self._too_large_response(request)

        if request.path.startswith("/api/"):
            response["Cache-Control"] = "no-store"
        return response

    @staticmethod
    def _too_large_response(request):
        response = JsonResponse(
            {
                "error": {
                    "code": "request_too_large",
                    "message": "The request body is too large.",
                    "details": {
                        "max_bytes": settings.DATA_UPLOAD_MAX_MEMORY_SIZE,
                    },
                },
                "request_id": getattr(request, "request_id", None),
            },
            status=413,
        )
        response["Cache-Control"] = "no-store"
        return response
