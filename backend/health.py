"""Minimal operational health probes with no sensitive diagnostics."""

import uuid

from django.conf import settings
from django.core.cache import cache
from django.db import DatabaseError, connections
from django.http import JsonResponse
from redis.exceptions import RedisError


def _database_is_ready() -> bool:
    try:
        with connections["default"].cursor() as cursor:
            cursor.execute("SELECT 1")
            return cursor.fetchone() == (1,)
    except DatabaseError:
        return False


def _probe_response(payload: dict[str, str], status: int = 200) -> JsonResponse:
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store"
    return response


def _cache_is_ready() -> bool:
    if not settings.CACHE_URL:
        return True
    key = f"health:readiness:{uuid.uuid4()}"
    value = "ok"
    try:
        cache.set(key, value, timeout=5)
        is_ready = cache.get(key) == value
        cache.delete(key)
        return is_ready
    except (OSError, RedisError):
        return False


def liveness(_request):
    return _probe_response({"status": "ok"})


def readiness(_request):
    if _database_is_ready() and _cache_is_ready():
        return _probe_response({"status": "ready"})
    return _probe_response({"status": "unavailable"}, status=503)
