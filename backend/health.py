"""Minimal operational health probes with no sensitive diagnostics."""

from django.db import DatabaseError, connections
from django.http import JsonResponse


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


def liveness(_request):
    return _probe_response({"status": "ok"})


def readiness(_request):
    if _database_is_ready():
        return _probe_response({"status": "ready"})
    return _probe_response({"status": "unavailable"}, status=503)
