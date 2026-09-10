"""Stable, request-correlated error envelopes for REST API clients."""

from rest_framework import status
from rest_framework.views import exception_handler

ERROR_MESSAGES = {
    status.HTTP_400_BAD_REQUEST: "The request is invalid.",
    status.HTTP_401_UNAUTHORIZED: "Authentication is required.",
    status.HTTP_403_FORBIDDEN: "You do not have permission to perform this action.",
    status.HTTP_404_NOT_FOUND: "The requested resource was not found.",
    status.HTTP_405_METHOD_NOT_ALLOWED: "The HTTP method is not allowed.",
    status.HTTP_429_TOO_MANY_REQUESTS: "The request rate limit was exceeded.",
}


def api_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return None

    request = context.get("request")
    request_id = getattr(request, "request_id", None)
    response.data = {
        "error": {
            "code": getattr(exc, "default_code", "api_error"),
            "message": ERROR_MESSAGES.get(
                response.status_code,
                "The request could not be completed.",
            ),
            "details": response.data,
        },
        "request_id": request_id,
    }
    return response
