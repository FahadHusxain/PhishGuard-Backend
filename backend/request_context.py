"""Request-scoped metadata shared by middleware and logging."""

from contextvars import ContextVar

current_request_id: ContextVar[str | None] = ContextVar(
    "current_request_id",
    default=None,
)
