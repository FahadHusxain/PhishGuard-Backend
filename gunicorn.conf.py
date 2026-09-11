"""Conservative Gunicorn defaults suitable for the model's memory footprint."""

import os


def positive_int_from_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


port = positive_int_from_env("PORT", 8000)
if port > 65535:
    raise RuntimeError("PORT must not exceed 65535")

bind = f"0.0.0.0:{port}"
workers = positive_int_from_env("WEB_CONCURRENCY", 2)
threads = positive_int_from_env("GUNICORN_THREADS", 2)
worker_class = "gthread"
timeout = positive_int_from_env("GUNICORN_TIMEOUT", 30)
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
accesslog = None
errorlog = "-"
capture_output = True
# Gunicorn 26 enables a filesystem-backed control socket by default. The
# Compose service deliberately has a read-only root filesystem and does not
# use that local control interface, so disable it explicitly.
control_socket_disable = True
