# syntax=docker/dockerfile:1

FROM python:3.13.15-slim-trixie AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.txt .
RUN python -m pip wheel --wheel-dir /wheels -r requirements.txt


FROM python:3.13.15-slim-trixie AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid app --create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY requirements.txt .
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY --chown=app:app . .
RUN DJANGO_DEBUG=true python manage.py collectstatic --noinput

USER app
EXPOSE 8000

CMD ["gunicorn", "--config", "gunicorn.conf.py", "backend.wsgi:application"]
