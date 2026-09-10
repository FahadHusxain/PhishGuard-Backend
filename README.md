# PhishGuard Backend

PhishGuard is a Django REST API for URL phishing analysis, scan logging, and
whitelist management.

## Local development

The supported development baseline is Python 3.13.15 and Django 5.2.17 LTS.

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

The API is available at `http://127.0.0.1:8000/api/`.

Operational probes are available at `/health/live/` and `/health/ready/`.
Every response includes an `X-Request-ID` header for log correlation. Production
logs are emitted as one JSON object per line.

The versioned API is available under `/api/v1/`. Existing `/api/` routes remain
available for compatibility. OpenAPI JSON and interactive documentation are
published at `/api/schema/` and `/api/docs/`.

API errors use a stable envelope containing `error.code`, a safe human-readable
`error.message`, structured `error.details`, and the response `request_id`.
Administrative REST actions accept authenticated Django sessions; HTTP Basic
authentication is disabled.

## Configuration

Local configuration belongs in `.env`, which Git ignores. Copy
`.env.example` to get safe development defaults. Hosted environments must set
their own `DJANGO_SECRET_KEY`, allowed hosts, CORS origins, database URL, and
HTTPS security options.

Never commit `.env`, `db.sqlite3`, user scan data, or generated cache files.

Scan records contain only normalized origins, not paths, queries, or fragments.
Delete records older than the configured retention period with:

```bash
python manage.py purge_scan_logs --dry-run
python manage.py purge_scan_logs
```

The retention period defaults to 30 days and is configured through
`PHISHGUARD_SCAN_RETENTION_DAYS`. Schedule the command daily in hosted
environments.

## Production deployment

Production requires PostgreSQL through `DATABASE_URL`; the SQLite fallback is
development-only. Apply migrations as a release step, then start Gunicorn:

```bash
python manage.py migrate --noinput
gunicorn --config gunicorn.conf.py backend.wsgi:application
```

A non-root production image is defined in `Dockerfile`:

```bash
docker build -t phishguard-backend .
docker run --rm -p 8000:8000 --env-file .env phishguard-backend
```

Set `WEB_CONCURRENCY`, `GUNICORN_THREADS`, and `PORT` to tune the server for the
hosting environment. Never bake a production `.env` file into the image.

## Detection engine

The URL API currently defaults to the explainable rules engine. The historical
CNN can be loaded through the lightweight NumPy adapter, but it is intentionally
disabled because the repository contains no training/evaluation provenance and
smoke evaluation shows unacceptable false positives. See
`ml_models/MODEL_CARD.md` before changing `PHISHGUARD_ML_ENABLED`.

## Verification

```bash
python -m pip check
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
ruff check .
ruff format --check .
coverage run manage.py test
coverage report
```
