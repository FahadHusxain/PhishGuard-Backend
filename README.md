# PhishGuard Backend

PhishGuard is a phishing-detection platform with a Django REST API, web
application, and Chromium browser extension for URL analysis.

## Project documentation

- [System architecture and data flow](docs/architecture.md)
- [Security threat model](docs/threat-model.md)
- [Testing and examiner demonstration guide](docs/testing.md)
- [Deployment and recovery runbook](docs/operations.md)
- [Release checklist](docs/release-checklist.md)
- [ML experimentation and evaluation](ml_pipeline/README.md)
- [ML version 2 upgrade plan](docs/ml-upgrade-plan.md)
- [Unreleased change history](CHANGELOG.md)
- [Chrome and Edge extension](browser-extension/README.md)

## Browser extension

The installable Manifest V3 client lives in `browser-extension/`. It can
analyze the active Chrome or Edge tab or any pasted HTTP(S) URL. Its default
backend is the local development service at `http://127.0.0.1:8000`; remote
backends must use HTTPS and receive an explicit runtime host-permission grant.

The extension does not inject code into visited pages or request browser
history. Its production ML status is identical to the web application because
both clients use `/api/v1/predict/`.

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

Load the bundled trust-domain ranks into a fresh database with
`python manage.py load_domains`. If an older development database already has
stale rank-zero rows, review the source and use
`python manage.py load_domains --update-existing` explicitly; that mode can
reactivate entries an administrator previously disabled.

The dashboard has no runtime CDN dependency. Its CSS and JavaScript are served
through Django static files, and it enforces a strict same-origin Content
Security Policy. Self-hosted API documentation receives only the narrow inline
exception required by Swagger UI.

Operational probes are available at `/health/live/` and `/health/ready/`.
Every response includes an `X-Request-ID` header for log correlation. Production
logs are emitted as one JSON object per line.

The versioned API is available under `/api/v1/`. Existing `/api/` routes remain
available for compatibility. OpenAPI JSON and interactive documentation are
published at `/api/schema/` and `/api/docs/`.

API errors use a stable envelope containing `error.code`, a safe human-readable
`error.message`, structured `error.details`, and the response `request_id`.
Administrative REST actions accept authenticated Django sessions; HTTP Basic
authentication is disabled. Whitelist mutation additionally requires an active
staff account with both the `api.add_whitelistdomain` and
`api.change_whitelistdomain` permissions. Django's session authentication
enforces CSRF protection for these changes. Administrative sessions expire
when the browser closes and have an eight-hour maximum lifetime by default.

API endpoints accept JSON request bodies only and return `Cache-Control:
no-store`. Request bodies default to a 16 KiB ceiling. Analysis,
administration, and read endpoints have separate configurable rate budgets.
Set `PHISHGUARD_NUM_PROXIES` to the exact number of trusted reverse proxies so
client addresses cannot be forged through `X-Forwarded-For`.

Manual whitelist mutations through the REST endpoint create read-only audit
records containing the staff actor, reason, rank transition, request ID, and
timestamp. Repeated requests for an already-trusted domain do not create false
change events.

Whitelist hostnames are stored in canonical lowercase ASCII form. Model and API
writes normalize Unicode IDNs and trailing dots, while a database constraint
prevents case-insensitive duplicates. This keeps trusted-domain matching
consistent regardless of how a hostname is written in a submitted URL.
Matching uses an offline Public Suffix List, including private suffixes, so a
trusted tenant cannot accidentally grant trust to sibling tenants or an entire
public suffix.

## Configuration

Local configuration belongs in `.env`, which Git ignores. Copy
`.env.example` to get safe development defaults. Hosted environments must set
their own `DJANGO_SECRET_KEY`, allowed hosts, CORS origins, database URL, and
HTTPS security options.

Use `python manage.py createsuperuser` only for the initial owner account. For
day-to-day reviewers, create staff users and grant only the two whitelist
permissions named above. If administration is served from a separate trusted
HTTPS origin, list it explicitly in `DJANGO_CSRF_TRUSTED_ORIGINS`; never use a
wildcard.

Never commit `.env`, `db.sqlite3`, user scan data, or generated cache files.

Development uses an in-process cache. Multi-worker or multi-replica deployments
must set `CACHE_URL` to a shared Redis instance so application throttles share
state. Application throttling is a fairness and resource-protection control,
not a DDoS firewall; production should also enforce limits at its edge proxy or
hosting platform.

Dashboard aggregates are computed with two database queries and cached for ten
seconds by default (`PHISHGUARD_STATS_CACHE_SECONDS`). Model writes invalidate
the cached values. Trusted-domain search uses an indexed prefix rather than an
unbounded substring scan across the full dataset.

Run a bounded, read-only concurrency smoke test against a running instance with:

```bash
python scripts/load_test.py --base-url http://127.0.0.1:8000 \
  --requests 100 --concurrency 10
```

Pass `--target https://example.com/login` to exercise analysis instead; those
requests create normal scan records and remain subject to API throttling.

Scan records contain only normalized origins, not paths, queries, or fragments.
Public statistics contain aggregate counts only. Recent submitted domains are
returned only to active staff users with the `api.view_scanlog` permission.
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

For a production-shaped local stack with the application, PostgreSQL, Redis,
health-gated migrations, persistent database storage, and localhost-only port
binding:

```bash
cp .env.compose.example .env.compose
# Replace the placeholder secrets in .env.compose before continuing.
docker compose --env-file .env.compose up --detach --build --wait
curl --fail http://127.0.0.1:8000/health/ready/
```

The VS Code Containers extension can manage this stack once Docker Desktop is
installed and running. See [the operations runbook](docs/operations.md) for
logs, shutdown, backup, restore, hosted-environment requirements, and incident
checks.

## Detection engine

The URL API currently defaults to the explainable rules engine. The historical
CNN can be loaded through the lightweight NumPy adapter, but it is intentionally
disabled because the repository contains no training/evaluation provenance and
smoke evaluation shows unacceptable false positives. See
`ml_models/MODEL_CARD.md` before changing `PHISHGUARD_ML_ENABLED`.

The reproducible replacement experiment, dataset manifest, grouped evaluation,
and non-promotion decision are documented in `ml_pipeline/README.md` and
`ml_models/LEXICAL_MODEL_CARD.md`.

Rules evaluate independent structural signals such as IP-address hosts,
credential-lure tokens, nested redirect URLs, unusual subdomain depth, encoded
content, internationalized hostnames, and nonstandard ports. Keywords are
tokenized rather than substring-matched to reduce obvious false positives.
Rules-only results remain `UNKNOWN` when the evidence is insufficient; absence
of a known rule is never presented as proof that an arbitrary URL is safe.

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
