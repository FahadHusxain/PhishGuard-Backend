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
