# Operations runbook

This runbook covers the repository's local, production-shaped Compose stack and
the minimum controls required when adapting it to a hosted environment.

## Start and verify the stack

Docker Desktop (including Docker Compose v2) must be running. The VS Code
Containers extension provides editor integration but does not replace the
Docker engine.

```bash
cp .env.compose.example .env.compose
```

Replace both placeholder passwords in `.env.compose` with long, URL-safe random
values. Then start the stack:

```bash
docker compose --env-file .env.compose config --quiet
docker compose --env-file .env.compose up --detach --build --wait
docker compose --env-file .env.compose ps
curl --fail http://127.0.0.1:8000/health/ready/
```

The web port binds only to loopback. PostgreSQL and Redis have no host ports.
The one-shot `migrate` service must complete before the web service starts.

Inspect structured application logs with:

```bash
docker compose --env-file .env.compose logs --follow web
```

Stop services without deleting database data:

```bash
docker compose --env-file .env.compose down
```

Do not add `--volumes` unless permanent deletion of the local database is
intended and a verified backup exists.

## Back up PostgreSQL

Run from the repository root while the database service is healthy:

```bash
./scripts/backup_postgres.sh
```

Backups are written with owner-only permissions when supported to the ignored
`backups/` directory. Move production backups to encrypted storage outside the
server and define retention independently of the application scan-log policy.

Verify that a new dump is non-empty and periodically perform a restore drill in
an isolated environment. A backup that has never been restored is unproven.

## Restore PostgreSQL

Restoration replaces the Compose database contents. Take a fresh backup first,
verify the target file, and run:

```bash
./scripts/restore_postgres.sh --confirm-replace-database backups/FILE.dump
curl --fail http://127.0.0.1:8000/health/ready/
```

The script stops the web service before restoring and restarts it only after a
successful restore. If restoration fails, inspect the database logs and keep
the web service stopped until consistency has been verified.

## Hosted deployment requirements

The checked-in Compose defaults are for localhost evaluation, not direct
internet exposure. A hosted deployment must additionally provide:

- managed PostgreSQL with encrypted backups and point-in-time recovery;
- managed or private Redis shared by every web replica;
- TLS termination at a trusted reverse proxy or platform edge;
- `DJANGO_SECURE_SSL_REDIRECT=true`, secure cookies, and an appropriate HSTS
  policy after HTTPS has been verified;
- exact allowed-host, CORS, and CSRF origin lists without wildcards;
- secrets from the platform secret manager, never image layers or Git;
- a single migration release job before rolling out web replicas;
- log collection, availability alerts, and scheduled `purge_scan_logs` runs;
- tested rollback to the previous image and a compatible database state.

Set `PHISHGUARD_NUM_PROXIES` to the exact number of trusted proxies in front of
Django. Keep the Compose value at zero because clients connect directly during
local testing.

## Candidate shadow evaluation

Leave `PHISHGUARD_ML_SHADOW_ENABLED=false` during normal use. After the frozen
future-data gate passes, enable it in a controlled environment and restart the
web service. `python manage.py check` fails closed if any v4 artifact is missing
or has a different checksum. API responses include `shadow_*` diagnostic fields
while active verdict fields remain unchanged.

Aggregate the `shadow_prediction` structured log events to review agreement and
UNKNOWN behavior. Calculate false-safe and false-phishing rates only in a
controlled labeled evaluation; the privacy-reduced operational events
intentionally contain no URL or label. Disable the flag immediately if latency
or error rates regress; this requires no database or model rollback because
shadow mode never controls the user-visible verdict.

## Incident checks

When the service is unhealthy:

1. Check `docker compose ps` and the `/health/ready/` response.
2. Inspect `web`, `database`, and `cache` logs without copying secrets.
3. Confirm migration completion and database/cache reachability.
4. Roll back the application image if the failure followed a release.
5. Restore data only when corruption or data loss is confirmed; availability
   failures alone are not a reason to overwrite a database.
