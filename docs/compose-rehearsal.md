# Local Compose rehearsal evidence

This record captures a production-shaped local rehearsal performed on
2026-09-12. It is evidence for project review, not proof that a hosted release
is production-ready.

## Environment

- Docker Engine 29.7.2
- Docker Compose v5.5.1
- application image built from `chore/modernization-foundation`
- local secrets supplied through the ignored `.env.compose` file
- ML shadow mode disabled

## Verified results

- Compose configuration validation completed without errors.
- The application and migration images built successfully.
- PostgreSQL 17 and Redis 8 reached their configured healthy states.
- The one-shot migration container exited successfully with code zero.
- Gunicorn started two threaded workers and the web container became healthy.
- The web process ran as the non-root `app` user with a read-only root
  filesystem and `no-new-privileges` enabled.
- PostgreSQL and Redis published no ports to the host; only the web service was
  bound to `127.0.0.1:8000`.
- Liveness and readiness returned `ok` and `ready`.
- Dashboard-adjacent API documentation and administration pages returned HTTP
  200 and served the PhishGuard theme assets.
- A valid HTTPS URL produced a controlled rules-only response, while a
  non-HTTP(S) URL was rejected with HTTP 400.
- A bounded 100-request, concurrency-10 liveness test completed with zero
  failures. Observed throughput was 248.14 requests/second, with 20.54 ms
  median and 198.39 ms p95 latency on this development machine.
- Restarting the web container restored readiness and retained the existing
  PostgreSQL scan count.
- The backup script produced a non-empty custom-format PostgreSQL dump. That
  dump restored successfully into a separate disposable PostgreSQL 17
  container, recovering 13 public tables, all 25 migration records, and all
  four scan rows present at backup time. The temporary database and unencrypted
  local dump were removed after verification.

The latency figures are a local smoke-test observation, not a capacity claim or
service-level objective. The restore proves local dump readability, not hosted
backup encryption, retention, or disaster recovery. Hosted deployment still
requires the controls in the [operations runbook](operations.md) and every
applicable item in the [release checklist](release-checklist.md).

## Reproduction

From the repository root, with Docker Desktop running and a reviewed local
`.env.compose` file:

```bash
docker compose --env-file .env.compose config --quiet
docker compose --env-file .env.compose up --detach --build --wait
docker compose --env-file .env.compose ps
curl --fail http://127.0.0.1:8000/health/live/
curl --fail http://127.0.0.1:8000/health/ready/
python scripts/load_test.py --base-url http://127.0.0.1:8000 \
  --requests 100 --concurrency 10
```

Stop the stack without deleting its PostgreSQL volume:

```bash
docker compose --env-file .env.compose down
```
