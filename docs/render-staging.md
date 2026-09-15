# Render staging deployment

## Purpose

The staging Blueprint is deliberately separate from the owner's existing
`main` deployment. It targets `chore/modernization-foundation`, disables
automatic deploys, creates resources with staging-specific names, and cannot
merge or modify `main`.

Render's current Blueprint documentation supports Docker web services, cron
jobs, Key Value instances, PostgreSQL references, pre-deploy commands, and HTTP
health paths. Review the current specification before applying this file:

- https://render.com/docs/blueprint-spec
- https://render.com/docs/deploy-django
- https://render.com/docs/cronjobs
- https://render.com/docs/health-checks

## Cost and lifetime warning

Do not apply `render.staging.yaml` without reviewing every resource in Render's
preview. The web service uses a paid compute plan because Render documents the
pre-deploy migration command as a paid-service feature, and the cron job also
has a minimum monthly charge. Free PostgreSQL is temporary and is unsuitable
for a final production service.
Render can change plans and pricing independently of this repository.

## Create the isolated staging environment

1. In Render, create a new Blueprint and select this repository.
2. Set the Blueprint path to `render.staging.yaml`.
3. Confirm that every service uses `chore/modernization-foundation`.
4. Confirm the names end in `staging` or `staging-*` and do not match the
   existing service.
5. Enter the exact staging hostname for `DJANGO_ALLOWED_HOSTS`.
6. Enter the exact HTTPS staging origin for `DJANGO_CORS_ALLOWED_ORIGINS` and
   `DJANGO_CSRF_TRUSTED_ORIGINS`. Add a browser-extension origin only after its
   installed ID is known and tested.
7. Review costs, database expiry, region, and resource ownership before Apply.

The web health check remains `/health/ready/` so a stale optional feed does not
take the core analysis API offline. Monitor `/health/intelligence/` separately;
it returns 503 for missing, stale, empty, or unavailable feed data.

## First deployment checks

Record the exact deployed commit and run:

```bash
curl --fail https://STAGING_HOST/health/live/
curl --fail https://STAGING_HOST/health/ready/
curl --fail https://STAGING_HOST/health/intelligence/
```

Trigger the feed-sync cron job manually once. Its log must report a nonzero
indicator count and state that raw URLs were not stored. Then confirm the
intelligence health endpoint is fresh.

Test the web dashboard, API documentation, browser extension, one reviewed
official root, one ordinary URL, reserved structural-risk fixtures, malformed
input, and one current feed URL obtained directly by the operator. Do not paste
live malicious URLs into screenshots, documentation, issue trackers, or Git.

## Release boundary

Staging approval does not promote v4 ML, merge the feature branch, or authorize
production data. Keep `PHISHGUARD_ML_SHADOW_ENABLED=false`. Record monitoring,
backup, rollback, retention, operator, and extension-origin evidence before a
production decision.
