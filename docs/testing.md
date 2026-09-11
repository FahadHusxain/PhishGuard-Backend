# Testing strategy and demonstration guide

## Automated quality gate

Run from an activated project virtual environment:

```bash
python -m ruff check .
python -m ruff format --check .
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py spectacular --validate --fail-on-warn --file openapi.yml
python -m coverage run manage.py test
python -m coverage report
python -m pip check
python -m pip_audit --local --strict
python scripts/check_docs.py
```

CI repeats these checks, validates hardened deployment settings, builds the
container, starts PostgreSQL and Redis, applies migrations, waits for readiness,
and requests the ready endpoint.

## Teacher-facing URL demonstration

The scanner accepts any syntactically valid, complete HTTP(S) URL. Do not tune
the demonstration to a single memorized URL. Select examples from each class:

| Class | Example | Behavior being demonstrated |
| --- | --- | --- |
| Ordinary URL | `https://example.com/` | Accepted and analyzed without visiting the page |
| Credential lure | `http://secure-login.example/verify/account` | Multiple explainable risk signals |
| IP hostname | `http://192.0.2.10/login` | IP-address and insecure-login signals |
| Nested redirect | `https://example.com/?next=https%3A%2F%2Fevil.example` | Concealed nested URL signal |
| Deep hostname | `https://a.b.c.d.login.example/` | Excessive subdomain-depth signal |
| Internationalized hostname | `https://xn--80ak6aa92e.com/` | Punycode signal |
| Unusual port | `https://example.com:8443/login` | Nonstandard-port signal |
| Malformed input | `not a URL` | Stable validation error; no server crash |
| Unsupported scheme | `javascript:alert(1)` | Rejected before analysis |

Reserved example domains and addresses are used here so testing does not accuse
a real organization or contact an arbitrary target. For an examiner-provided
URL, the important invariants are:

- the service returns a controlled JSON result or validation error;
- it does not fetch or execute the destination;
- the response identifies the engine and explains detected signals;
- a rules-only low score is `UNKNOWN`, not a false claim of safety;
- persisted history omits path, query, fragment, and credentials.

The verdict for a previously unseen URL is not predetermined. Claims of perfect
detection would be scientifically invalid; discuss false positives, false
negatives, and the disabled ML candidate openly.

## Manual API checks

Start Django, then use a separate terminal:

```bash
curl --fail http://127.0.0.1:8000/health/live/
curl --fail http://127.0.0.1:8000/health/ready/
curl --request POST http://127.0.0.1:8000/api/v1/predict/ \
  --header "Content-Type: application/json" \
  --data '{"url":"https://example.com/login"}'
```

Inspect `/api/docs/` for the versioned contract. Exercise the dashboard at wide
and narrow viewport widths, keyboard-only navigation, empty/error/loading
states, URL analysis, and trusted-domain search.

## Bounded concurrency check

With the service running:

```bash
python scripts/load_test.py --base-url http://127.0.0.1:8000 \
  --requests 100 --concurrency 10
```

The default target is read-only. Supplying `--target` creates scan records and
is subject to analysis throttling, so use smaller counts for that mode.

## Evidence to retain

For a project demonstration or release candidate, record the tested commit SHA,
CI run URL, test count, coverage percentage, dependency-audit result, container
readiness result, date, Python version, and any accepted limitations. Do not
capture secrets, session cookies, full production URLs, or private scan data.
