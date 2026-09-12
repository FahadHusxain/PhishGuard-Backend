# System architecture

## Purpose and scope

PhishGuard is a URL-risk decision-support service. It validates an arbitrary
HTTP(S) URL, checks canonical domain reference data, evaluates explainable lexical
and structural signals, optionally combines a qualified ML model, stores a
privacy-reduced scan record, and returns a structured verdict.

PhishGuard does not open the submitted page, download its content, execute its
scripts, or claim that a low lexical score proves a site is safe.

## Runtime topology

```mermaid
flowchart LR
    C[Browser or API client] -->|HTTPS| E[TLS edge / reverse proxy]
    E -->|HTTP + trusted proxy headers| W[Gunicorn / Django]
    W --> P[(PostgreSQL)]
    W --> R[(Shared Redis)]
    W -. optional, disabled by default .-> G[ipapi.co]
    O[Operator] -->|release job| M[Django migrations]
    M --> P
```

The checked-in Compose stack represents this topology locally without the TLS
edge. It binds the web service to loopback and does not expose database or cache
ports. Hosted environments must provide the omitted edge controls.

## Request path

```mermaid
sequenceDiagram
    participant Client
    participant Middleware
    participant API
    participant Reference as Domain reference
    participant Engine as Detection engine
    participant DB as Scan store

    Client->>Middleware: POST /api/v1/predict/ + JSON URL
    Middleware->>Middleware: request ID, size/type limits, security headers
    Middleware->>API: throttled request
    API->>API: strict URL validation and normalization
    API->>Reference: canonical hostname candidates
    Reference-->>API: listed or unlisted context
    API->>Engine: validated URL (always)
    Engine-->>API: verdict, score, engine, signals
    API->>DB: redacted origin + engine verdict
    API-->>Client: JSON result + request ID
```

A temporary scan-log write failure is logged but does not discard an
already-computed verdict. Domain-list context depends on database availability,
which is covered by the readiness probe.

## Application components

| Component | Responsibility |
| --- | --- |
| `backend/settings.py` | Environment contract, databases, cache, security and framework configuration |
| `api/middleware.py` | Request IDs, request limits, response cache controls and browser security headers |
| `api/serializers.py` | Input validation, hostname extraction, and storage redaction |
| `api/domains.py` | Canonical hostname and public-suffix-aware list candidates |
| `api/ml_logic.py` | Explainable rule scoring and optional hybrid model combination |
| `api/views.py` | API orchestration, permissions, audit creation and scan persistence |
| `api/dashboard.py` | Short-lived aggregate cache and query-efficient statistics |
| `browser-extension/` | Manifest V3 popup client for active-tab and pasted-URL analysis |
| `api/models.py` | Trusted domains, immutable audit history, and privacy-reduced scan records |
| `backend/health.py` | Liveness and database/cache readiness probes |
| `ml_pipeline/` | Reproducible candidate training and external evaluation workflow |

## Data model and classification

| Record | Stored fields | Classification | Retention |
| --- | --- | --- | --- |
| Scan log | normalized origin, verdict, confidence, optional resolved IP/country, timestamp | operationally sensitive | 30 days by default |
| Listed domain | canonical ASCII hostname and active reference rank | internal configuration | until administratively changed |
| Trust audit event | domain, action, actor identity snapshot, reason, request ID, timestamp | security audit | retain according to institutional policy |

For scan logs, the origin contains only scheme, hostname, and explicit port.
Paths, queries, fragments, and credentials are removed before persistence.
Recent target domains are hidden from anonymous dashboard users.

The browser extension is a separate presentation client. It reads the current
tab only after the user invokes the toolbar action and sends the selected URL
to the existing versioned prediction endpoint. It has no content script or
background service worker and does not alter visited pages.

## Detection decision

1. Strict parsing accepts only complete HTTP or HTTPS URLs with valid hosts.
2. Canonical hostname candidates are checked against the domain reference list.
3. Independent URL-structure rules always produce a risk score and reasons;
   list membership never bypasses detection.
4. A score at or above the configured threshold is `PHISHING`.
5. An exact HTTPS root in the small reviewed official-platform registry may be
   `SAFE` when no high-risk rule matches. This policy never extends to content
   paths, queries, fragments, nonstandard ports, or arbitrary subdomains.
6. Other rules-only analysis below the threshold is `UNKNOWN`, not `SAFE`, because
   absence of a lexical signal is not proof of safety.
7. `domain_listed` and `domain_context` provide reputation context separately;
   popularity or an administrative list entry never verifies the exact page.

The historical CNN was removed. The current v4 candidate remains shadow-only;
its limitations and evaluation evidence are recorded in the model cards.

## Availability and scaling

- Gunicorn uses bounded worker/thread counts and worker recycling.
- PostgreSQL connections are reused with health checks.
- Redis shares throttling state and dashboard aggregates across web replicas.
- Liveness tests the process; readiness tests database and cache dependencies.
- Database migrations run once before web startup in the Compose stack.
- Dashboard aggregates use two database queries and a short, invalidated cache.

Application throttling protects fair resource use. An edge proxy or hosting
platform must provide connection limits, request timeouts, and DDoS controls.

## Related documents

- [Threat model](threat-model.md)
- [Testing strategy](testing.md)
- [Operations runbook](operations.md)
- [Release checklist](release-checklist.md)
- [ML evaluation workflow](../ml_pipeline/README.md)
