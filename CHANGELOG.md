# Changelog

Significant project changes are recorded here. The modernization work remains
unreleased until its branch passes the release checklist and is explicitly
approved for merge.

## Unreleased

### Added

- Versioned `/api/v1/` contract, OpenAPI schema, and self-hosted documentation.
- Request correlation, structured production logging, liveness, and dependency
  readiness probes.
- Canonical public-suffix-aware trust matching and immutable trust audit events.
- Scan-log retention tooling and privacy-reduced origin storage.
- Reproducible ML candidate training, external evaluation, and model cards.
- Shared-cache throttling, request-size limits, and cached dashboard aggregates.
- Non-root production container and health-gated PostgreSQL/Redis Compose stack.
- Backup/restore tooling plus architecture, threat, testing, operations, and
  release documentation.
- Reproducible local Compose rehearsal evidence covering service health,
  isolation, hardening, restart recovery, and bounded concurrency.
- A CI-enforced repository hygiene check for committed secrets, environment
  files, private keys, databases, runtime data, and generated artifacts.
- Joint project authorship, an MIT license for original PhishGuard work, and
  explicit third-party dataset attribution and legacy-artifact exclusions.
- A checksum-pinned, attributed 100,000-domain Majestic Million reference
  snapshot and a deterministic builder with CI integrity validation.

### Changed

- Removed the rejected historical CNN, tokenizer, unsafe activation path, and
  runtime dependency; the auditable v4 candidate remains shadow-only.
- Replaced the untraceable historical `top1m.csv` with the attributed reference
  snapshot used by the domain loader.
- Added a conservative low-risk verdict for exact HTTPS roots in a small,
  reviewed official-platform registry while keeping all paths and popularity
  matches inconclusive unless stronger evidence exists.
- Recorded functional browser-extension review against the rebuilt Compose
  service across low-risk, inconclusive, and high-risk outcomes.
- Refined the dashboard and extension into a consistent high-contrast threat
  console and made Enter submit extension scans while Shift+Enter adds a line.
- Prevented Chromium's narrow initial popup viewport from collapsing the
  extension layout by enforcing its reviewed 400-pixel tool width.
- Rebuilt web and extension result composition around circular risk
  instruments, segmented risk vectors, case codes, and terminal-framed input.
- A provenance-aware version 2 ML corpus contract that blocks training on
  unlicensed, source-confounded, representation-mismatched, or undated data.
- A reproducible aggregate readiness audit for locally held ML sources, with
  explicit candidate-source terms and ground-truth constraints.
- A checksum-locked, URL-only open-corpus acquisition path using PhreshPhish
  and verified PhishVN training rows, with automatic ambiguous-domain quarantine.
- A reproducible v2 lexical baseline with domain-isolated balanced splits,
  dual high-precision thresholds, and an explicit UNKNOWN decision region.
- A pre-registered v2 holdout policy tied to the exact candidate hash, with
  contamination, quality, realistic-prevalence, size, and latency requirements.
- A no-tuning evaluation on published unseen-domain holdouts, preserving the
  v2 lexical candidate's rejection and aggregate error/operational evidence.
- A safe, reproducible structural-feature gradient-boosting experiment, with
  native/portable inference parity and a documented development rejection.
- A pre-registered v4 ensemble-development policy bound to exact component
  hashes, partition isolation, and a no-historical-holdout rule.
- A development-selected v4 lexical/structural ensemble with safe hash-bound
  artifacts, portable inference parity, and an explicit future-data blocker.
- A hash-bound future-evaluation policy and non-runnable manifest template that
  require prospective timestamps, defensible labels, and reviewed data rights.
- A fail-closed, no-tuning v4 future evaluator with checksum, chronology,
  provenance, contamination, source-quality, metric, and operational gates.
- A checksum-bound, NumPy-only v4 shadow runtime with training-implementation
  parity tests and privacy-reduced comparison logging that cannot change verdicts.
- A minimal-permission Chromium Manifest V3 extension for current-tab and
  pasted-link analysis, with configurable HTTPS backend access and CI checks.

### Changed

- Dashboard and extension presentation now use an original cinematic security
  operations visual system with responsive HUD details, animated analysis
  states, live counters, and reduced-motion fallbacks.
- API documentation and authenticated administration now share the same
  self-hosted, high-contrast PhishGuard command-console identity.
- Rules-only results without sufficient evidence now return `UNKNOWN` instead
  of making an unsupported claim that an arbitrary URL is safe.
- Trusted-domain imports can explicitly refresh stale existing ranks while the
  safe default continues to preserve administrator-managed entries.
- Domain-list membership is now contextual metadata and never short-circuits
  URL analysis or independently produces a `SAFE` verdict.
- Gunicorn's unused filesystem control socket is disabled so the hardened,
  read-only container starts without attempting to write under the app home.
- Whitelist mutation now requires an authorized staff session and explicit
  model permissions.
- Recent scan targets are visible only to authorized staff users.
- The browser interface uses self-hosted assets and a dedicated threat-console
  design.

### Security

- Removed exposed development secrets and unsafe production defaults.
- Added strict browser security headers, CSRF-protected administrative actions,
  stable API error envelopes, safe request limits, and proxy-aware throttling.
- Disabled the historical CNN and rejected the current candidate because the
  available evidence does not support production promotion.
