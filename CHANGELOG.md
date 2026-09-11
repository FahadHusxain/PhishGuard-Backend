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

### Changed

- Rules-only results without sufficient evidence now return `UNKNOWN` instead
  of making an unsupported claim that an arbitrary URL is safe.
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
