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
