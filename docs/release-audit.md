# Release-readiness audit

This living audit covers the modernization branch through the legal,
artifact-provenance, scoped-verdict, threat-intelligence, cross-machine, and
staging-preparation phases rechecked on 2026-09-16. It is not release approval.
The exact release-candidate SHA and its CI run must still be recorded before
merge.

## Verified locally

- The tracked working tree contains no database, private environment file,
  private key, log, cache, backup, media, or generated static directory.
- High-confidence scans of the current tracked tree found no AWS, GitHub, Slack,
  private-key, or hard-coded Django-secret signature.
- CI now repeats that repository-hygiene check on every covered push and pull
  request.
- Anonymous clients receive aggregate analytics without recent submitted
  targets and cannot mutate the domain-reference list.
- The local production-shaped Compose stack passed the health, isolation,
  migration, restart, persistence, malformed-input, and concurrency checks
  recorded in [the Compose rehearsal](compose-rehearsal.md).
- A fresh local PostgreSQL dump restored into an isolated disposable database
  with complete schema, migration history, and scan-row counts; the temporary
  unencrypted dump was removed afterward.
- The exact audit baseline passed both required GitHub Actions jobs.
- The untraceable legacy CNN, tokenizer, and popularity file are absent from
  the release tree; CI prevents their filenames from being restored.
- The replacement 100,000-domain reference is attributed, checksum-pinned,
  deterministically generated, and checked in CI.
- Exact official-platform roots use a separate reviewed registry with a
  fail-closed Django system check; popularity alone never produces `SAFE`.
- A fresh OpenPhish Community snapshot was imported locally on 2026-09-15 as
  300 SHA-256 URL digests with no raw URLs retained. An in-memory current-feed
  check returned `PHISHING` through `threat-intelligence-rules`; exact-path,
  stale-feed, disabled-mode, and replacement behavior are covered by tests.
- On 2026-09-12, Asad Abbas visually reviewed the browser-extension results
  against the rebuilt Compose service. GitHub and Facebook official roots were
  low risk, the unreviewed YTS URL was inconclusive, and the loopback URL was
  high risk with its IP-address and nonstandard-port signals explained.
- On 2026-09-16, the branch passed 158 Django tests with 77% branch-aware
  coverage against the configured 75% minimum. Ruff lint and format checks,
  Django system and hardened-deployment checks, migration drift detection,
  warning-free OpenAPI validation, documentation and repository checks,
  reference-data verification, Render Blueprint invariants, seven Node
  extension tests, and extension manifest/CSP/permission checks all passed.
- The installed Python environment reported no known vulnerabilities under
  `pip-audit --local --strict` on 2026-09-16. This is a time-bounded result and
  must be rerun for the immutable release candidate.
- Fahad Hussain independently cloned the feature branch on a second Windows
  laptop, created separate local secrets, built the Compose stack, synchronized
  the OpenPhish Community feed, and confirmed normal local operation. No secret,
  database volume, or machine-specific environment file was transferred from
  Asad Abbas's laptop.

## Blocking owner decisions

The project owners selected the MIT License for original PhishGuard work and
recorded joint authorship. Dataset attribution and artifacts excluded from that
grant are documented separately in `THIRD_PARTY_NOTICES.md`.

1. **Historical secret:** the original `main` history contains a hard-coded
   Django secret that is absent from the modernized tree. It must be treated as
   compromised and must never be reused. Any environment that used it requires
   a newly generated secret. History rewriting is intentionally not attempted
   because it is disruptive and would require owner coordination.
2. **Resolved release-tree artifact rights:** the untraceable historical CNN,
   tokenizer, and `top1m.csv` were removed. The domain reference now has an
   attributed, checksum-pinned source and deterministic transformation. The
   removed files remain in Git history and must not be restored without proof
   of origin and redistribution rights.
3. **Completed UI sign-off:** Asad Abbas reviewed the final desktop dashboard
   and extension redesign, confirmed keyboard navigation and validation
   behavior, and accepted the fixed-width popup and threat-instrument layout on
   2026-09-13. This is project review evidence, not a formal WCAG certification.
4. **ML promotion:** v4 remains shadow-only until a qualifying prospective
   holdout and controlled shadow review pass the frozen policy.

## Final local-gate status

The local code-quality, security, schema, API, extension, and reproducibility
gates are green. The tracked feature branch remains separate from `main`, and
the active verdict continues to use explainable rules plus exact current
threat-intelligence matches. Both historical ML and the v4 candidate remain
disabled for user-visible decisions.

The remaining release gate is procedural rather than a known code failure:
create an immutable candidate commit, push it, require both GitHub Actions jobs
to pass for that exact SHA, complete the final owner review, and record explicit
approval before merging. Hosted-production controls remain intentionally open
because the project currently uses the local Docker demonstration path.

## Hosting-only evidence still required

- create secrets in the selected platform's secret manager;
- configure exact host, origin, proxy, TLS, resource, and edge-rate limits;
- identify the candidate image by immutable digest or commit-derived tag;
- configure monitoring, alerts, operator ownership, and retention schedules;
- create an encrypted production backup and approve its retention policy;
- document a database-compatible rollback and previous image;
- verify the exact candidate through its real HTTPS endpoint.

An opt-in `render.staging.yaml` now describes an isolated manual-deploy staging
web service, database, cache, and 12-hour feed-sync cron job. Repository checks
enforce its feature-branch and staging-name boundaries. This is deployment
preparation only; no Render resources have been created and the hosting-only
evidence above remains open.

These items cannot be truthfully marked complete against a localhost stack.
Use the [release checklist](release-checklist.md) as the final gate and do not
merge into `main` while any required item remains open.
