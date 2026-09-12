# Release-readiness audit

This audit records the state reviewed from modernization commit `ae3c3dc` on
2026-09-12 plus the repository-hygiene guard introduced in the same audit
phase. It is not release approval. The exact release candidate must be recorded
and rechecked after final UI review.

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

## Blocking owner decisions

1. **License:** the repository has no license file. The owner must choose the
   intended permissions and add the corresponding license; contributors cannot
   infer that legal decision.
2. **Historical secret:** the original `main` history contains a hard-coded
   Django secret that is absent from the modernized tree. It must be treated as
   compromised and must never be reused. Any environment that used it requires
   a newly generated secret. History rewriting is intentionally not attempted
   because it is disruptive and would require owner coordination.
3. **Final UI review:** desktop and extension review is not yet signed off, and
   mobile/accessibility review remains part of the final polish phase.
4. **ML promotion:** v4 remains shadow-only until a qualifying prospective
   holdout and controlled shadow review pass the frozen policy.

## Hosting-only evidence still required

- create secrets in the selected platform's secret manager;
- configure exact host, origin, proxy, TLS, resource, and edge-rate limits;
- identify the candidate image by immutable digest or commit-derived tag;
- configure monitoring, alerts, operator ownership, and retention schedules;
- create an encrypted production backup and approve its retention policy;
- document a database-compatible rollback and previous image;
- verify the exact candidate through its real HTTPS endpoint.

These items cannot be truthfully marked complete against a localhost stack.
Use the [release checklist](release-checklist.md) as the final gate and do not
merge into `main` while any required item remains open.
