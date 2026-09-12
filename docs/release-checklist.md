# Release checklist

This checklist is a gate, not a declaration that every branch commit is ready
for production. Complete it against one immutable candidate commit.

## Scope and evidence

- [ ] Candidate commit SHA and release version are recorded.
- [x] The project owners selected MIT for original PhishGuard work and added
      separate third-party notices and exclusions.
- [ ] Intended changes and known limitations are understandable to a reviewer.
- [ ] Architecture, threat model, API schema, model cards, and operations runbook
      match the candidate.
- [x] Final UI review is complete for the desktop dashboard and narrow browser
      extension popup, including keyboard navigation and result states.
- [ ] The historical and candidate ML models remain disabled unless a separate,
      documented promotion review has passed.

## Quality and security

- [ ] Required GitHub Actions jobs pass for the exact candidate SHA.
- [ ] Test coverage meets the configured threshold.
- [ ] No pending migrations or OpenAPI validation warnings exist.
- [ ] Installed dependencies have no known audited vulnerability.
- [ ] Secret scanning and repository inspection find no real credentials,
      environment files, databases, private scan data, or generated caches.
- [ ] Security-sensitive changes have regression tests and threat-model updates.
- [x] An authorized reviewer tested official-root, unreviewed-site, and
      high-risk structural URL cases against the rebuilt local candidate.
- [ ] An authorized reviewer has tested malformed and unsupported URL inputs.

## Deployment preparation

- [ ] Production secrets are generated in the platform secret manager.
- [ ] PostgreSQL and Redis are private, monitored, and reachable by the app.
- [ ] Allowed hosts, CORS origins, CSRF origins, and trusted proxy count are exact.
- [ ] HTTPS redirect, secure cookies, and the reviewed HSTS policy are enabled.
- [ ] A single migration job is scheduled before web rollout.
- [ ] The candidate image is identified by immutable digest or commit-derived tag.
- [ ] CPU, memory, worker count, timeouts, and edge rate limits are configured.

## Recovery and lifecycle

- [ ] A fresh encrypted backup exists and its retention policy is documented.
- [ ] Restore has succeeded in an isolated environment.
- [ ] Previous application image and database-compatible rollback procedure exist.
- [ ] Readiness alerts, error-log alerts, and an operator contact are configured.
- [ ] Daily scan-log purging is scheduled and audit-log retention is approved.

## Release and verification

- [ ] Deploy the exact reviewed candidate without rebuilding source differently.
- [ ] Apply migrations once and confirm completion.
- [ ] Confirm liveness, readiness, dashboard assets, API schema, and one benign
      analysis request through the real HTTPS endpoint.
- [ ] Confirm anonymous users cannot view recent targets or mutate trust data.
- [ ] Record the outcome and close or document every failed check.

If any required item fails, stop the release or record explicit acceptance by
the responsible project owner. Never merge the modernization branch into
`main` merely because the checklist exists.
