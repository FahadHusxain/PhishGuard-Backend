# Threat model

## Security objective

PhishGuard must analyze untrusted URL text without allowing that text or an
unauthorized caller to trigger network access, disclose private scan activity,
alter trust decisions, exhaust application resources, or corrupt audit data.

## Assets

- integrity of phishing verdicts and domain-reference records;
- administrator sessions and deployment secrets;
- scan history, IP-derived metadata, and audit actor identities;
- availability of the API, PostgreSQL, and shared throttling cache;
- integrity and provenance of ML artifacts and evaluation evidence.

## Trust boundaries

1. **Public client to application:** every URL, header, query, and JSON value is
   attacker-controlled.
2. **Reverse proxy to Django:** forwarding headers are trusted only when the
   exact proxy count is configured.
3. **Application to PostgreSQL/Redis:** private service traffic still requires
   network isolation and managed credentials in hosted environments.
4. **Staff browser to administration:** authenticated sessions cross a higher
   privilege boundary and require CSRF validation plus model permissions.
5. **Application to geolocation provider:** optional outbound metadata sharing;
   disabled by default.
6. **Training data/model to inference:** artifacts are untrusted until provenance
   and external evaluation meet the release gates.

## Threats and controls

| Threat | Example | Current controls | Residual risk / owner action |
| --- | --- | --- | --- |
| SSRF | URL points to localhost, metadata service, or private IPv6 | Core analysis never requests the submitted URL; optional geolocation resolves only globally routable addresses and contacts a fixed provider | Keep page fetching out of the API unless isolated behind a dedicated fetcher policy |
| Parser confusion | credentials, malformed ports, Unicode hostnames, trailing dots | strict serializer validation, standard URL parser, canonical IDNA hostname handling | Differential parser behavior must be regression-tested when libraries change |
| Domain-list boundary bypass | listing `example.co.uk` accidentally matches a public suffix or sibling tenant | offline public-suffix-aware candidates, private suffix support, canonical uniqueness, positive-rank filter | A listed site can later be compromised |
| Popularity mistaken for safety | a top-ranked or user-content domain causes every path to be labeled safe | detection always runs; list membership is separate context; rules-only low risk remains `UNKNOWN` | The list is contextual reputation data, not page-level ground truth |
| Unauthorized trust mutation | anonymous caller marks a phishing domain safe | active staff session, explicit add/change permissions, CSRF, separate admin throttle | Privileged account compromise remains possible; use strong passwords and platform MFA |
| Audit repudiation | administrator denies changing trust data | append-only admin presentation plus actor snapshot, reason, request ID and timestamp | Database administrators can alter records; export logs to controlled storage for stronger assurance |
| Sensitive-data disclosure | dashboard exposes submitted paths or recent targets | origin-only storage, anonymous aggregate-only statistics, permission-gated recent activity, no-store responses | Hostnames can still be sensitive; enforce retention and restrict database access |
| Stored/reflected XSS | crafted URL or domain renders executable markup | DOM `textContent`, Django escaping, no inline handlers, strict CSP and frame denial | Re-test CSP whenever third-party browser assets are introduced |
| Request exhaustion | large JSON, high request rate, regex abuse | body/field limits, bounded URL lengths, categorized throttles, linear rules, Gunicorn limits | Application throttles are not DDoS protection; enforce limits at the edge |
| Throttle evasion | forged `X-Forwarded-For` changes client identity | exact trusted-proxy count; zero for direct local access | Incorrect production proxy configuration can weaken this control |
| Cache inconsistency | stale dashboard values after writes | short TTL plus immediate and post-commit invalidation | Statistics are operational, not an accounting ledger |
| Dependency compromise | vulnerable or malicious package/image | pinned Python dependencies, dependency audit, CI container build | Base-image tags should be updated through reviewed maintenance and registry scanning |
| Model poisoning/drift | biased dataset produces confident wrong verdicts | ML disabled by default, grouped split, external evaluation, model cards, explicit promotion decision | A production-quality representative dataset is still required |
| Secret exposure | `.env`, database, or key committed to Git/image | ignore rules, example-only values, runtime injection, Docker ignore | Rotate any value that has ever entered version control or logs |
| Excessive extension privilege | browser client reads or modifies unrelated page data | user-invoked `activeTab`, no content scripts/history/cookies/web-request access, loopback-only required hosts | User still controls any optional HTTPS backend permission |
| Malicious backend response | remote response injects executable markup into popup | self-only extension CSP, bundled assets, DOM text nodes, response-shape validation | Only configure a reviewed HTTPS backend |
| Extension endpoint substitution | attacker redirects scans to an untrusted server | validated origin-only setting, remote HTTPS requirement, explicit runtime permission prompt | A user can intentionally authorize a hostile endpoint; configuration remains a trust decision |
| Data loss | operator removes volume or failed migration corrupts data | backup/restore tooling, migration gate, recovery runbook | Hosted backups and restore drills remain an operator responsibility |

## Abuse cases that must remain tested

- private and loopback IPv4/IPv6 targets;
- usernames/passwords embedded before a hostname;
- excessive subdomains, hyphens, digits, encoding, and nested redirect URLs;
- Unicode and punycode lookalike hostnames;
- invalid schemes, missing hosts, malformed ports, and oversized bodies;
- cross-tenant public/private suffixes;
- anonymous and underprivileged whitelist changes;
- forged forwarding headers and repeated requests beyond throttle limits;
- HTML/script payloads embedded in URL text or trust-search input.

## Accepted limitations

PhishGuard is currently a URL-based decision-support system. It does not inspect
page content, redirects, certificates, domain age, DNS reputation, brand logos,
or browser behavior. Consequently, a novel phishing URL can be `UNKNOWN`, and a
listed domain can host malicious content after compromise. These are explicit
product limits, not defects to hide in a demonstration.

## Review triggers

Revisit this model when adding outbound page fetching, authentication methods,
new proxy layers, third-party telemetry, file uploads, background workers, ML
artifacts, or any new category of persisted user data.
