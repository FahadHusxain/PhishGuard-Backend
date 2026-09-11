# PhishGuard v2 lexical candidate

## Status

`REJECTED_BY_HOLDOUT_GATE`. This artifact is retained as reproducible negative
evidence and is not imported by the production API. Its thresholds must not be
retuned against the now-opened holdouts.

## Intended use

The candidate estimates phishing risk from an HTTP(S) URL string. It supports
offline anti-phishing research and candidate comparison. It must not be treated
as proof that a site is safe, used as the sole control for a high-impact action,
or enabled in production without the documented promotion review.

## Data and attribution

- **PhreshPhish v1.0.1**, by Thomas Dalton, Hemanth Gowda, Girish Rao, Sachin
  Pargi, Alireza Hadj Khodabakhshi, Joseph Rombs, Stephan Jou, and Manish Marwah.
  The pinned training split is used under CC BY 4.0 for anti-phishing research.
  Only URL, label, date, and content hash metadata were projected; HTML was not
  downloaded. The published test split remains untouched.
- **PhishVN v3.1.0**, contributed by Thai Nguyen Vu, DOI
  `10.17632/b97hxbxtpd.4`. Gold/silver training rows are used under CC BY 4.0.
  Bronze rows and published validation/test rows are excluded. Upstream sources
  credited by PhishVN include NCSC Tin Nhiem Mang, ChongLuaDao, and Tranco.

Raw and projected datasets are checksum-locked and remain outside Git. The
committed readiness and development reports contain aggregate evidence only.

## Model and decision policy

- Character 3-5 gram `HashingVectorizer`, 262,144 features.
- L2-regularized linear classifier with Platt calibration.
- Deterministic label/source-stratified 70/15/15 assignment by registrable-domain
  groups; no domain crosses fit, calibration, and development partitions.
- Probability at or below `0.02485990`: SAFE.
- Probability at or above `0.98727048`: PHISHING.
- Probability between those thresholds: UNKNOWN.

The artifact is a deterministic, non-executable NumPy archive. Its SHA-256 is
`c4f10d32f8b6df65f32fb76de37d4b43278c5f94ef44ca8fdf80c079e4c6216c`.

## Internal development evidence

The 69,397-row development partition contains 39,897 benign and 29,500 phishing
URLs across 29,973 registrable-domain groups.

- ROC-AUC: 0.989293; PR-AUC: 0.985446.
- SAFE precision: 0.994485; benign recall: 0.777377.
- PHISHING precision: 0.995693; phishing recall: 0.517220.
- Decisive coverage: 0.670216; UNKNOWN rate: 0.329784.
- False-safe count: 172; false-phishing count: 66.

## Limitations and risks

- These are internal development results and may overstate performance on new
  time periods, sources, languages, brands, or adversarial URL patterns.
- URL-only classification cannot inspect page content, redirects, certificates,
  hosting history, or post-load behavior.
- PhishVN entries are mostly origin representations and are a small minority of
  this corpus; geographic and source imbalance remain possible.
- The high-precision thresholds intentionally abstain on many URLs. UNKNOWN
  requires rules, reputation evidence, or human/user caution—not a SAFE fallback.
- A phishing page can disappear or a benign domain can later be compromised;
  labels describe observations, not permanent domain truth.

## Frozen holdout decision

The unchanged candidate was tested on 94,087 unseen-domain URLs after the
pre-registered contamination exclusions. It failed SAFE precision, false-safe,
decisive-coverage, and both per-source gates. PhishVN PHISHING precision was
0.365979, demonstrating material source shift. Operational size, latency, and
throughput gates passed. The candidate is permanently rejected; see
`V2_HOLDOUT_EVALUATION.json` for aggregate evidence.

See `V2_CANDIDATE_DEVELOPMENT.json` for the machine-readable record and
`../docs/ml-upgrade-plan.md` for the remaining promotion gates.
