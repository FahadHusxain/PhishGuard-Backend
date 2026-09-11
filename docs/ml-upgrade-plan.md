# ML upgrade plan

## Safety decision

The production API remains rules-only. Version 2 work is isolated under the ML
pipeline and cannot affect a verdict until a separately reviewed promotion
changes production configuration.

The first lexical candidate is not a safe foundation for threshold tuning. Its
frozen cross-source evaluation produced a 0.999667 benign false-positive rate,
showing severe distribution shift. The external set remains evaluation-only and
must not be relabeled as training data for that candidate.

## Version 2 corpus contract

Every ingested sample must carry:

- the complete URL used as model input;
- a binary label with documented meaning;
- a stable source identifier;
- a timezone-aware observation timestamp;
- whether it is a genuine full URL, origin, or bare domain; and
- confirmation that its license or terms permit the intended training use.

Before training, canonical duplicates and conflicting labels are audited.
Training is blocked unless both labels have at least two independent sources,
at least 1,000 unique URLs, at least 95% genuine full-URL coverage, at least 80%
timestamp coverage, and complete licensing confirmation. Registrable domains
appearing under both labels require adjudication.

These are minimum integrity checks, not a guarantee that the corpus is
representative.

## Data acquisition stages

1. Preserve current PhiUSIIL, PhishTank, and Tranco snapshots exactly as frozen
   evidence.
2. Obtain documented training rights for at least two time-stamped phishing
   sources and two benign full-URL sources.
3. Store raw downloads outside Git with immutable manifests containing source
   URL, retrieval time, license, schema, size, and SHA-256.
4. Normalize only after retaining the raw checksum; reject malformed URLs and
   embedded credentials.
5. Remove exact/canonical duplicates, conflicting URL labels, and disputed
   registrable-domain labels.
6. Reserve the newest period and an untouched source for final evaluation.

Bare popularity-list domains are useful as a benign stress slice but are not
equivalent to real benign page URLs and cannot satisfy the training contract.

## Modeling ladder

Candidates are evaluated in increasing complexity:

1. character n-gram logistic baseline;
2. explicit structural-feature gradient boosting;
3. calibrated ensemble of lexical and structural models;
4. compact byte/character neural model only if earlier candidates plateau.

No neural candidate is preferred merely for being described as AI. It must
improve temporal and cross-source results enough to justify its latency, memory,
and operational complexity.

## Decision policy

The selected model will use independently calibrated lower and upper thresholds:

- probability at or below the lower threshold: SAFE;
- probability at or above the upper threshold: PHISHING;
- probability between thresholds: UNKNOWN.

Thresholds are selected on a calibration period, frozen, and evaluated once on
the final temporal/cross-source test. Whitelist handling remains explicit and
separate from learned probability.

## Required evaluation

- PR-AUC, precision, recall, false-positive rate, and confusion matrix;
- Brier score, log loss, and calibration error;
- metrics at realistic phishing prevalence, not only a balanced set;
- performance by source, month, TLD, IDN, URL length, lure terms, IP hosts,
  redirects, encoding, and previously unseen registrable domains;
- median and p95 inference latency plus peak memory;
- manual review of false positives and false negatives;
- shadow-mode comparison before any user-visible activation.

The final gate and numerical thresholds will be committed before viewing final
test labels. Failed candidates remain documented and disabled.

## Current blockers

The source registry records the current evidence:

- PhiUSIIL is licensed but has no observation timestamps.
- The frozen PhishTank snapshot is phishing-only and lacks a recorded training
  license review.
- Tranco contains domains rather than verified benign full page URLs.
- No future temporal snapshot exists yet.

Accordingly, the v2 corpus is intentionally marked training_ready false. The
next safe step is source licensing and acquisition, not model fitting.

## Candidate source decisions

The source registry distinguishes availability from permission and label
quality:

- [OpenPhish academic access](https://www.openphish.com/academic_use.html) is a
  strong candidate for a second timestamped phishing source, but requires an
  approved university application, attribution, non-commercial use, and strict
  non-redistribution controls.
- [PhishTank's developer feed](https://phishtank.org/developer_info.php) exposes
  verified full URLs and verification timestamps. It remains evaluation-only
  until written terms clearly cover model training and artifact distribution.
- [Common Crawl's URL Index](https://commoncrawl.org/url-index) provides crawl
  observations with full URLs, but crawl presence is not a benign verdict.
  Its [terms](https://commoncrawl.org/terms-of-use) also require a separate
  rights assessment. It cannot be admitted merely to make the metrics pass.

No raw third-party feed will be committed to Git. OpenPhish data, if approved,
must remain local and must not appear in test fixtures, reports, or model
documentation in reconstructable form.
