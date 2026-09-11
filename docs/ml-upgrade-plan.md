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

The legacy holdings remain unsuitable by themselves. The separately pinned
open corpus now passes the v2 training gate after malformed URLs and every
cross-label registrable domain are quarantined. Model promotion remains blocked
because v2 failed its frozen holdout gate and no later candidate has passed
development, a new future holdout, and shadow-mode review.

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

## Selected open corpus

- PhreshPhish v1.0.1 is pinned to an immutable repository commit. Only its
  published training shards and the `sha256`, `url`, `label`, and `date` columns
  are projected locally; captured HTML is not downloaded.
- PhishVN v3.1.0 is pinned by DOI, archive URL, byte size, and SHA-256. Only
  gold/silver rows from its published training split are admitted. Because its
  URLs are overwhelmingly synthesized origins, they are conservatively marked
  as `origin`, not genuine full-page URLs.
- The PhreshPhish test split and PhishVN validation/test splits remain untouched.

The committed aggregate readiness report records 462,644 unique retained URLs
after 4,446 invalid rows and all 340 cross-label domains were quarantined. It
contains no reconstructable source URLs.

## V2 lexical baseline

The first replacement candidate is trained only from the selected open-corpus
training rows. A deterministic, label/source-balanced group assignment keeps
every registrable domain inside exactly one 70/15/15 fit, calibration, or
development partition. Character 3-5 gram hashing and a linear classifier keep
the artifact compact, inspectable, and safe to load without pickle.

Two thresholds were frozen on calibration data at a 99.5% precision floor. On
the internal development partition, SAFE precision is 99.45%, PHISHING
precision is 99.57%, and decisive coverage is 67.02%; the remaining 32.98% is
UNKNOWN. These are development results, not a production claim. The candidate
was kept disabled before the published holdout labels were opened.

Before opening those labels, `ml_pipeline/v2_evaluation_policy.json` freezes the
candidate hash, contamination exclusions, aggregate and per-source quality
floors, realistic-prevalence scenarios, artifact-size limit, and inference
latency requirements. No threshold or model parameter may change after this
point; a failed required gate rejects the candidate rather than moving the goal.

## Frozen holdout result

The v2 lexical baseline was evaluated once, unchanged, on 94,087 canonical URLs
whose registrable domains were absent from training. The evaluator first removed
1,733 malformed rows, 75,764 training-domain overlaps, 2,374 rows from 60
cross-label domains, and 19 duplicates.

The candidate is **rejected**. Aggregate PR-AUC was 0.966290 and PHISHING
precision was 0.991727, but SAFE precision was only 0.948806, decisive coverage
was 0.476261, and the false-safe rate was 0.022278. On PhishVN specifically,
PHISHING precision fell to 0.365979. At a simulated 1% phishing prevalence,
the measured rates imply only 0.439110 PHISHING precision. The compact artifact,
single-URL latency, and batch-throughput gates passed, so the failure is model
generalization rather than deployment cost.

No threshold will be retuned against these opened holdouts. They can remain a
historical benchmark, but a materially different candidate must be developed
using training/development evidence only and must reserve a new future temporal
snapshot for final unbiased promotion evidence.

## V3 structural candidate

The second modeling-ladder candidate uses 27 explicit URL-structure features
and histogram gradient boosting. It deliberately excludes the HTTPS scheme as
a feature, performs no DNS or page retrieval, and is stored as validated
numeric tree arrays rather than an executable serialized estimator. Training
and selection used only the original fit, calibration, and development
partitions; the opened historical holdouts were not scored.

This candidate is **rejected by development evidence**. Development ROC-AUC was
0.966914, PR-AUC was 0.958649, SAFE precision was 0.987412, PHISHING precision
was 0.993417, and decisive coverage was 0.510224. Both precisions missed the
existing 99.5% target, and every primary comparison metric was below v2's
internal development result. The candidate is retained only as reproducible
research evidence and will not consume a new holdout evaluation.

The next planned experiment is a calibrated lexical/structural ensemble. It
may be selected only from training/development evidence and cannot be promoted
without a genuinely new future temporal snapshot.

Before producing any v4 scores, `ml_pipeline/v4_development_policy.json`
freezes the exact component hashes, raw-score stacking design, logistic meta
model, data-partition contract, and numerical development gate. Failure of any
required gate rejects v4 without scoring an opened historical holdout. Passing
the gate would establish only development selection, not production readiness.

## V4 ensemble development result

V4 combines the frozen lexical and structural raw scores with the exact
logistic meta-model declared in the policy. All six development gates passed.
On 69,397 domain-isolated development URLs it reached ROC-AUC 0.992198, PR-AUC
0.989797, SAFE precision 0.993273, PHISHING precision 0.994430, and decisive
coverage 0.797960. Its false-safe and false-phishing rates were 0.007797 and
0.002958. This improves on v2's internal PR-AUC and coverage while retaining
high precision.

V4 is **development-selected, not production-ready**. These sources and this
development partition are no longer unbiased evidence. The historical v2
holdouts are also prohibited because their results have been opened. The next
scientific step is to acquire and checksum a genuinely future temporal snapshot,
freeze a v4 evaluation policy before viewing its labels, then evaluate once
without threshold changes. Shadow-mode review remains required afterward.

The final evaluation rules are now frozen in
`ml_pipeline/v4_future_evaluation_policy.json`, bound to candidate commit
`b62de62` and the exact ensemble/component hashes. A future snapshot must be
acquired after that commit, every retained observation must be newer, and its
manifest must document checksums, label methods, timestamps, and reviewed
evaluation rights. `future_holdout_manifest.example.json` is deliberately
non-runnable until those facts are supplied.

PhishTank is suitable as a candidate phishing source because its official feed
contains community-verified online phishing URLs and verification timestamps.
It cannot provide benign labels. Common Crawl may supply recent URL observations,
but crawl presence is not benign ground truth and its terms place responsibility
for accuracy and third-party rights on the user. Neither source alone satisfies
the frozen evaluation contract.
