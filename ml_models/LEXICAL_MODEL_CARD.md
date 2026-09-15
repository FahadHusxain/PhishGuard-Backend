# PhishGuard lexical candidate model card

## Status

**Not promoted to production.** The artifact is committed for reproducible
evaluation and does not affect API decisions.

## Dataset and attribution

The candidate was trained on the UCI Machine Learning Repository's **PhiUSIIL
Phishing URL (Website)** dataset (235,795 source rows), created by Arvind Prasad
and Shalini Chandra and made available under CC BY 4.0. The associated paper is
“PhiUSIIL: A diverse security profile empowered phishing URL detection
framework based on similarity index and incremental learning,”
https://doi.org/10.1016/j.cose.2023.103545.

The exact source URL, license, schema, and archive SHA-256 are pinned in
`ml_pipeline/dataset_manifest.json`. Raw URLs are not committed.

## Method

Only the `URL` and `label` columns are used. Page-content and derived similarity
features are excluded because the production service does not visit submitted
sites. The pipeline removes exact duplicates, removes any conflicting labels,
and assigns complete registrable-domain groups to deterministic 70/15/15
training, calibration, and test splits.

The model is a linear logistic classifier over hashed character 3–5 grams.
Platt scaling is fitted only on the calibration split. The threshold is also
selected on that split with a target of at least 98% phishing precision. The
artifact is a deterministic NumPy archive and does not deserialize executable
Python objects.

## Held-out results

The untouched grouped test split contains 34,246 URLs across 29,683 domains.
At the calibration-selected threshold:

- Precision: 0.976726
- Recall: 0.994542
- F1: 0.985554
- ROC-AUC: 0.998105
- PR-AUC: 0.998367
- False-positive rate: 0.016239

The complete machine-readable report and confusion matrix are in
`CANDIDATE_EVALUATION.json`.

## Why it is not enabled

The 98% precision gate did not hold on the untouched test split. More
importantly, a random deterministic grouped split from one historical source
does not measure temporal drift or cross-source generalization. Enabling this
candidate before an independent evaluation would turn impressive-looking
metrics into an unsupported safety claim.

A frozen no-tuning cross-source evaluation was subsequently run against 42,101
current PhishTank URLs and 42,101 Tranco domains after excluding all training
domains. It decisively failed: PR-AUC was 0.619966 and the calibration-selected
threshold produced a 0.999667 false-positive rate. See
`EXTERNAL_EVALUATION.json`. This demonstrates substantial source/distribution
shift and confirms that the candidate must not be deployed.

A future replacement requires training data from multiple independently
licensed sources, a forward-in-time holdout, manual false-positive analysis,
latency/load testing, and an audited production inference path. The frozen
external set must remain evaluation-only and must not be used to tune this
candidate.
