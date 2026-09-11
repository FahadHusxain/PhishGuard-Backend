# PhishGuard v4 ensemble candidate model card

## Status

**Selected on development evidence; not promoted to production.** The artifact
is an offline candidate and is not imported by the production API. A genuinely
new future temporal holdout and shadow-mode review are still mandatory.

## Pre-registration and data isolation

`ml_pipeline/v4_development_policy.json` was committed before v4 was scored. It
binds the experiment to exact v2 lexical and v3 structural artifact hashes,
the open-corpus fingerprint, the model design, and numerical acceptance gates.

Both base models were fitted on the existing fit partition. The ensemble's
logistic meta-model and dual thresholds use the calibration partition; the
development partition is used only for candidate selection. Registrable domains
remain isolated between partitions. Previously opened PhreshPhish and PhishVN
holdouts were not loaded or scored.

## Method

The meta-model receives exactly two inputs: the uncalibrated raw decision score
from the v2 character n-gram model and the raw decision score from the v3
structural gradient-boosting model. Logistic regression combines and calibrates
them. Independent thresholds target 99.5% precision on calibration, with the
middle probability interval returned as UNKNOWN.

The ensemble artifact contains only coefficients, thresholds, feature names,
and component hashes in a deterministic NumPy archive. It is loaded with
`allow_pickle=False`, verifies both component files before inference, and is
tested against the native meta-model output.

## Development result

On 69,397 development URLs from isolated registrable-domain groups:

- ROC-AUC: 0.992198
- PR-AUC: 0.989797
- SAFE precision: 0.993273
- PHISHING precision: 0.994430
- Decisive coverage: 0.797960
- UNKNOWN rate: 0.202040
- False-safe rate: 0.007797
- False-phishing rate: 0.002958

All six pre-registered development gates passed. The aggregate report is in
`V4_ENSEMBLE_DEVELOPMENT.json` and contains no source URLs.

## Limitations and next gate

These are internal development results from sources already used throughout
model development. They are not an unbiased estimate of future performance and
must not be described as production accuracy. The earlier historical holdouts
cannot be reused for v4 selection because their results are already known.

V4 may advance only after an independently frozen policy is bound to a new
future temporal snapshot. If that evaluation fails, thresholds must not be
retuned against it. A passing future evaluation would still require latency,
privacy, failure-mode, and shadow-mode review before any production integration.
