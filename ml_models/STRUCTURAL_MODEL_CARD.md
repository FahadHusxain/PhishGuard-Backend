# PhishGuard structural candidate model card

## Status

**Rejected by development evidence.** This experimental artifact is retained
for reproducibility and comparison. It is not imported by the production API
and does not affect verdicts.

## Dataset and isolation

The candidate uses the same checksum-pinned, licensed open-corpus training
rows and deterministic registrable-domain partitions as the v2 lexical
candidate. The previously opened PhreshPhish and PhishVN holdouts were not
read, scored, or used for feature or parameter selection.

## Method

The model is histogram gradient boosting over 27 explicit URL-structure
features, including lengths, punctuation, path and query structure, character
entropy, lure terms, IP hosts, punycode hosts, and explicit ports. It performs
no DNS queries or page retrieval. The HTTPS scheme itself is deliberately not
a feature because collection behavior can make it a source shortcut rather
than a durable phishing signal.

Platt calibration and independent SAFE/PHISHING thresholds are fitted on the
calibration partition at the existing 99.5% precision target. The interval
between the thresholds is UNKNOWN. Training uses pinned scikit-learn, but the
runtime experiment uses a compact deterministic NumPy archive with
`allow_pickle=False`. Tests and the trainer require its predictions to match
the native fitted estimator.

## Development result

On 69,397 development URLs from domain groups excluded from fitting and
calibration:

- ROC-AUC: 0.966914
- PR-AUC: 0.958649
- SAFE precision: 0.987412
- PHISHING precision: 0.993417
- Decisive coverage: 0.510224
- UNKNOWN rate: 0.489776

The complete aggregate report is in `V3_STRUCTURAL_DEVELOPMENT.json`. It
contains no source URLs.

## Why it was rejected

Both development precisions fell below the existing 99.5% target, and all five
primary comparison metrics were worse than the v2 lexical development result.
Opening another holdout would not rescue a candidate that already failed its
internal comparison. The artifact is therefore research evidence only.

Any later ensemble or neural candidate must be developed without tuning to the
opened historical holdouts and must reserve a genuinely new future temporal
snapshot before promotion can be considered.
