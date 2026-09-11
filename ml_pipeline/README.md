# ML evaluation pipeline

This pipeline trains a URL-only lexical candidate from a checksum-pinned UCI
dataset. Raw data belongs in `.ml-data/` and must not be committed.

```bash
python -m ml_pipeline.train
```

The source label `0` is mapped to internal phishing label `1`. Exact duplicate
URLs are collapsed and conflicting labels are removed. Splits are assigned by a
stable SHA-256 hash of the registrable domain, preventing URLs from the same
site appearing in more than one split.

The training split fits a character n-gram linear classifier. The calibration
split fits Platt scaling and selects a threshold requiring at least 98% phishing
precision. The untouched test split supplies the reported metrics.

The candidate uses URL text only. It intentionally ignores the dataset's
page-content and derived similarity fields because production PhishGuard does
not fetch arbitrary pages. The artifact is a non-executable NumPy archive, not
a pickle.

For offline experiments, `LexicalCandidate` in `candidate.py` validates and
scores the generated artifact. It depends on the training-only scikit-learn
package and is deliberately not imported by the production API.

Passing this evaluation does not automatically enable the candidate. Promotion
requires a second independently sourced or temporal test set, documented false
positive review, and a compatible audited inference implementation.

`python -m ml_pipeline.evaluate_external` evaluates the frozen candidate,
without tuning, against checksum-recorded PhishTank and Tranco snapshots. Raw
feeds stay in `.ml-data/` and are not redistributed. The resulting cross-source
report is committed so the rejection decision remains reviewable.

## Version 2 safety gate

`corpus.py` defines the provenance-aware contract for the replacement corpus.
It records source, observation time, representation type, and confirmed
training rights for every sample. `audit_corpus` detects normalized conflicts,
source/label shortcuts, incomplete time coverage, and bare-domain imbalance;
`require_training_ready` prevents model fitting while any minimum gate fails.

The current source status is machine-readable in `source_registry.json`. It is
deliberately marked not ready. See the
[ML upgrade plan](../docs/ml-upgrade-plan.md) for acquisition, modeling,
calibration, and promotion stages.
