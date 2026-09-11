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

With the raw snapshots present locally, audit the eligible full-URL holdings
without training a model:

```bash
python -m ml_pipeline.audit_current
```

The generated `ml_models/CORPUS_READINESS.json` contains aggregate diagnostics
only. A failed readiness result is expected until the documented source and
licensing gaps are closed.

Acquire the pinned open corpus and generate its aggregate readiness report:

```bash
python -m pip install -r requirements-ml.txt
python -m ml_pipeline.acquire_open_corpus
python -m ml_pipeline.audit_open
```

The PhreshPhish acquisition projects URL metadata only, avoiding its 36.6 GB
HTML payload. Raw/projected data stays under ignored `.ml-data/`. The committed
`OPEN_CORPUS_READINESS.json` contains counts and gate outcomes only.

Fit and calibrate the isolated v2 lexical candidate:

```bash
python -m ml_pipeline.train_open
```

This command revalidates the corpus gate, removes canonical duplicates, and
assigns every registrable domain to exactly one deterministic, label/source-
balanced fit, calibration, or development partition. It freezes independent
SAFE and PHISHING thresholds at a 99.5% calibration precision floor and leaves
the interval between them as UNKNOWN. It never reads the published holdouts.

The resulting `url_lexical_candidate_v2.npz` is a non-executable NumPy archive.
`V2_CANDIDATE_DEVELOPMENT.json` contains aggregate development evidence only;
the candidate remains disconnected from production until all promotion gates
pass.

Evaluate the exact frozen candidate against the published holdouts once:

```bash
python -m ml_pipeline.acquire_open_corpus --include-holdout
python -m ml_pipeline.evaluate_v2_holdout
```

The evaluator verifies the candidate and policy hashes, excludes every training
domain, quarantines ambiguous holdout domains, and never changes a threshold.
It records aggregate, source, temporal, structural, realistic-prevalence, and
operational results without storing source URLs. The first v2 lexical candidate
is permanently rejected by this gate; its report remains committed as evidence.

Train the next pre-planned structural candidate without reading any holdout:

```bash
python -m ml_pipeline.train_structural
```

This experiment extracts 27 explicit, offline URL-structure features and fits
histogram gradient boosting. The trainer serializes only numeric tree arrays to
a deterministic NPZ file and verifies its portable scorer against
scikit-learn's native decisions. The v3 candidate is rejected by development
evidence: it missed the existing precision floor and underperformed v2 on all
primary internal comparison metrics. Its artifact and aggregate report remain
disconnected from production for reproducibility.
