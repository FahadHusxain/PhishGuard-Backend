# PhishGuard URL CNN model card

## Intended use

This model provides one signal in PhishGuard's hybrid URL-risk assessment. It
must not be treated as proof that a site is safe or malicious, and it must not
be used as the sole basis for consequential decisions.

## Artifact

- File: `phishguard_cnn.h5`
- SHA-256: `53720e1fe88488578d7ee23d356f91a03a0f9a97c821f1e2ca848d282941ddb1`
- Original framework: Keras 3.12 with a TensorFlow backend
- Input: URL text with the scheme and `www.` removed, post-padded and
  post-truncated to 200 character IDs
- Architecture: embedding, one-dimensional convolution, global max pooling,
  and a sigmoid output
- Output interpretation: values closer to 1 indicate higher phishing risk

The reviewed character vocabulary is stored in `tokenizer.json`. The exact
preprocessing mode was recovered from the repository's original inference code.
Runtime code does not deserialize the original pickle because pickle loading
can execute arbitrary code.

## Runtime implementation

PhishGuard performs inference with NumPy and reads only the required weight
arrays with h5py. This reproduces the model's inference graph without requiring
the much larger TensorFlow runtime. Artifact shapes are validated before use.

## Known limitations

The repository does not include the training dataset, training script, data
split, experiment seed, evaluation report, or license/provenance record. The
sigmoid output is not known to be calibrated. Reproducing the original
preprocessing produced extreme phishing scores for many ordinary domains,
including `example.com`, `microsoft.com`, and `openai.com`. The artifact is
therefore disabled by default. It remains available for reproducible evaluation
through `PHISHGUARD_ML_ENABLED`, but it must not be enabled in a deployed
environment until it passes a representative held-out evaluation.

When explicitly enabled, the model is combined with explainable rules and an
exact-domain whitelist, and its weight is configurable.

Before claiming production accuracy, the project needs a versioned and legally
usable dataset, leakage-resistant train/validation/test splits, precision,
recall, F1, ROC-AUC, PR-AUC, calibration, false-positive analysis, and tests
against obfuscated and internationalized URLs.

Reproducible replacement experiments now exist separately; see
`LEXICAL_MODEL_CARD.md`, `STRUCTURAL_MODEL_CARD.md`, and
`ENSEMBLE_MODEL_CARD.md`. All candidate artifacts remain disabled. The lexical
model failed its frozen holdout gate, the structural model was rejected on
development evidence, and the v4 ensemble awaits a new future temporal holdout.
