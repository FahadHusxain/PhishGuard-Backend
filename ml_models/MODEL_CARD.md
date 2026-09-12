# Historical PhishGuard URL CNN rejection record

## Intended use

This document records why an inherited CNN was rejected and removed. It is not
a supported model and is not present in the release tree.

## Artifact

- Historical file: `phishguard_cnn.h5` (removed)
- SHA-256: `53720e1fe88488578d7ee23d356f91a03a0f9a97c821f1e2ca848d282941ddb1`
- Original framework: Keras 3.12 with a TensorFlow backend
- Input: URL text with the scheme and `www.` removed, post-padded and
  post-truncated to 200 character IDs
- Architecture: embedding, one-dimensional convolution, global max pooling,
  and a sigmoid output
- Output interpretation: values closer to 1 indicate higher phishing risk

The historical character vocabulary was stored in `tokenizer.json` (removed). The exact
preprocessing mode was recovered from the repository's original inference code.
Runtime code does not deserialize the original pickle because pickle loading
can execute arbitrary code.

## Known limitations

The repository does not include the training dataset, training script, data
split, experiment seed, evaluation report, or license/provenance record. The
sigmoid output is not known to be calibrated. Reproducing the original
preprocessing produced extreme phishing scores for many ordinary domains,
including `example.com`, `microsoft.com`, and `openai.com`. The artifact is
therefore could not be safely shipped. The artifact, tokenizer, loader, runtime
dependency, and activation settings were removed. Their historical hashes and
rejection evidence remain here and in Git history for auditability.

Before claiming production accuracy, the project needs a versioned and legally
usable dataset, leakage-resistant train/validation/test splits, precision,
recall, F1, ROC-AUC, PR-AUC, calibration, false-positive analysis, and tests
against obfuscated and internationalized URLs.

Reproducible replacement experiments now exist separately; see
`LEXICAL_MODEL_CARD.md`, `STRUCTURAL_MODEL_CARD.md`, and
`ENSEMBLE_MODEL_CARD.md`. All candidate artifacts remain disabled. The lexical
model failed its frozen holdout gate, the structural model was rejected on
development evidence, and the v4 ensemble awaits a new future temporal holdout.
