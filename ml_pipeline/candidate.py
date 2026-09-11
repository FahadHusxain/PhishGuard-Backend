"""Offline scoring adapter for evaluation-only lexical candidates."""

from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer


class CandidateModelError(RuntimeError):
    """Raised when a candidate artifact is incomplete or malformed."""


class LexicalCandidate:
    def __init__(self, model_path: Path):
        try:
            with np.load(model_path, allow_pickle=False) as artifact:
                self.coefficients = artifact["coefficients"].astype(np.float64)
                self.intercept = artifact["intercept"].astype(np.float64)
                self.calibration_coefficient = artifact[
                    "calibration_coefficient"
                ].astype(np.float64)
                self.calibration_intercept = artifact["calibration_intercept"].astype(
                    np.float64
                )
                self.threshold = float(artifact["threshold"].item())
                feature_count = int(artifact["feature_count"].item())
                ngram_range = tuple(int(value) for value in artifact["ngram_range"])
        except (OSError, KeyError, ValueError) as exc:
            raise CandidateModelError(
                "The lexical candidate artifact is invalid."
            ) from exc

        if (
            self.coefficients.shape != (1, feature_count)
            or self.intercept.shape != (1,)
            or self.calibration_coefficient.shape != (1, 1)
            or self.calibration_intercept.shape != (1,)
            or len(ngram_range) != 2
            or not 0.0 <= self.threshold <= 1.0
        ):
            raise CandidateModelError("The lexical candidate dimensions are invalid.")

        self.vectorizer = HashingVectorizer(
            analyzer="char",
            ngram_range=ngram_range,
            n_features=feature_count,
            alternate_sign=False,
            lowercase=True,
            norm="l2",
        )

    def predict_probability(self, url: str) -> float:
        return float(self.predict_probabilities([url])[0])

    def predict_probabilities(self, urls: list[str]) -> np.ndarray:
        features = self.vectorizer.transform(urls)
        raw_scores = np.asarray(features @ self.coefficients.T).ravel()
        raw_scores += self.intercept.item()
        calibrated_logits = (
            self.calibration_coefficient.item() * raw_scores
            + self.calibration_intercept.item()
        )
        return 1.0 / (1.0 + np.exp(-np.clip(calibrated_logits, -80.0, 80.0)))

    def predict(self, url: str) -> bool:
        return self.predict_probability(url) >= self.threshold


class V2LexicalCandidate(LexicalCandidate):
    """Three-way v2 scorer with independently frozen SAFE/PHISHING thresholds."""

    def __init__(self, model_path: Path):
        super().__init__(model_path)
        try:
            with np.load(model_path, allow_pickle=False) as artifact:
                self.lower_threshold = float(artifact["lower_threshold"].item())
                self.upper_threshold = float(artifact["upper_threshold"].item())
        except (OSError, KeyError, ValueError) as exc:
            raise CandidateModelError("The v2 lexical thresholds are invalid.") from exc
        if not 0.0 <= self.lower_threshold < self.upper_threshold <= 1.0:
            raise CandidateModelError("The v2 lexical thresholds overlap.")

    def classify(self, url: str) -> str:
        probability = self.predict_probability(url)
        if probability <= self.lower_threshold:
            return "SAFE"
        if probability >= self.upper_threshold:
            return "PHISHING"
        return "UNKNOWN"
