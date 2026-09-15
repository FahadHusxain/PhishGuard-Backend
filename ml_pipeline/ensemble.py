"""Safe inference adapter for the development-only v4 ensemble."""

from pathlib import Path

import numpy as np

from ml_pipeline.candidate import CandidateModelError, V2LexicalCandidate
from ml_pipeline.dataset import sha256_file
from ml_pipeline.structural import StructuralCandidate

ENSEMBLE_FEATURE_NAMES = (
    "v2_lexical_raw_score",
    "v3_structural_raw_score",
)


class EnsembleCandidate:
    """Load and score the non-executable v4 stacked-model artifact."""

    def __init__(
        self,
        model_path: Path,
        lexical_path: Path,
        structural_path: Path,
    ):
        try:
            with np.load(model_path, allow_pickle=False) as artifact:
                self.coefficients = artifact["coefficients"].astype(np.float64)
                self.intercept = artifact["intercept"].astype(np.float64)
                self.lower_threshold = float(artifact["lower_threshold"].item())
                self.upper_threshold = float(artifact["upper_threshold"].item())
                names = tuple(str(value) for value in artifact["feature_names"])
                lexical_sha256 = str(artifact["lexical_sha256"].item())
                structural_sha256 = str(artifact["structural_sha256"].item())
        except (OSError, KeyError, ValueError) as exc:
            raise CandidateModelError(
                "The ensemble candidate artifact is invalid."
            ) from exc
        if (
            self.coefficients.shape != (1, len(ENSEMBLE_FEATURE_NAMES))
            or self.intercept.shape != (1,)
            or names != ENSEMBLE_FEATURE_NAMES
            or not np.all(np.isfinite(self.coefficients))
            or not np.all(np.isfinite(self.intercept))
            or not 0 <= self.lower_threshold < self.upper_threshold <= 1
            or lexical_sha256 != sha256_file(lexical_path)
            or structural_sha256 != sha256_file(structural_path)
        ):
            raise CandidateModelError("The ensemble candidate contract is invalid.")
        self.lexical = V2LexicalCandidate(lexical_path)
        self.structural = StructuralCandidate(structural_path)

    def decision_function(self, urls: list[str]) -> np.ndarray:
        features = np.column_stack(
            (
                self.lexical.decision_function(urls),
                self.structural.decision_function(urls),
            )
        )
        return (
            np.asarray(features @ self.coefficients.T).ravel() + self.intercept.item()
        )

    def predict_probabilities(self, urls: list[str]) -> np.ndarray:
        logits = self.decision_function(urls)
        return 1.0 / (1.0 + np.exp(-np.clip(logits, -80.0, 80.0)))

    def predict_probability(self, url: str) -> float:
        return float(self.predict_probabilities([url])[0])

    def classify(self, url: str) -> str:
        probability = self.predict_probability(url)
        if probability <= self.lower_threshold:
            return "SAFE"
        if probability >= self.upper_threshold:
            return "PHISHING"
        return "UNKNOWN"
