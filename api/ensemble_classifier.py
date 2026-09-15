"""Dependency-light, integrity-checked inference for the frozen v4 ensemble."""

import hashlib
import re
import struct
from pathlib import Path

import numpy as np

from ml_pipeline.errors import CandidateModelError
from ml_pipeline.structural import StructuralCandidate

ENSEMBLE_FEATURE_NAMES = (
    "v2_lexical_raw_score",
    "v3_structural_raw_score",
)
EXPECTED_SHA256 = {
    "ensemble": "ecfad83fdb02552e264f609bc17992bdd95951901cd65919115a36400249cbc2",
    "lexical": "c4f10d32f8b6df65f32fb76de37d4b43278c5f94ef44ca8fdf80c079e4c6216c",
    "structural": "25bf55bb8874378837ff85412ff6e0cee8f0754bfe643e7c0a52d171eabf66aa",
}
_WHITESPACE = re.compile(r"\s\s+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _murmurhash3_32(value: bytes) -> int:
    """Return sklearn-compatible unsigned MurmurHash3 x86_32 with seed zero."""
    length = len(value)
    hash_value = 0
    rounded_end = length & ~0x3
    for offset in range(0, rounded_end, 4):
        key = struct.unpack_from("<I", value, offset)[0]
        key = (key * 0xCC9E2D51) & 0xFFFFFFFF
        key = ((key << 15) | (key >> 17)) & 0xFFFFFFFF
        key = (key * 0x1B873593) & 0xFFFFFFFF
        hash_value ^= key
        hash_value = ((hash_value << 13) | (hash_value >> 19)) & 0xFFFFFFFF
        hash_value = (hash_value * 5 + 0xE6546B64) & 0xFFFFFFFF

    key = 0
    tail = value[rounded_end:]
    if len(tail) == 3:
        key ^= tail[2] << 16
    if len(tail) >= 2:
        key ^= tail[1] << 8
    if tail:
        key ^= tail[0]
        key = (key * 0xCC9E2D51) & 0xFFFFFFFF
        key = ((key << 15) | (key >> 17)) & 0xFFFFFFFF
        key = (key * 0x1B873593) & 0xFFFFFFFF
        hash_value ^= key

    hash_value ^= length
    hash_value ^= hash_value >> 16
    hash_value = (hash_value * 0x85EBCA6B) & 0xFFFFFFFF
    hash_value ^= hash_value >> 13
    hash_value = (hash_value * 0xC2B2AE35) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    return hash_value


class PortableLexicalCandidate:
    """Score the frozen character n-gram model without scikit-learn at runtime."""

    def __init__(self, model_path: Path):
        try:
            with np.load(model_path, allow_pickle=False) as artifact:
                self.coefficients = artifact["coefficients"].astype(np.float64).ravel()
                self.intercept = float(artifact["intercept"].item())
                self.feature_count = int(artifact["feature_count"].item())
                self.ngram_range = tuple(
                    int(value) for value in artifact["ngram_range"]
                )
        except (OSError, KeyError, ValueError) as exc:
            raise CandidateModelError("The lexical artifact is invalid.") from exc
        if (
            self.coefficients.shape != (self.feature_count,)
            or self.ngram_range != (3, 5)
            or self.feature_count <= 0
            or self.feature_count & (self.feature_count - 1)
            or not np.all(np.isfinite(self.coefficients))
            or not np.isfinite(self.intercept)
        ):
            raise CandidateModelError("The lexical artifact contract is invalid.")

    def decision_function(self, url: str) -> float:
        text = _WHITESPACE.sub(" ", url.lower())
        counts: dict[int, int] = {}
        for size in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for start in range(max(0, len(text) - size + 1)):
                hash_value = _murmurhash3_32(text[start : start + size].encode("utf-8"))
                signed_hash = (
                    hash_value if hash_value < 0x80000000 else hash_value - 0x100000000
                )
                index = abs(signed_hash) % self.feature_count
                counts[index] = counts.get(index, 0) + 1
        norm = sum(count * count for count in counts.values()) ** 0.5
        if not norm:
            return self.intercept
        score = sum(self.coefficients[index] * count for index, count in counts.items())
        return float(score / norm + self.intercept)


class RuntimeEnsembleClassifier:
    """Load the exact frozen v4 bundle and expose shadow classifications."""

    def __init__(self, ensemble_path: Path, lexical_path: Path, structural_path: Path):
        paths = {
            "ensemble": Path(ensemble_path),
            "lexical": Path(lexical_path),
            "structural": Path(structural_path),
        }
        if any(_sha256(path) != EXPECTED_SHA256[name] for name, path in paths.items()):
            raise CandidateModelError("The v4 runtime artifact checksum is invalid.")
        try:
            with np.load(paths["ensemble"], allow_pickle=False) as artifact:
                self.coefficients = artifact["coefficients"].astype(np.float64).ravel()
                self.intercept = float(artifact["intercept"].item())
                self.lower_threshold = float(artifact["lower_threshold"].item())
                self.upper_threshold = float(artifact["upper_threshold"].item())
                names = tuple(str(value) for value in artifact["feature_names"])
        except (OSError, KeyError, ValueError) as exc:
            raise CandidateModelError("The v4 ensemble artifact is invalid.") from exc
        if (
            self.coefficients.shape != (2,)
            or names != ENSEMBLE_FEATURE_NAMES
            or not 0 <= self.lower_threshold < self.upper_threshold <= 1
            or not np.all(np.isfinite(self.coefficients))
            or not np.isfinite(self.intercept)
        ):
            raise CandidateModelError("The v4 ensemble contract is invalid.")
        self.lexical = PortableLexicalCandidate(paths["lexical"])
        self.structural = StructuralCandidate(paths["structural"])

    def predict_probability(self, url: str) -> float:
        features = np.asarray(
            [
                self.lexical.decision_function(url),
                float(self.structural.decision_function([url])[0]),
            ]
        )
        logit = float(features @ self.coefficients + self.intercept)
        return float(1.0 / (1.0 + np.exp(-np.clip(logit, -80.0, 80.0))))

    def classify(self, url: str) -> str:
        probability = self.predict_probability(url)
        if probability <= self.lower_threshold:
            return "SAFE"
        if probability >= self.upper_threshold:
            return "PHISHING"
        return "UNKNOWN"
