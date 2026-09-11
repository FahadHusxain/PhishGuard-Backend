"""Explicit URL-structure features and safe inference for the v3 candidate."""

import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np

from ml_pipeline.candidate import CandidateModelError

FEATURE_NAMES = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "host_dots",
    "subdomain_depth",
    "tld_length",
    "hyphens",
    "host_hyphens",
    "digits",
    "host_digits",
    "slashes",
    "percent_signs",
    "equals_signs",
    "ampersands",
    "at_signs",
    "underscores",
    "path_depth",
    "query_parameters",
    "digit_ratio",
    "special_ratio",
    "longest_token",
    "character_entropy",
    "lure_term_count",
    "ip_host",
    "punycode_host",
    "explicit_port",
)
LURE_TERMS = (
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "invoice",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def structural_features(urls: list[str]) -> np.ndarray:
    """Extract stable numeric URL features without DNS or page retrieval."""
    matrix = np.empty((len(urls), len(FEATURE_NAMES)), dtype=np.float64)
    for row_index, url in enumerate(urls):
        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise CandidateModelError(
                "Cannot extract features from malformed URL."
            ) from exc
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            raise CandidateModelError("Cannot extract features from malformed URL.")

        rendered = url.lower()
        tokens = [token for token in re.split(r"[^a-z0-9]+", rendered) if token]
        labels = hostname.strip(".").split(".")
        try:
            ipaddress.ip_address(hostname)
            ip_host = 1.0
        except ValueError:
            ip_host = 0.0
        special_count = sum(not character.isalnum() for character in rendered)
        digit_count = sum(character.isdigit() for character in rendered)
        matrix[row_index] = (
            len(rendered),
            len(hostname),
            len(parsed.path),
            len(parsed.query),
            hostname.count("."),
            max(0, len(labels) - 2),
            len(labels[-1]),
            rendered.count("-"),
            hostname.count("-"),
            digit_count,
            sum(character.isdigit() for character in hostname),
            rendered.count("/"),
            rendered.count("%"),
            rendered.count("="),
            rendered.count("&"),
            rendered.count("@"),
            rendered.count("_"),
            len([part for part in parsed.path.split("/") if part]),
            len([part for part in parsed.query.split("&") if part]),
            digit_count / len(rendered),
            special_count / len(rendered),
            max((len(token) for token in tokens), default=0),
            _entropy(rendered),
            sum(term in rendered for term in LURE_TERMS),
            ip_host,
            float(hostname.startswith("xn--") or ".xn--" in hostname),
            float(port is not None),
        )
    return matrix


class StructuralCandidate:
    """Portable three-way scorer for serialized histogram-boosting trees."""

    def __init__(self, model_path: Path):
        try:
            with np.load(model_path, allow_pickle=False) as artifact:
                names = tuple(str(value) for value in artifact["feature_names"])
                self.baseline = float(artifact["baseline"].item())
                self.values = artifact["values"].astype(np.float64)
                self.features = artifact["features"].astype(np.int32)
                self.thresholds = artifact["thresholds"].astype(np.float64)
                self.left = artifact["left"].astype(np.int32)
                self.right = artifact["right"].astype(np.int32)
                self.is_leaf = artifact["is_leaf"].astype(bool)
                self.offsets = artifact["offsets"].astype(np.int32)
                self.calibration_coefficient = float(
                    artifact["calibration_coefficient"].item()
                )
                self.calibration_intercept = float(
                    artifact["calibration_intercept"].item()
                )
                self.lower_threshold = float(artifact["lower_threshold"].item())
                self.upper_threshold = float(artifact["upper_threshold"].item())
        except (OSError, KeyError, ValueError) as exc:
            raise CandidateModelError(
                "The structural candidate artifact is invalid."
            ) from exc
        lengths = {
            len(self.values),
            len(self.features),
            len(self.thresholds),
            len(self.left),
            len(self.right),
            len(self.is_leaf),
        }
        if (
            names != FEATURE_NAMES
            or lengths != {len(self.values)}
            or len(self.offsets) < 2
            or self.offsets[0] != 0
            or self.offsets[-1] != len(self.values)
            or np.any(np.diff(self.offsets) <= 0)
            or not np.isfinite(self.baseline)
            or not np.all(np.isfinite(self.values))
            or not np.isfinite(self.calibration_coefficient)
            or not np.isfinite(self.calibration_intercept)
            or not np.isfinite(self.lower_threshold)
            or not np.isfinite(self.upper_threshold)
            or not 0 <= self.lower_threshold < self.upper_threshold <= 1
        ):
            raise CandidateModelError(
                "The structural candidate dimensions are invalid."
            )
        for start, end in zip(self.offsets[:-1], self.offsets[1:], strict=True):
            local_size = end - start
            local_indices = np.arange(local_size)
            branches = ~self.is_leaf[start:end]
            if (
                np.any(self.features[start:end][branches] < 0)
                or np.any(self.features[start:end][branches] >= len(FEATURE_NAMES))
                or not np.all(np.isfinite(self.thresholds[start:end][branches]))
                or np.any(self.left[start:end][branches] <= local_indices[branches])
                or np.any(self.right[start:end][branches] <= local_indices[branches])
                or np.any(self.left[start:end][branches] >= local_size)
                or np.any(self.right[start:end][branches] >= local_size)
            ):
                raise CandidateModelError("The structural candidate tree is invalid.")

    def decision_function(self, urls: list[str]) -> np.ndarray:
        matrix = structural_features(urls)
        scores = np.full(len(urls), self.baseline, dtype=np.float64)
        for start, _end in zip(self.offsets[:-1], self.offsets[1:], strict=True):
            nodes = np.zeros(len(urls), dtype=np.int32)
            active = np.ones(len(urls), dtype=bool)
            while active.any():
                rows = np.flatnonzero(active)
                absolute_nodes = start + nodes[rows]
                leaves = self.is_leaf[absolute_nodes]
                if leaves.any():
                    leaf_rows = rows[leaves]
                    scores[leaf_rows] += self.values[absolute_nodes[leaves]]
                    active[leaf_rows] = False
                branch_rows = rows[~leaves]
                if branch_rows.size:
                    branch_nodes = absolute_nodes[~leaves]
                    feature_values = matrix[branch_rows, self.features[branch_nodes]]
                    nodes[branch_rows] = np.where(
                        feature_values <= self.thresholds[branch_nodes],
                        self.left[branch_nodes],
                        self.right[branch_nodes],
                    )
        return scores

    def predict_probabilities(self, urls: list[str]) -> np.ndarray:
        raw_scores = self.decision_function(urls)
        logits = self.calibration_coefficient * raw_scores + self.calibration_intercept
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
