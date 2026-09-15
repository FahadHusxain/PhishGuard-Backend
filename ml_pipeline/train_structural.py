"""Train the v3 structural candidate using training/development evidence only."""

import argparse
import json
import platform
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

from ml_pipeline.audit_open import load_open_training_samples
from ml_pipeline.corpus import audit_corpus, require_training_ready
from ml_pipeline.dataset import sha256_file
from ml_pipeline.structural import (
    FEATURE_NAMES,
    StructuralCandidate,
    structural_features,
)
from ml_pipeline.train import RANDOM_SEED, _write_deterministic_npz
from ml_pipeline.train_open import (
    MIN_DECISION_PRECISION,
    _deduplicated_splits,
    _lower_threshold,
    _probability_metrics,
    _triage_metrics,
    _upper_threshold,
)

V2_DEVELOPMENT_BASELINE = {
    "roc_auc": 0.989293,
    "pr_auc": 0.985446,
    "safe_precision": 0.994485,
    "phishing_precision": 0.995693,
    "decisive_coverage": 0.670216,
}


def _serialized_trees(model: HistGradientBoostingClassifier) -> dict[str, np.ndarray]:
    values = []
    features = []
    thresholds = []
    left = []
    right = []
    is_leaf = []
    offsets = [0]
    for iteration in model._predictors:
        if len(iteration) != 1:
            raise RuntimeError("Only binary structural candidates are supported.")
        nodes = iteration[0].nodes
        if np.any(nodes["is_categorical"]):
            raise RuntimeError("Categorical tree nodes are not supported.")
        values.extend(nodes["value"])
        features.extend(nodes["feature_idx"])
        thresholds.extend(nodes["num_threshold"])
        left.extend(nodes["left"])
        right.extend(nodes["right"])
        is_leaf.extend(nodes["is_leaf"])
        offsets.append(len(values))
    return {
        "values": np.asarray(values, dtype=np.float64),
        "features": np.asarray(features, dtype=np.int32),
        "thresholds": np.asarray(thresholds, dtype=np.float64),
        "left": np.asarray(left, dtype=np.int32),
        "right": np.asarray(right, dtype=np.int32),
        "is_leaf": np.asarray(is_leaf, dtype=np.uint8),
        "offsets": np.asarray(offsets, dtype=np.int32),
    }


def train_structural(data_directory: Path, model_path: Path, report_path: Path) -> dict:
    samples, _pre_adjudication, quarantine = load_open_training_samples(data_directory)
    readiness = audit_corpus(samples)
    require_training_ready(readiness)
    splits, corpus = _deduplicated_splits(samples)
    matrices = {
        name: structural_features(split["urls"]) for name, split in splits.items()
    }
    labels = {
        name: np.asarray(split["labels"], dtype=np.int8)
        for name, split in splits.items()
    }
    model = HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_iter=150,
        max_leaf_nodes=15,
        min_samples_leaf=30,
        l2_regularization=1.0,
        class_weight="balanced",
        random_state=RANDOM_SEED,
    )
    model.fit(matrices["fit"], labels["fit"])

    calibration_scores = model.decision_function(matrices["calibration"])
    calibrator = LogisticRegression(random_state=RANDOM_SEED)
    calibrator.fit(calibration_scores.reshape(-1, 1), labels["calibration"])
    calibration_probabilities = calibrator.predict_proba(
        calibration_scores.reshape(-1, 1)
    )[:, 1]
    lower = _lower_threshold(labels["calibration"], calibration_probabilities)
    upper = _upper_threshold(labels["calibration"], calibration_probabilities)
    if lower >= upper:
        raise RuntimeError("Structural SAFE and PHISHING thresholds overlap.")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    arrays = {
        **_serialized_trees(model),
        "baseline": np.asarray(model._baseline_prediction, dtype=np.float64),
        "calibration_coefficient": calibrator.coef_.astype(np.float64),
        "calibration_intercept": calibrator.intercept_.astype(np.float64),
        "feature_names": np.asarray(FEATURE_NAMES),
        "lower_threshold": np.asarray([lower], dtype=np.float64),
        "upper_threshold": np.asarray([upper], dtype=np.float64),
    }
    _write_deterministic_npz(model_path, arrays)
    candidate = StructuralCandidate(model_path)
    for name in ("calibration", "development"):
        portable_scores = candidate.decision_function(splits[name]["urls"])
        native_scores = model.decision_function(matrices[name])
        if not np.allclose(portable_scores, native_scores, rtol=0, atol=1e-12):
            raise RuntimeError(
                "Portable structural inference differs from training model."
            )

    probabilities = {
        name: candidate.predict_probabilities(splits[name]["urls"])
        for name in ("calibration", "development")
    }
    metrics = {
        name: {
            **_probability_metrics(labels[name], probabilities[name]),
            **_triage_metrics(
                labels[name],
                probabilities[name],
                candidate.lower_threshold,
                candidate.upper_threshold,
            ),
        }
        for name in ("calibration", "development")
    }
    development_gate = {
        "safe_precision_at_least_0_995": (
            metrics["development"]["safe_precision"] >= MIN_DECISION_PRECISION
        ),
        "phishing_precision_at_least_0_995": (
            metrics["development"]["phishing_precision"] >= MIN_DECISION_PRECISION
        ),
    }
    baseline_comparison = {
        name: {
            "v2": baseline,
            "v3": metrics["development"][name],
            "delta": round(metrics["development"][name] - baseline, 6),
        }
        for name, baseline in V2_DEVELOPMENT_BASELINE.items()
    }
    split_summary = {}
    for name, split in splits.items():
        counts = Counter(split["labels"])
        split_summary[name] = {
            "rows": len(split["urls"]),
            "groups": len(split["groups"]),
            "benign": counts[0],
            "phishing": counts[1],
        }
    report = {
        "pipeline_version": 3,
        "candidate_status": "REJECTED_BY_DEVELOPMENT_EVIDENCE",
        "candidate_reason": (
            "The candidate missed the existing 99.5% precision floor on the "
            "development partition and underperformed the v2 lexical baseline."
        ),
        "opened_holdouts_used_for_training_or_selection": False,
        "model_sha256": sha256_file(model_path),
        "artifact_format": "deterministic NumPy NPZ; pickle disabled",
        "corpus": {**corpus, "quarantine": quarantine},
        "random_seed": RANDOM_SEED,
        "training_environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "features": {
            "type": "explicit URL structure; HTTPS scheme intentionally excluded",
            "count": len(FEATURE_NAMES),
            "names": list(FEATURE_NAMES),
        },
        "model": {
            "type": "histogram gradient boosting",
            "iterations": model.n_iter_,
            "max_leaf_nodes": 15,
            "max_depth": None,
        },
        "decision_policy": {
            "minimum_calibration_precision": MIN_DECISION_PRECISION,
            "lower_threshold": candidate.lower_threshold,
            "upper_threshold": candidate.upper_threshold,
        },
        "splits": split_summary,
        "calibration_metrics": metrics["calibration"],
        "development_metrics": metrics["development"],
        "development_gate": development_gate,
        "v2_development_comparison": baseline_comparison,
        "future_holdout_required_for_any_later_candidate": True,
        "promotion_ready": False,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument(
        "--model", type=Path, default=Path("ml_models/url_structural_candidate_v3.npz")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/V3_STRUCTURAL_DEVELOPMENT.json")
    )
    arguments = parser.parse_args()
    print(
        json.dumps(
            train_structural(arguments.data, arguments.model, arguments.report),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
