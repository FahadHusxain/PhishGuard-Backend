"""Train v4 exactly as frozen in its development policy."""

import argparse
import json
import platform
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression

from ml_pipeline.audit_open import load_open_training_samples
from ml_pipeline.candidate import V2LexicalCandidate
from ml_pipeline.corpus import audit_corpus, require_training_ready
from ml_pipeline.dataset import sha256_file
from ml_pipeline.ensemble import ENSEMBLE_FEATURE_NAMES, EnsembleCandidate
from ml_pipeline.structural import StructuralCandidate
from ml_pipeline.train import _write_deterministic_npz
from ml_pipeline.train_open import (
    _deduplicated_splits,
    _lower_threshold,
    _probability_metrics,
    _triage_metrics,
    _upper_threshold,
)


def _load_policy(policy_path: Path) -> dict:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    contract = policy["partition_contract"]
    if (
        policy["candidate"] != "v4_lexical_structural_ensemble"
        or tuple(policy["meta_model"]["features"]) != ENSEMBLE_FEATURE_NAMES
        or not contract["registrable_domain_isolation_required"]
        or not contract["historical_holdouts_must_not_be_loaded"]
    ):
        raise RuntimeError("The v4 development policy contract is invalid.")
    return policy


def _component_features(
    lexical: V2LexicalCandidate,
    structural: StructuralCandidate,
    urls: list[str],
) -> np.ndarray:
    return np.column_stack(
        (lexical.decision_function(urls), structural.decision_function(urls))
    )


def _gate(metrics: dict, requirements: dict) -> tuple[dict[str, bool], list[str]]:
    results = {}
    for requirement, target in requirements.items():
        if requirement.endswith("_at_least"):
            metric = requirement.removesuffix("_at_least")
            results[requirement] = metrics[metric] >= target
        elif requirement.endswith("_at_most"):
            metric = requirement.removesuffix("_at_most")
            results[requirement] = metrics[metric] <= target
        else:
            raise RuntimeError(f"Unknown development gate: {requirement}")
    return results, [name for name, passed in results.items() if not passed]


def train_ensemble(
    data_directory: Path,
    lexical_path: Path,
    structural_path: Path,
    policy_path: Path,
    model_path: Path,
    report_path: Path,
) -> dict:
    policy = _load_policy(policy_path)
    components = policy["components"]
    if (
        sha256_file(lexical_path) != components["v2_lexical"]["sha256"]
        or sha256_file(structural_path) != components["v3_structural"]["sha256"]
    ):
        raise RuntimeError("A v4 component does not match its frozen hash.")

    samples, _pre_adjudication, quarantine = load_open_training_samples(data_directory)
    readiness = audit_corpus(samples)
    require_training_ready(readiness)
    splits, corpus = _deduplicated_splits(samples)
    if corpus["corpus_sha256"] != policy["corpus_sha256"]:
        raise RuntimeError("The v4 corpus does not match its frozen hash.")

    lexical = V2LexicalCandidate(lexical_path)
    structural = StructuralCandidate(structural_path)
    labels = {
        name: np.asarray(splits[name]["labels"], dtype=np.int8)
        for name in ("calibration", "development")
    }
    features = {
        name: _component_features(lexical, structural, splits[name]["urls"])
        for name in ("calibration", "development")
    }
    meta_policy = policy["meta_model"]
    model = LogisticRegression(
        C=meta_policy["C"],
        solver=meta_policy["solver"],
        max_iter=meta_policy["max_iter"],
        tol=meta_policy["tolerance"],
        random_state=meta_policy["random_seed"],
    )
    model.fit(features["calibration"], labels["calibration"])
    probabilities = {
        name: model.predict_proba(features[name])[:, 1]
        for name in ("calibration", "development")
    }
    lower = _lower_threshold(labels["calibration"], probabilities["calibration"])
    upper = _upper_threshold(labels["calibration"], probabilities["calibration"])
    if lower >= upper:
        raise RuntimeError("Ensemble SAFE and PHISHING thresholds overlap.")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    _write_deterministic_npz(
        model_path,
        {
            "coefficients": model.coef_.astype(np.float64),
            "intercept": model.intercept_.astype(np.float64),
            "feature_names": np.asarray(ENSEMBLE_FEATURE_NAMES),
            "lexical_sha256": np.asarray([components["v2_lexical"]["sha256"]]),
            "structural_sha256": np.asarray([components["v3_structural"]["sha256"]]),
            "lower_threshold": np.asarray([lower], dtype=np.float64),
            "upper_threshold": np.asarray([upper], dtype=np.float64),
        },
    )
    candidate = EnsembleCandidate(model_path, lexical_path, structural_path)
    for name in ("calibration", "development"):
        portable = candidate.predict_probabilities(splits[name]["urls"])
        if not np.allclose(portable, probabilities[name], rtol=0, atol=1e-12):
            raise RuntimeError(
                "Portable ensemble inference differs from training model."
            )

    metrics = {
        name: {
            **_probability_metrics(labels[name], probabilities[name]),
            **_triage_metrics(labels[name], probabilities[name], lower, upper),
        }
        for name in ("calibration", "development")
    }
    gate, failures = _gate(
        metrics["development"], policy["development_acceptance_gate"]
    )
    passed = all(gate.values())
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
        "pipeline_version": 4,
        "candidate_status": (
            "DEVELOPMENT_SELECTED_AWAITING_FUTURE_HOLDOUT"
            if passed
            else "REJECTED_BY_DEVELOPMENT_GATE"
        ),
        "candidate_reason": policy["if_gate_passes"]
        if passed
        else policy["if_gate_fails"],
        "opened_holdouts_used_for_training_or_selection": False,
        "policy_sha256": sha256_file(policy_path),
        "model_sha256": sha256_file(model_path),
        "component_sha256": {
            "v2_lexical": sha256_file(lexical_path),
            "v3_structural": sha256_file(structural_path),
        },
        "artifact_format": "deterministic NumPy NPZ; pickle disabled",
        "corpus": {**corpus, "quarantine": quarantine},
        "training_environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "meta_model": {
            **meta_policy,
            "learned_coefficients": model.coef_.ravel().tolist(),
            "learned_intercept": float(model.intercept_.item()),
        },
        "decision_policy": {
            **policy["decision_policy"],
            "lower_threshold": candidate.lower_threshold,
            "upper_threshold": candidate.upper_threshold,
        },
        "splits": split_summary,
        "calibration_metrics": metrics["calibration"],
        "development_metrics": metrics["development"],
        "development_gate": {
            "requirements": policy["development_acceptance_gate"],
            "results": gate,
            "failures": failures,
            "passed": passed,
        },
        "new_future_temporal_holdout_required": True,
        "promotion_ready": False,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument(
        "--lexical", type=Path, default=Path("ml_models/url_lexical_candidate_v2.npz")
    )
    parser.add_argument(
        "--structural",
        type=Path,
        default=Path("ml_models/url_structural_candidate_v3.npz"),
    )
    parser.add_argument(
        "--policy", type=Path, default=Path("ml_pipeline/v4_development_policy.json")
    )
    parser.add_argument(
        "--model", type=Path, default=Path("ml_models/url_ensemble_candidate_v4.npz")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/V4_ENSEMBLE_DEVELOPMENT.json")
    )
    arguments = parser.parse_args()
    print(
        json.dumps(
            train_ensemble(
                arguments.data,
                arguments.lexical,
                arguments.structural,
                arguments.policy,
                arguments.model,
                arguments.report,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
