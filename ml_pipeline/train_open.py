"""Fit and calibrate the v2 lexical candidate without opening final holdouts."""

import argparse
import hashlib
import json
import platform
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    log_loss,
    roc_auc_score,
)

from ml_pipeline.audit_open import load_open_training_samples
from ml_pipeline.corpus import (
    URLSample,
    audit_corpus,
    normalize_corpus_url,
    require_training_ready,
)
from ml_pipeline.dataset import sha256_file
from ml_pipeline.train import FEATURE_COUNT, RANDOM_SEED, _write_deterministic_npz

SPLIT_NAMES = ("fit", "calibration", "development")
SPLIT_FRACTIONS = {"fit": 0.70, "calibration": 0.15, "development": 0.15}
MIN_DECISION_PRECISION = 0.995


def _deduplicated_splits(samples: list[URLSample]) -> tuple[dict[str, dict], dict]:
    records: dict[str, tuple[int, str, set[str]]] = {}
    duplicate_rows = 0
    for sample in samples:
        normalized_url, group = normalize_corpus_url(sample.url)
        if normalized_url in records:
            previous_label, previous_group, sources = records[normalized_url]
            if previous_label != sample.label or previous_group != group:
                raise RuntimeError(
                    "Quarantined corpus still contains a label conflict."
                )
            sources.add(sample.source)
            duplicate_rows += 1
        else:
            records[normalized_url] = (sample.label, group, {sample.source})

    splits = {
        name: {"urls": [], "labels": [], "groups": set(), "sources": Counter()}
        for name in SPLIT_NAMES
    }
    groups: dict[str, dict] = {}
    for url, (label, group, sources) in records.items():
        entry = groups.setdefault(
            group,
            {"urls": [], "label": label, "source_counts": Counter()},
        )
        if entry["label"] != label:
            raise RuntimeError("Quarantined corpus still contains a domain conflict.")
        entry["urls"].append(url)
        entry["source_counts"].update(sources)

    strata: dict[tuple[int, str], list[tuple[str, dict]]] = {}
    for group, entry in groups.items():
        primary_source = min(
            entry["source_counts"],
            key=lambda source: (-entry["source_counts"][source], source),
        )
        key = (entry["label"], primary_source)
        strata.setdefault(key, []).append((group, entry))

    for stratum_groups in strata.values():
        total_rows = sum(len(entry["urls"]) for _group, entry in stratum_groups)
        assigned_rows = Counter()
        ordered_groups = sorted(
            stratum_groups,
            key=lambda item: (
                -len(item[1]["urls"]),
                hashlib.sha256(item[0].encode()).digest(),
            ),
        )
        for group, entry in ordered_groups:
            split_name = min(
                SPLIT_NAMES,
                key=lambda name: (
                    assigned_rows[name] / (total_rows * SPLIT_FRACTIONS[name]),
                    SPLIT_NAMES.index(name),
                ),
            )
            split = splits[split_name]
            urls = sorted(entry["urls"])
            split["urls"].extend(urls)
            split["labels"].extend([entry["label"]] * len(urls))
            split["groups"].add(group)
            assigned_rows[split_name] += len(urls)
            for url in urls:
                for source in records[url][2]:
                    split["sources"][source] += 1

    group_sets = [splits[name]["groups"] for name in SPLIT_NAMES]
    if any(
        group_sets[left] & group_sets[right]
        for left in range(len(group_sets))
        for right in range(left + 1, len(group_sets))
    ):
        raise RuntimeError("Registrable-domain leakage detected between splits.")
    fingerprint = hashlib.sha256()
    for url, (label, _group, _sources) in sorted(records.items()):
        fingerprint.update(f"{label}\t{url}\n".encode())
    return splits, {
        "unique_urls": len(records),
        "duplicate_rows_removed": duplicate_rows,
        "corpus_sha256": fingerprint.hexdigest(),
    }


def _upper_threshold(labels: np.ndarray, probabilities: np.ndarray) -> float:
    order = np.argsort(probabilities)[::-1]
    ordered_labels = labels[order]
    true_positives = np.cumsum(ordered_labels == 1)
    predicted = np.arange(1, len(labels) + 1)
    precision = true_positives / predicted
    group_boundaries = np.flatnonzero(
        np.r_[probabilities[order][1:] != probabilities[order][:-1], True]
    )
    eligible = group_boundaries[precision[group_boundaries] >= MIN_DECISION_PRECISION]
    if eligible.size == 0:
        raise RuntimeError("No phishing threshold meets the precision floor.")
    index = int(eligible[-1])
    return float(probabilities[order[index]])


def _lower_threshold(labels: np.ndarray, probabilities: np.ndarray) -> float:
    order = np.argsort(probabilities)
    ordered_labels = labels[order]
    true_negatives = np.cumsum(ordered_labels == 0)
    predicted = np.arange(1, len(labels) + 1)
    precision = true_negatives / predicted
    group_boundaries = np.flatnonzero(
        np.r_[probabilities[order][1:] != probabilities[order][:-1], True]
    )
    eligible = group_boundaries[precision[group_boundaries] >= MIN_DECISION_PRECISION]
    if eligible.size == 0:
        raise RuntimeError("No safe threshold meets the precision floor.")
    index = int(eligible[-1])
    return float(probabilities[order[index]])


def _triage_metrics(
    labels: np.ndarray,
    probabilities: np.ndarray,
    lower_threshold: float,
    upper_threshold: float,
) -> dict:
    safe = probabilities <= lower_threshold
    phishing = probabilities >= upper_threshold
    unknown = ~(safe | phishing)
    benign = labels == 0
    malicious = labels == 1
    safe_count = int(safe.sum())
    phishing_count = int(phishing.sum())
    return {
        "lower_threshold": round(lower_threshold, 8),
        "upper_threshold": round(upper_threshold, 8),
        "decisive_coverage": round(float((safe | phishing).mean()), 6),
        "unknown_rate": round(float(unknown.mean()), 6),
        "safe_precision": round(float((safe & benign).sum() / safe_count), 6),
        "phishing_precision": round(
            float((phishing & malicious).sum() / phishing_count), 6
        ),
        "benign_recall": round(float((safe & benign).sum() / benign.sum()), 6),
        "phishing_recall": round(
            float((phishing & malicious).sum() / malicious.sum()), 6
        ),
        "false_safe_rate": round(float((safe & malicious).sum() / malicious.sum()), 6),
        "false_phishing_rate": round(
            float((phishing & benign).sum() / benign.sum()), 6
        ),
        "counts": {
            "safe": safe_count,
            "unknown": int(unknown.sum()),
            "phishing": phishing_count,
            "false_safe": int((safe & malicious).sum()),
            "false_phishing": int((phishing & benign).sum()),
        },
    }


def _probability_metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict:
    return {
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
        "pr_auc": round(float(average_precision_score(labels, probabilities)), 6),
        "brier_score": round(float(brier_score_loss(labels, probabilities)), 6),
        "log_loss": round(float(log_loss(labels, probabilities)), 6),
    }


def train_open(data_directory: Path, model_path: Path, report_path: Path) -> dict:
    samples, _pre_adjudication, quarantine = load_open_training_samples(data_directory)
    readiness = audit_corpus(samples)
    require_training_ready(readiness)
    splits, corpus = _deduplicated_splits(samples)
    if any(set(splits[name]["labels"]) != {0, 1} for name in SPLIT_NAMES):
        raise RuntimeError("Every model partition must contain both labels.")

    vectorizer = HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=FEATURE_COUNT,
        alternate_sign=False,
        lowercase=True,
        norm="l2",
    )
    fit_labels = np.asarray(splits["fit"]["labels"], dtype=np.int8)
    classifier = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=1e-5,
        class_weight="balanced",
        max_iter=50,
        tol=1e-4,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    classifier.fit(vectorizer.transform(splits["fit"]["urls"]), fit_labels)

    calibration_labels = np.asarray(splits["calibration"]["labels"], dtype=np.int8)
    calibration_scores = classifier.decision_function(
        vectorizer.transform(splits["calibration"]["urls"])
    )
    calibrator = LogisticRegression(random_state=RANDOM_SEED)
    calibrator.fit(calibration_scores.reshape(-1, 1), calibration_labels)
    calibration_probabilities = calibrator.predict_proba(
        calibration_scores.reshape(-1, 1)
    )[:, 1]
    lower_threshold = _lower_threshold(calibration_labels, calibration_probabilities)
    upper_threshold = _upper_threshold(calibration_labels, calibration_probabilities)
    if lower_threshold >= upper_threshold:
        raise RuntimeError("Calibrated SAFE and PHISHING thresholds overlap.")

    development_labels = np.asarray(splits["development"]["labels"], dtype=np.int8)
    development_scores = classifier.decision_function(
        vectorizer.transform(splits["development"]["urls"])
    )
    development_probabilities = calibrator.predict_proba(
        development_scores.reshape(-1, 1)
    )[:, 1]

    model_path.parent.mkdir(parents=True, exist_ok=True)
    _write_deterministic_npz(
        model_path,
        {
            "calibration_coefficient": calibrator.coef_.astype(np.float32),
            "calibration_intercept": calibrator.intercept_.astype(np.float32),
            "coefficients": classifier.coef_.astype(np.float32),
            "feature_count": np.asarray([FEATURE_COUNT], dtype=np.int64),
            "intercept": classifier.intercept_.astype(np.float32),
            "lower_threshold": np.asarray([lower_threshold], dtype=np.float32),
            "ngram_range": np.asarray([3, 5], dtype=np.int64),
            "threshold": np.asarray([upper_threshold], dtype=np.float32),
            "upper_threshold": np.asarray([upper_threshold], dtype=np.float32),
        },
    )

    split_summary = {}
    for name, split in splits.items():
        labels = Counter(split["labels"])
        split_summary[name] = {
            "rows": len(split["urls"]),
            "groups": len(split["groups"]),
            "benign": labels[0],
            "phishing": labels[1],
            "source_membership": dict(sorted(split["sources"].items())),
        }

    report = {
        "pipeline_version": 2,
        "candidate_status": "NOT_PROMOTED",
        "candidate_reason": (
            "Thresholds are frozen, but published holdouts, operational slices, "
            "and shadow-mode behavior have not yet been evaluated."
        ),
        "source_manifest": "open_corpus_manifest.json",
        "readiness_report": "OPEN_CORPUS_READINESS.json",
        "artifact_format": "deterministic NumPy NPZ; pickle disabled",
        "model_sha256": sha256_file(model_path),
        "corpus": {**corpus, "quarantine": quarantine},
        "split_strategy": (
            "deterministic label/source-stratified registrable-domain groups: 70/15/15"
        ),
        "random_seed": RANDOM_SEED,
        "training_environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "features": {
            "type": "character hashing",
            "ngram_range": [3, 5],
            "feature_count": FEATURE_COUNT,
        },
        "decision_policy": {
            "minimum_calibration_precision": MIN_DECISION_PRECISION,
            "safe": "probability <= lower_threshold",
            "unknown": "lower_threshold < probability < upper_threshold",
            "phishing": "probability >= upper_threshold",
        },
        "splits": split_summary,
        "calibration_metrics": {
            **_probability_metrics(calibration_labels, calibration_probabilities),
            **_triage_metrics(
                calibration_labels,
                calibration_probabilities,
                lower_threshold,
                upper_threshold,
            ),
        },
        "development_metrics": {
            **_probability_metrics(development_labels, development_probabilities),
            **_triage_metrics(
                development_labels,
                development_probabilities,
                lower_threshold,
                upper_threshold,
            ),
        },
        "final_holdouts_opened": False,
        "promotion_gate": {
            "published_holdouts_passed": False,
            "operational_slices_passed": False,
            "latency_and_memory_passed": False,
            "shadow_review_passed": False,
        },
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument(
        "--model", type=Path, default=Path("ml_models/url_lexical_candidate_v2.npz")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/V2_CANDIDATE_DEVELOPMENT.json")
    )
    arguments = parser.parse_args()
    report = train_open(arguments.data, arguments.model, arguments.report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
