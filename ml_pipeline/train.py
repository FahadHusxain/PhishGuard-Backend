"""Train and evaluate a URL-only candidate without serializing executable code."""

import argparse
import hashlib
import io
import json
import platform
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import sklearn
from django.core.exceptions import ValidationError
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

from api.domains import normalize_hostname, registrable_domain
from ml_pipeline.dataset import acquire_archive, iter_labeled_urls, sha256_file

RANDOM_SEED = 20260911
FEATURE_COUNT = 2**18


def _group_for_url(url: str) -> str:
    try:
        hostname = normalize_hostname(urlsplit(url).hostname or "")
        return registrable_domain(hostname) or hostname
    except (TypeError, ValueError, ValidationError):
        return f"invalid:{hashlib.sha256(url.encode()).hexdigest()}"


def _split_for_group(group: str) -> str:
    bucket = (
        int.from_bytes(hashlib.sha256(group.encode("utf-8")).digest()[:8], "big") % 100
    )
    if bucket < 70:
        return "train"
    if bucket < 85:
        return "calibration"
    return "test"


def _load_splits(archive_path: Path) -> tuple[dict[str, dict], int, int, int]:
    labels_by_url: dict[str, int] = {}
    conflicting_urls: set[str] = set()
    source_rows = 0
    for url, label in iter_labeled_urls(archive_path):
        source_rows += 1
        normalized_url = url.strip()
        previous_label = labels_by_url.setdefault(normalized_url, label)
        if previous_label != label:
            conflicting_urls.add(normalized_url)

    duplicate_rows = source_rows - len(labels_by_url)
    for url in conflicting_urls:
        del labels_by_url[url]

    splits = {
        name: {"urls": [], "labels": [], "groups": set()}
        for name in ("train", "calibration", "test")
    }
    for url, label in labels_by_url.items():
        group = _group_for_url(url)
        split = splits[_split_for_group(group)]
        split["urls"].append(url)
        split["labels"].append(label)
        split["groups"].add(group)
    return splits, source_rows, duplicate_rows, len(conflicting_urls)


def _choose_threshold(labels: np.ndarray, probabilities: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(labels, probabilities)
    eligible = np.flatnonzero(precision[:-1] >= 0.98)
    if eligible.size == 0:
        return 0.5
    best_index = eligible[np.argmax(recall[eligible])]
    return float(thresholds[best_index])


def _metrics(labels: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predictions = probabilities >= threshold
    true_negative, false_positive, false_negative, true_positive = confusion_matrix(
        labels, predictions, labels=[0, 1]
    ).ravel()
    return {
        "threshold": round(threshold, 8),
        "precision": round(precision_score(labels, predictions, zero_division=0), 6),
        "recall": round(recall_score(labels, predictions, zero_division=0), 6),
        "f1": round(f1_score(labels, predictions, zero_division=0), 6),
        "roc_auc": round(roc_auc_score(labels, probabilities), 6),
        "pr_auc": round(average_precision_score(labels, probabilities), 6),
        "brier_score": round(brier_score_loss(labels, probabilities), 6),
        "log_loss": round(log_loss(labels, probabilities), 6),
        "false_positive_rate": round(
            false_positive / (false_positive + true_negative), 6
        ),
        "confusion_matrix": {
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }


def _write_deterministic_npz(path: Path, arrays: dict[str, np.ndarray]) -> None:
    """Write a compressed NumPy archive without variable ZIP timestamps."""
    temporary_path = path.with_suffix(f"{path.suffix}.part")
    try:
        with zipfile.ZipFile(
            temporary_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name in sorted(arrays):
                buffer = io.BytesIO()
                np.save(buffer, arrays[name], allow_pickle=False)
                entry = zipfile.ZipInfo(f"{name}.npy", date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o600 << 16
                archive.writestr(entry, buffer.getvalue(), compresslevel=9)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def train(archive_path: Path, model_path: Path, report_path: Path) -> dict:
    archive_path = acquire_archive(archive_path)
    splits, source_rows, duplicate_rows, conflicting_urls = _load_splits(archive_path)
    group_sets = [split["groups"] for split in splits.values()]
    if any(
        group_sets[left] & group_sets[right]
        for left in range(3)
        for right in range(left + 1, 3)
    ):
        raise RuntimeError("Registrable-domain leakage detected between splits.")

    vectorizer = HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=FEATURE_COUNT,
        alternate_sign=False,
        lowercase=True,
        norm="l2",
    )
    train_labels = np.asarray(splits["train"]["labels"], dtype=np.int8)
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
    classifier.fit(vectorizer.transform(splits["train"]["urls"]), train_labels)

    calibration_scores = classifier.decision_function(
        vectorizer.transform(splits["calibration"]["urls"])
    )
    calibration_labels = np.asarray(splits["calibration"]["labels"], dtype=np.int8)
    calibrator = LogisticRegression(random_state=RANDOM_SEED)
    calibrator.fit(calibration_scores.reshape(-1, 1), calibration_labels)
    calibration_probabilities = calibrator.predict_proba(
        calibration_scores.reshape(-1, 1)
    )[:, 1]
    threshold = _choose_threshold(calibration_labels, calibration_probabilities)

    test_scores = classifier.decision_function(
        vectorizer.transform(splits["test"]["urls"])
    )
    test_labels = np.asarray(splits["test"]["labels"], dtype=np.int8)
    test_probabilities = calibrator.predict_proba(test_scores.reshape(-1, 1))[:, 1]
    test_metrics = _metrics(test_labels, test_probabilities, threshold)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    _write_deterministic_npz(
        model_path,
        {
            "calibration_coefficient": calibrator.coef_.astype(np.float32),
            "calibration_intercept": calibrator.intercept_.astype(np.float32),
            "coefficients": classifier.coef_.astype(np.float32),
            "feature_count": np.asarray([FEATURE_COUNT], dtype=np.int64),
            "intercept": classifier.intercept_.astype(np.float32),
            "ngram_range": np.asarray([3, 5], dtype=np.int64),
            "threshold": np.asarray([threshold], dtype=np.float32),
        },
    )

    split_summary = {}
    for name, split in splits.items():
        counts = Counter(split["labels"])
        split_summary[name] = {
            "rows": len(split["urls"]),
            "groups": len(split["groups"]),
            "legitimate": counts[0],
            "phishing": counts[1],
        }

    metric_gate = {
        "precision_at_least": 0.98,
        "recall_at_least": 0.95,
        "pr_auc_at_least": 0.98,
        "false_positive_rate_at_most": 0.02,
    }
    metric_gate_passed = (
        test_metrics["precision"] >= metric_gate["precision_at_least"]
        and test_metrics["recall"] >= metric_gate["recall_at_least"]
        and test_metrics["pr_auc"] >= metric_gate["pr_auc_at_least"]
        and test_metrics["false_positive_rate"]
        <= metric_gate["false_positive_rate_at_most"]
    )
    report = {
        "pipeline_version": 1,
        "candidate_status": "NOT_PROMOTED",
        "candidate_reason": (
            "The metric gate did not pass, and a grouped single-dataset evaluation "
            "cannot establish temporal or cross-source generalization."
        ),
        "dataset_archive_sha256": sha256_file(archive_path),
        "model_sha256": sha256_file(model_path),
        "source_rows": source_rows,
        "unique_urls": sum(summary["rows"] for summary in split_summary.values()),
        "duplicate_rows_removed": duplicate_rows,
        "conflicting_urls_removed": conflicting_urls,
        "split_strategy": "SHA-256 registrable-domain groups: 70/15/15",
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
        "splits": split_summary,
        "promotion_gate": {
            **metric_gate,
            "requires_independent_or_temporal_evaluation": True,
            "metric_gate_passed": metric_gate_passed,
            "independent_or_temporal_evaluation_passed": False,
        },
        "test_metrics": test_metrics,
        "test_metrics_at_default_threshold": _metrics(
            test_labels, test_probabilities, 0.5
        ),
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, default=Path(".ml-data/phiusiil.zip"))
    parser.add_argument(
        "--model", type=Path, default=Path("ml_models/url_lexical_candidate.npz")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/CANDIDATE_EVALUATION.json")
    )
    arguments = parser.parse_args()
    report = train(arguments.archive, arguments.model, arguments.report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
