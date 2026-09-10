"""Evaluate a frozen candidate against independent feeds without tuning."""

import argparse
import bz2
import csv
import io
import json
import zipfile
from pathlib import Path

import numpy as np

from ml_pipeline.candidate import LexicalCandidate
from ml_pipeline.dataset import acquire_archive, iter_labeled_urls, sha256_file
from ml_pipeline.train import _group_for_url, _metrics

MANIFEST_PATH = Path(__file__).with_name("external_evaluation_manifest.json")


def _verified_path(data_directory: Path, source: dict) -> Path:
    path = data_directory / source["local_filename"]
    if not path.is_file() or sha256_file(path) != source["sha256"]:
        raise RuntimeError(f"External source is missing or invalid: {path}")
    return path


def _training_groups(training_archive: Path) -> set[str]:
    return {_group_for_url(url) for url, _label in iter_labeled_urls(training_archive)}


def _phishing_urls(path: Path, excluded_groups: set[str]) -> tuple[list[str], set[str]]:
    urls_by_value: dict[str, None] = {}
    accepted_groups = set()
    with bz2.open(path, "rt", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            url = row["url"].strip()
            group = _group_for_url(url)
            if group not in excluded_groups:
                urls_by_value[url] = None
                accepted_groups.add(group)
    return list(urls_by_value), accepted_groups


def _benign_urls(
    path: Path,
    excluded_groups: set[str],
    target_count: int,
) -> tuple[list[str], set[str]]:
    urls = []
    accepted_groups = set()
    with (
        zipfile.ZipFile(path) as archive,
        archive.open("top-1m.csv") as binary_source,
    ):
        text_source = io.TextIOWrapper(binary_source, encoding="utf-8", newline="")
        for row in csv.reader(text_source):
            domain = row[1].strip()
            group = _group_for_url(f"https://{domain}/")
            if group in excluded_groups or group in accepted_groups:
                continue
            urls.append(f"https://{domain}/")
            accepted_groups.add(group)
            if len(urls) >= target_count:
                break
    return urls, accepted_groups


def _score_in_batches(candidate: LexicalCandidate, urls: list[str]) -> np.ndarray:
    batches = [
        candidate.predict_probabilities(urls[start : start + 10_000])
        for start in range(0, len(urls), 10_000)
    ]
    return np.concatenate(batches)


def evaluate(
    data_directory: Path,
    model_path: Path,
    report_path: Path,
) -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    training_archive = acquire_archive(data_directory / "phiusiil.zip")
    training_groups = _training_groups(training_archive)
    phishing_path = _verified_path(data_directory, manifest["sources"]["phishing"])
    benign_path = _verified_path(data_directory, manifest["sources"]["benign"])

    phishing_urls, phishing_groups = _phishing_urls(phishing_path, training_groups)
    benign_urls, benign_groups = _benign_urls(
        benign_path,
        training_groups | phishing_groups,
        len(phishing_urls),
    )
    if len(benign_urls) != len(phishing_urls):
        raise RuntimeError("Insufficient independent benign domains for evaluation.")

    candidate = LexicalCandidate(model_path)
    urls = benign_urls + phishing_urls
    labels = np.concatenate(
        [
            np.zeros(len(benign_urls), dtype=np.int8),
            np.ones(len(phishing_urls), dtype=np.int8),
        ]
    )
    probabilities = _score_in_batches(candidate, urls)
    metrics = _metrics(labels, probabilities, candidate.threshold)
    gate_passed = (
        metrics["precision"] >= 0.98
        and metrics["recall"] >= 0.95
        and metrics["false_positive_rate"] <= 0.02
        and metrics["pr_auc"] >= 0.98
    )
    report = {
        "evaluation_type": "frozen cross-source, no tuning",
        "source_manifest": MANIFEST_PATH.name,
        "model_sha256": sha256_file(model_path),
        "training_groups_excluded": len(training_groups),
        "phishing_rows": len(phishing_urls),
        "phishing_groups": len(phishing_groups),
        "benign_rows": len(benign_urls),
        "benign_groups": len(benign_groups),
        "balanced_test_prevalence": 0.5,
        "metrics": metrics,
        "metrics_at_default_threshold": _metrics(labels, probabilities, 0.5),
        "metric_gate_passed": gate_passed,
        "limitations": [
            "Tranco domains are treated as benign but individual pages were not verified.",
            "Balanced prevalence does not represent production traffic.",
            "Live feed URLs can become inactive after retrieval.",
        ],
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument(
        "--model", type=Path, default=Path("ml_models/url_lexical_candidate.npz")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/EXTERNAL_EVALUATION.json")
    )
    arguments = parser.parse_args()
    report = evaluate(arguments.data, arguments.model, arguments.report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
