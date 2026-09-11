"""Evaluate frozen v4 against a prospective, locally supplied holdout."""

import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np

from ml_pipeline.corpus import CorpusValidationError, URLSample
from ml_pipeline.dataset import sha256_file
from ml_pipeline.ensemble import EnsembleCandidate
from ml_pipeline.evaluate_v2_holdout import (
    HoldoutRecord,
    _base_rate_metrics,
    _benchmark,
    _gate_metrics,
    _prepare_records,
    _slice_summary,
    _slices,
    _training_groups,
)
from ml_pipeline.train_open import _probability_metrics, _triage_metrics

POLICY_PATH = Path(__file__).with_name("v4_future_evaluation_policy.json")
FROZEN_POLICY_SHA256 = (
    "162de53e5492c2fbae21708005805a12fdbb3b28263294c0c3d315d7b9bfdfa0"
)
SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


class FutureHoldoutError(RuntimeError):
    """Raised before scoring when prospective evidence violates its contract."""


def _timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise FutureHoldoutError(f"{field} must be an ISO 8601 timestamp.") from exc
    if parsed.utcoffset() is None:
        raise FutureHoldoutError(f"{field} must include a timezone.")
    return parsed


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FutureHoldoutError(f"Cannot read JSON contract: {path.name}.") from exc
    if not isinstance(value, dict):
        raise FutureHoldoutError(f"JSON contract must be an object: {path.name}.")
    return value


def _future_samples(
    data_directory: Path, manifest_path: Path, policy: dict
) -> tuple[list[URLSample], dict]:
    manifest = _load_json(manifest_path)
    frozen_at = _timestamp(policy["candidate_frozen_at"], "candidate_frozen_at")
    acquired_at = _timestamp(manifest.get("acquired_at"), "acquired_at")
    if manifest.get("manifest_version") != 1:
        raise FutureHoldoutError("Unsupported future holdout manifest version.")
    if manifest.get("candidate_sha256") != policy["candidate_sha256"]:
        raise FutureHoldoutError("Future snapshot is not bound to the v4 candidate.")
    if acquired_at <= frozen_at:
        raise FutureHoldoutError("Future snapshot predates the candidate freeze.")
    if not SOURCE_ID_PATTERN.fullmatch(str(manifest.get("snapshot_id", ""))):
        raise FutureHoldoutError("Future snapshot ID is invalid.")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise FutureHoldoutError("Future snapshot must declare at least one file.")

    samples = []
    file_evidence = []
    seen_sources = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise FutureHoldoutError("Every future file contract must be an object.")
        source_id = str(entry.get("source_id", ""))
        filename = str(entry.get("local_filename", ""))
        if not SOURCE_ID_PATTERN.fullmatch(source_id) or source_id in seen_sources:
            raise FutureHoldoutError("Future source IDs must be unique and stable.")
        seen_sources.add(source_id)
        if not filename or Path(filename).name != filename:
            raise FutureHoldoutError(
                "Future data filenames cannot contain directories."
            )
        if entry.get("evaluation_rights_reviewed") is not True:
            raise FutureHoldoutError(
                f"Evaluation rights are unreviewed for {source_id}."
            )
        if not str(entry.get("source_url", "")).startswith(("https://", "http://")):
            raise FutureHoldoutError(f"Official source URL is missing for {source_id}.")
        if not str(entry.get("terms_url", "")).startswith(("https://", "http://")):
            raise FutureHoldoutError(f"Terms URL is missing for {source_id}.")
        if not str(entry.get("label_method", "")).strip():
            raise FutureHoldoutError(f"Label method is missing for {source_id}.")

        path = data_directory / filename
        if not path.is_file():
            raise FutureHoldoutError(f"Future data file is missing: {filename}.")
        if path.stat().st_size != entry.get("byte_size"):
            raise FutureHoldoutError(f"Future data size mismatch: {filename}.")
        digest = sha256_file(path)
        if digest != entry.get("sha256"):
            raise FutureHoldoutError(f"Future data checksum mismatch: {filename}.")
        expected_columns = ["url", "label", "observed_at"]
        if entry.get("expected_columns") != expected_columns:
            raise FutureHoldoutError(f"Unexpected schema contract for {source_id}.")

        rows = 0
        with path.open(encoding="utf-8", newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != expected_columns:
                raise FutureHoldoutError(f"Unexpected CSV schema for {source_id}.")
            try:
                for row in reader:
                    observed_at = _timestamp(row["observed_at"], "observed_at")
                    if observed_at <= frozen_at:
                        raise FutureHoldoutError(
                            f"Non-future observation found in {source_id}."
                        )
                    if row["label"] not in {"benign", "phishing"}:
                        raise FutureHoldoutError(f"Invalid label found in {source_id}.")
                    samples.append(
                        URLSample(
                            row["url"],
                            int(row["label"] == "phishing"),
                            source_id,
                            observed_at,
                            True,
                        )
                    )
                    rows += 1
            except (KeyError, CorpusValidationError) as exc:
                raise FutureHoldoutError(
                    f"Invalid future URL row found in {source_id}."
                ) from exc
        file_evidence.append(
            {
                "source_id": source_id,
                "sha256": digest,
                "byte_size": path.stat().st_size,
                "input_rows": rows,
                "label_method": entry["label_method"],
                "evaluation_rights_reviewed": True,
            }
        )
    return samples, {
        "snapshot_id": manifest["snapshot_id"],
        "acquired_at": acquired_at.isoformat(),
        "manifest_sha256": sha256_file(manifest_path),
        "files": file_evidence,
    }


def _require_data_gate(records: list[HoldoutRecord], policy: dict) -> dict:
    contract = policy["data_contract"]
    counts = Counter(record.label for record in records)
    sources_by_label = {
        label: {
            source
            for record in records
            if record.label == label
            for source in record.sources
        }
        for label in (0, 1)
    }
    all_sources = sources_by_label[0] | sources_by_label[1]
    checks = {
        "minimum_benign_rows": counts[0] >= contract["minimum_retained_rows_per_label"],
        "minimum_phishing_rows": counts[1]
        >= contract["minimum_retained_rows_per_label"],
        "minimum_sources_total": len(all_sources)
        >= contract["minimum_independent_sources_total"],
        "minimum_benign_sources": len(sources_by_label[0])
        >= contract["minimum_independent_sources_per_label"],
        "minimum_phishing_sources": len(sources_by_label[1])
        >= contract["minimum_independent_sources_per_label"],
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise FutureHoldoutError(
            "Future holdout data gate failed: " + ", ".join(failures)
        )
    return {
        "passed": True,
        "checks": checks,
        "retained_benign": counts[0],
        "retained_phishing": counts[1],
        "sources_by_label": {
            "benign": sorted(sources_by_label[0]),
            "phishing": sorted(sources_by_label[1]),
        },
    }


def _source_reports(
    records: list[HoldoutRecord],
    labels: np.ndarray,
    probabilities: np.ndarray,
    candidate,
    policy: dict,
) -> tuple[dict, list[str]]:
    reports = {}
    failed_sources = []
    gate = policy["source_quality_gate"]
    for source in sorted({item for record in records for item in record.sources}):
        indices = [
            index for index, record in enumerate(records) if source in record.sources
        ]
        source_labels = labels[indices]
        summary = _slice_summary(
            source_labels,
            probabilities[indices],
            candidate.lower_threshold,
            candidate.upper_threshold,
        )
        benign = int((source_labels == 0).sum())
        phishing = int((source_labels == 1).sum())
        checks = {
            "minimum_retained_rows": len(indices) >= gate["minimum_retained_rows"]
        }
        if benign:
            checks["false_phishing_rate"] = (
                summary["false_phishing"] / benign
                <= gate["false_phishing_rate_at_most"]
            )
        if phishing:
            checks["false_safe_rate"] = (
                summary["false_safe"] / phishing <= gate["false_safe_rate_at_most"]
            )
        failures = [name for name, passed in checks.items() if not passed]
        reports[source] = {
            **summary,
            "gate_passed": not failures,
            "gate_failures": failures,
        }
        if failures:
            failed_sources.append(source)
    return reports, failed_sources


def evaluate_future(
    data_directory: Path,
    manifest_path: Path,
    policy_path: Path,
    model_path: Path,
    lexical_path: Path,
    structural_path: Path,
    report_path: Path,
) -> dict:
    if sha256_file(policy_path) != FROZEN_POLICY_SHA256:
        raise FutureHoldoutError("Evaluation policy does not match the frozen hash.")
    policy = _load_json(policy_path)
    if (
        sha256_file(model_path) != policy["candidate_sha256"]
        or sha256_file(lexical_path) != policy["component_sha256"]["v2_lexical"]
        or sha256_file(structural_path) != policy["component_sha256"]["v3_structural"]
    ):
        raise FutureHoldoutError("Candidate artifacts do not match the frozen policy.")
    samples, snapshot = _future_samples(data_directory, manifest_path, policy)
    records, exclusions = _prepare_records(samples, _training_groups(data_directory))
    data_gate = _require_data_gate(records, policy)

    candidate = EnsembleCandidate(model_path, lexical_path, structural_path)
    labels = np.asarray([record.label for record in records], dtype=np.int8)
    urls = [record.url for record in records]
    probabilities = np.concatenate(
        [
            candidate.predict_probabilities(urls[start : start + 10_000])
            for start in range(0, len(urls), 10_000)
        ]
    )
    metrics = {
        **_probability_metrics(labels, probabilities),
        **_triage_metrics(
            labels,
            probabilities,
            candidate.lower_threshold,
            candidate.upper_threshold,
        ),
    }
    aggregate_passed, aggregate_failures = _gate_metrics(
        metrics, policy["aggregate_gate"]
    )
    source_reports, failed_sources = _source_reports(
        records, labels, probabilities, candidate, policy
    )
    benchmark = _benchmark(candidate, urls, model_path)
    total_size = sum(
        path.stat().st_size for path in (model_path, lexical_path, structural_path)
    )
    benchmark["total_artifact_size_bytes"] = total_size
    benchmark.pop("artifact_size_bytes")
    operational_gate = policy["operational_gate"]
    operational_checks = {
        "total_artifact_size": total_size
        <= operational_gate["total_artifact_size_bytes_at_most"],
        "single_url_p95_latency": benchmark["single_url_p95_latency_ms"]
        <= operational_gate["single_url_p95_latency_ms_at_most"],
        "batch_throughput": benchmark["batch_throughput_urls_per_second"]
        >= operational_gate["batch_throughput_urls_per_second_at_least"],
    }
    operational_failures = [
        name for name, passed in operational_checks.items() if not passed
    ]
    passed = aggregate_passed and not failed_sources and not operational_failures
    report = {
        "evaluation_version": 1,
        "evaluation_type": "prospective temporal holdout; no tuning",
        "candidate_sha256": sha256_file(model_path),
        "policy_sha256": sha256_file(policy_path),
        "thresholds_changed": False,
        "snapshot": snapshot,
        "exclusions": exclusions,
        "data_gate": data_gate,
        "aggregate_metrics": metrics,
        "aggregate_gate_passed": aggregate_passed,
        "aggregate_gate_failures": aggregate_failures,
        "per_source": source_reports,
        "source_quality_gate_passed": not failed_sources,
        "source_quality_gate_failures": failed_sources,
        "realistic_prevalence": _base_rate_metrics(
            metrics, policy["realistic_prevalence_scenarios"]
        ),
        "slices": _slices(
            records,
            labels,
            probabilities,
            candidate.lower_threshold,
            candidate.upper_threshold,
            policy["data_contract"]["minimum_rows_per_reported_slice"],
        ),
        "operational": benchmark,
        "operational_gate_passed": not operational_failures,
        "operational_gate_failures": operational_failures,
        "all_automated_gates_passed": passed,
        "candidate_status": (
            "FUTURE_GATES_PASSED_AWAITING_SHADOW_REVIEW"
            if passed
            else "REJECTED_BY_FUTURE_HOLDOUT_GATE"
        ),
        "promotion_ready": False,
        "remaining_requirements": (
            policy["post_evaluation_requirements"]
            if passed
            else ["Candidate is rejected; do not retune it on this snapshot."]
        ),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument(
        "--model", type=Path, default=Path("ml_models/url_ensemble_candidate_v4.npz")
    )
    parser.add_argument(
        "--lexical", type=Path, default=Path("ml_models/url_lexical_candidate_v2.npz")
    )
    parser.add_argument(
        "--structural",
        type=Path,
        default=Path("ml_models/url_structural_candidate_v3.npz"),
    )
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/V4_FUTURE_EVALUATION.json")
    )
    arguments = parser.parse_args()
    print(
        json.dumps(
            evaluate_future(
                arguments.data,
                arguments.manifest,
                arguments.policy,
                arguments.model,
                arguments.lexical,
                arguments.structural,
                arguments.report,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
