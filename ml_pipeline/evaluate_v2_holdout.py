"""Evaluate the frozen v2 candidate once against published holdouts, without tuning."""

import argparse
import ipaddress
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from statistics import median
from urllib.parse import urlsplit

import numpy as np

from ml_pipeline.acquire_open_corpus import (
    acquire_phishvn,
    acquire_phreshphish_holdout,
    load_open_manifest,
)
from ml_pipeline.audit_open import (
    _phishvn_samples,
    _phreshphish_samples,
    load_open_training_samples,
)
from ml_pipeline.candidate import V2LexicalCandidate
from ml_pipeline.corpus import CorpusValidationError, URLSample, normalize_corpus_url
from ml_pipeline.dataset import sha256_file
from ml_pipeline.train_open import _probability_metrics, _triage_metrics

POLICY_PATH = Path(__file__).with_name("v2_evaluation_policy.json")
DEFAULT_MODEL_PATH = Path("ml_models/url_lexical_candidate_v2.npz")
LURE_TERMS = (
    "account",
    "confirm",
    "invoice",
    "login",
    "password",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
)


@dataclass(slots=True)
class HoldoutRecord:
    url: str
    label: int
    sources: set[str]
    observed_at: datetime | None
    group: str


def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def _training_groups(data_directory: Path) -> set[str]:
    samples, _pre_adjudication, _quarantine = load_open_training_samples(data_directory)
    return {normalize_corpus_url(sample.url)[1] for sample in samples}


def _holdout_samples(data_directory: Path, manifest: dict):
    phreshphish_path, _holdout_hash = acquire_phreshphish_holdout(
        data_directory, manifest
    )
    for sample in _phreshphish_samples(phreshphish_path):
        yield replace(sample, source="phreshphish-v1.0.1-test")

    phishvn_path = acquire_phishvn(data_directory, manifest)
    source = manifest["phishvn"]
    for split in source["holdout_splits"]:
        split_manifest = {
            "eligible_tiers": source["eligible_tiers"],
            "eligible_splits": [split],
            "csv_member": f"data/splits/url_{split}.csv",
        }
        for sample in _phishvn_samples(phishvn_path, split_manifest):
            yield replace(sample, source="phishvn-v3.1.0-holdout")


def _prepare_records(
    samples: list[URLSample], training_groups: set[str]
) -> tuple[list[HoldoutRecord], dict]:
    candidates: list[tuple[URLSample, str, str]] = []
    labels_by_group: dict[str, set[int]] = defaultdict(set)
    invalid_rows = 0
    training_overlap_rows = 0
    for sample in samples:
        try:
            normalized_url, group = normalize_corpus_url(sample.url)
        except CorpusValidationError:
            invalid_rows += 1
            continue
        if group in training_groups:
            training_overlap_rows += 1
            continue
        candidates.append((sample, normalized_url, group))
        labels_by_group[group].add(sample.label)

    ambiguous_groups = {
        group for group, labels in labels_by_group.items() if len(labels) > 1
    }
    records_by_url: dict[str, HoldoutRecord] = {}
    ambiguous_rows = 0
    duplicate_rows = 0
    for sample, normalized_url, group in candidates:
        if group in ambiguous_groups:
            ambiguous_rows += 1
            continue
        existing = records_by_url.get(normalized_url)
        if existing:
            if existing.label != sample.label:
                raise RuntimeError("Holdout URL conflict escaped domain quarantine.")
            existing.sources.add(sample.source)
            if sample.observed_at and (
                existing.observed_at is None
                or sample.observed_at > existing.observed_at
            ):
                existing.observed_at = sample.observed_at
            duplicate_rows += 1
            continue
        records_by_url[normalized_url] = HoldoutRecord(
            normalized_url,
            sample.label,
            {sample.source},
            sample.observed_at,
            group,
        )

    records = [records_by_url[url] for url in sorted(records_by_url)]
    return records, {
        "input_rows": len(samples),
        "invalid_rows": invalid_rows,
        "training_overlap_rows_removed": training_overlap_rows,
        "ambiguous_groups_quarantined": len(ambiguous_groups),
        "ambiguous_rows_quarantined": ambiguous_rows,
        "duplicate_rows_removed": duplicate_rows,
        "retained_urls": len(records),
    }


def _score(candidate: V2LexicalCandidate, urls: list[str]) -> np.ndarray:
    batches = [
        candidate.predict_probabilities(urls[start : start + 10_000])
        for start in range(0, len(urls), 10_000)
    ]
    return np.concatenate(batches)


def _slice_summary(
    labels: np.ndarray, probabilities: np.ndarray, lower: float, upper: float
) -> dict:
    benign = labels == 0
    malicious = labels == 1
    safe = probabilities <= lower
    phishing = probabilities >= upper
    unknown = ~(safe | phishing)
    safe_count = int(safe.sum())
    phishing_count = int(phishing.sum())
    return {
        "rows": len(labels),
        "benign": int(benign.sum()),
        "phishing": int(malicious.sum()),
        "safe": safe_count,
        "unknown": int(unknown.sum()),
        "predicted_phishing": phishing_count,
        "safe_precision": (
            round(float((safe & benign).sum() / safe_count), 6) if safe_count else None
        ),
        "phishing_precision": (
            round(float((phishing & malicious).sum() / phishing_count), 6)
            if phishing_count
            else None
        ),
        "false_safe": int((safe & malicious).sum()),
        "false_phishing": int((phishing & benign).sum()),
    }


def _slice_key(record: HoldoutRecord, family: str) -> str:
    parsed = urlsplit(record.url)
    hostname = parsed.hostname or ""
    if family == "month":
        return record.observed_at.strftime("%Y-%m") if record.observed_at else "unknown"
    if family == "length":
        length = len(record.url)
        if length <= 50:
            return "000-050"
        if length <= 100:
            return "051-100"
        if length <= 200:
            return "101-200"
        return "201-plus"
    if family == "host_type":
        try:
            ipaddress.ip_address(hostname)
            return "ip"
        except ValueError:
            return (
                "idn"
                if hostname.startswith("xn--") or ".xn--" in hostname
                else "domain"
            )
    if family == "scheme":
        return parsed.scheme.lower()
    if family == "query":
        return "present" if parsed.query else "absent"
    if family == "lure_terms":
        searchable = f"{parsed.path}?{parsed.query}".lower()
        return "present" if any(term in searchable for term in LURE_TERMS) else "absent"
    if family == "tld":
        return hostname.rsplit(".", 1)[-1].lower() if "." in hostname else "none"
    raise ValueError(f"Unknown slice family: {family}")


def _slices(
    records: list[HoldoutRecord],
    labels: np.ndarray,
    probabilities: np.ndarray,
    lower: float,
    upper: float,
    minimum_rows: int,
) -> dict:
    result = {}
    for family in (
        "month",
        "length",
        "host_type",
        "scheme",
        "query",
        "lure_terms",
        "tld",
    ):
        indices_by_key: dict[str, list[int]] = defaultdict(list)
        for index, record in enumerate(records):
            indices_by_key[_slice_key(record, family)].append(index)
        family_report = {}
        for key, indices in sorted(indices_by_key.items()):
            if len(indices) < minimum_rows:
                continue
            family_report[key] = _slice_summary(
                labels[indices], probabilities[indices], lower, upper
            )
        result[family] = family_report
    return result


def _base_rate_metrics(metrics: dict, prevalences: list[float]) -> list[dict]:
    false_safe_rate = metrics["false_safe_rate"]
    false_phishing_rate = metrics["false_phishing_rate"]
    benign_recall = metrics["benign_recall"]
    phishing_recall = metrics["phishing_recall"]
    scenarios = []
    for prevalence in prevalences:
        phishing_denominator = (
            prevalence * phishing_recall + (1 - prevalence) * false_phishing_rate
        )
        safe_denominator = (
            1 - prevalence
        ) * benign_recall + prevalence * false_safe_rate
        scenarios.append(
            {
                "phishing_prevalence": prevalence,
                "estimated_phishing_precision": round(
                    prevalence * phishing_recall / phishing_denominator, 6
                ),
                "estimated_safe_precision": round(
                    (1 - prevalence) * benign_recall / safe_denominator, 6
                ),
            }
        )
    return scenarios


def _gate_metrics(metrics: dict, gate: dict) -> tuple[bool, list[str]]:
    checks = {
        "pr_auc": metrics["pr_auc"] >= gate["pr_auc_at_least"],
        "safe_precision": metrics["safe_precision"] >= gate["safe_precision_at_least"],
        "phishing_precision": metrics["phishing_precision"]
        >= gate["phishing_precision_at_least"],
        "decisive_coverage": metrics["decisive_coverage"]
        >= gate["decisive_coverage_at_least"],
        "false_safe_rate": metrics["false_safe_rate"]
        <= gate["false_safe_rate_at_most"],
        "false_phishing_rate": metrics["false_phishing_rate"]
        <= gate["false_phishing_rate_at_most"],
    }
    failures = [name for name, passed in checks.items() if not passed]
    return not failures, failures


def _benchmark(
    candidate: V2LexicalCandidate, urls: list[str], model_path: Path
) -> dict:
    benchmark_urls = urls[: min(len(urls), 10_000)]
    for url in benchmark_urls[:100]:
        candidate.predict_probability(url)
    single_durations = []
    for url in benchmark_urls[:1000]:
        started = time.perf_counter_ns()
        candidate.predict_probability(url)
        single_durations.append((time.perf_counter_ns() - started) / 1_000_000)
    started = time.perf_counter()
    _score(candidate, benchmark_urls)
    batch_seconds = time.perf_counter() - started
    return {
        "artifact_size_bytes": model_path.stat().st_size,
        "single_url_median_latency_ms": round(median(single_durations), 6),
        "single_url_p95_latency_ms": round(
            float(np.percentile(single_durations, 95)), 6
        ),
        "batch_rows": len(benchmark_urls),
        "batch_throughput_urls_per_second": round(
            len(benchmark_urls) / batch_seconds, 2
        ),
    }


def evaluate_holdouts(
    data_directory: Path, model_path: Path, report_path: Path
) -> dict:
    policy = load_policy()
    if sha256_file(model_path) != policy["candidate_sha256"]:
        raise RuntimeError("Candidate hash does not match the pre-registered policy.")
    manifest = load_open_manifest()
    records, exclusions = _prepare_records(
        list(_holdout_samples(data_directory, manifest)),
        _training_groups(data_directory),
    )
    labels = np.asarray([record.label for record in records], dtype=np.int8)
    if set(labels.tolist()) != {0, 1}:
        raise RuntimeError("Retained holdout must contain both labels.")
    candidate = V2LexicalCandidate(model_path)
    probabilities = _score(candidate, [record.url for record in records])
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

    source_reports = {}
    source_gate_failures = []
    source_gate = policy["per_source_gate"]
    for source in sorted({source for record in records for source in record.sources}):
        indices = [
            index for index, record in enumerate(records) if source in record.sources
        ]
        source_labels = labels[indices]
        source_probabilities = probabilities[indices]
        counts = Counter(source_labels.tolist())
        if min(counts[0], counts[1]) < source_gate["minimum_rows_per_label"]:
            source_reports[source] = {
                "rows": len(indices),
                "benign": counts[0],
                "phishing": counts[1],
                "gate_passed": False,
                "gate_failures": ["minimum_rows_per_label"],
            }
            source_gate_failures.append(source)
            continue
        source_metrics = {
            **_probability_metrics(source_labels, source_probabilities),
            **_triage_metrics(
                source_labels,
                source_probabilities,
                candidate.lower_threshold,
                candidate.upper_threshold,
            ),
        }
        source_checks = {
            "roc_auc": source_metrics["roc_auc"] >= source_gate["roc_auc_at_least"],
            "safe_precision": source_metrics["safe_precision"]
            >= source_gate["safe_precision_at_least"],
            "phishing_precision": source_metrics["phishing_precision"]
            >= source_gate["phishing_precision_at_least"],
        }
        failures = [name for name, passed in source_checks.items() if not passed]
        source_reports[source] = {
            "rows": len(indices),
            "benign": counts[0],
            "phishing": counts[1],
            **source_metrics,
            "gate_passed": not failures,
            "gate_failures": failures,
        }
        if failures:
            source_gate_failures.append(source)

    benchmark = _benchmark(candidate, [record.url for record in records], model_path)
    operational_gate = policy["operational_gate"]
    operational_checks = {
        "artifact_size": benchmark["artifact_size_bytes"]
        <= operational_gate["artifact_size_bytes_at_most"],
        "single_url_p95_latency": benchmark["single_url_p95_latency_ms"]
        <= operational_gate["single_url_p95_latency_ms_at_most"],
        "batch_throughput": benchmark["batch_throughput_urls_per_second"]
        >= operational_gate["batch_throughput_urls_per_second_at_least"],
    }
    operational_failures = [
        name for name, passed in operational_checks.items() if not passed
    ]
    all_required_gates_passed = (
        aggregate_passed and not source_gate_failures and not operational_failures
    )
    report = {
        "evaluation_version": 1,
        "evaluation_type": "frozen published holdouts; no tuning",
        "candidate_sha256": sha256_file(model_path),
        "policy_sha256": sha256_file(POLICY_PATH),
        "holdout_projection_sha256": manifest["phreshphish"]["holdout"][
            "output_sha256"
        ],
        "candidate_status": (
            "HOLDOUT_GATES_PASSED_NOT_PROMOTED"
            if all_required_gates_passed
            else "REJECTED_BY_HOLDOUT_GATE"
        ),
        "thresholds_changed": False,
        "exclusions": exclusions,
        "aggregate_metrics": metrics,
        "aggregate_gate_passed": aggregate_passed,
        "aggregate_gate_failures": aggregate_failures,
        "per_source": source_reports,
        "per_source_gate_passed": not source_gate_failures,
        "per_source_gate_failures": source_gate_failures,
        "realistic_prevalence": _base_rate_metrics(
            metrics, policy["realistic_prevalence_scenarios"]
        ),
        "slices": _slices(
            records,
            labels,
            probabilities,
            candidate.lower_threshold,
            candidate.upper_threshold,
            policy["contamination_policy"]["minimum_rows_per_reported_slice"],
        ),
        "operational": benchmark,
        "operational_gate_passed": not operational_failures,
        "operational_gate_failures": operational_failures,
        "all_required_gates_passed": all_required_gates_passed,
        "promotion_ready": False,
        "remaining_promotion_requirements": (
            [
                "Manual aggregate error review without redistributing source URLs",
                "Shadow-mode comparison in a production-shaped deployment",
                "Explicit maintainer approval for production integration",
            ]
            if all_required_gates_passed
            else [
                "This candidate is permanently rejected; do not retune it on holdouts",
                "Develop a materially different candidate using training/development only",
                "Reserve a new future temporal snapshot for unbiased final promotion evidence",
            ]
        ),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/V2_HOLDOUT_EVALUATION.json")
    )
    arguments = parser.parse_args()
    print(
        json.dumps(
            evaluate_holdouts(arguments.data, arguments.model, arguments.report),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
