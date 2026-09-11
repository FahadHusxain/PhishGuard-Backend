"""Provenance and leakage controls for the next-generation ML corpus."""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from django.core.exceptions import ValidationError

from api.domains import normalize_hostname, registrable_domain

Label = Literal[0, 1]
Representation = Literal["full_url", "origin", "domain"]
DEFAULT_MIN_SAMPLES_PER_LABEL = 1_000
SOURCE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*")


class CorpusValidationError(ValueError):
    """Raised when a sample violates the versioned corpus contract."""


class CorpusReadinessError(RuntimeError):
    """Raised when corpus evidence is inadequate for candidate training."""


@dataclass(frozen=True, slots=True)
class URLSample:
    url: str
    label: Label
    source: str
    observed_at: datetime | None
    license_confirmed: bool
    representation: Representation = "full_url"

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url.strip():
            raise CorpusValidationError("url is required")
        if type(self.label) is not int or self.label not in {0, 1}:
            raise CorpusValidationError("label must be 0 (benign) or 1 (phishing)")
        if not isinstance(self.source, str) or not SOURCE_ID_PATTERN.fullmatch(
            self.source
        ):
            raise CorpusValidationError("source must be a stable lowercase identifier")
        if self.representation not in {"full_url", "origin", "domain"}:
            raise CorpusValidationError("representation is invalid")
        if not isinstance(self.license_confirmed, bool):
            raise CorpusValidationError("license_confirmed must be boolean")
        if self.observed_at is not None and (
            not isinstance(self.observed_at, datetime)
            or self.observed_at.utcoffset() is None
        ):
            raise CorpusValidationError("observed_at must include a timezone")


def normalize_corpus_url(url: str) -> tuple[str, str]:
    """Return a stable URL and registrable group without contacting its host."""
    if not isinstance(url, str) or not url.strip():
        raise CorpusValidationError("sample URL is required")
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise CorpusValidationError("sample must be a complete HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise CorpusValidationError("embedded URL credentials are not allowed")
        hostname = normalize_hostname(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError, ValidationError) as exc:
        raise CorpusValidationError("sample URL is malformed") from exc

    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    netloc = (
        rendered_host if port is None or default_port else f"{rendered_host}:{port}"
    )
    normalized = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized, registrable_domain(hostname) or hostname


def audit_corpus(
    samples: list[URLSample],
    *,
    min_samples_per_label: int = DEFAULT_MIN_SAMPLES_PER_LABEL,
) -> dict:
    """Summarize source confounding, time coverage, and duplicate conflicts."""
    if type(min_samples_per_label) is not int or min_samples_per_label < 1:
        raise CorpusValidationError("min_samples_per_label must be a positive integer")
    labels_by_url: dict[str, set[int]] = defaultdict(set)
    sources_by_url: dict[str, set[str]] = defaultdict(set)
    samples_by_url: dict[str, list[URLSample]] = defaultdict(list)
    group_by_url: dict[str, str] = {}
    sources_by_label: dict[int, set[str]] = defaultdict(set)
    full_url_by_label = Counter()
    licensed_by_label = Counter()
    dated_by_label = Counter()
    groups_by_label: dict[int, set[str]] = defaultdict(set)
    invalid_rows = 0

    for sample in samples:
        try:
            normalized_url, group = normalize_corpus_url(sample.url)
        except CorpusValidationError:
            invalid_rows += 1
            continue
        labels_by_url[normalized_url].add(sample.label)
        sources_by_url[normalized_url].add(sample.source)
        samples_by_url[normalized_url].append(sample)
        group_by_url[normalized_url] = group

    conflicts = {url for url, labels in labels_by_url.items() if len(labels) > 1}
    retained = {url for url in labels_by_url if url not in conflicts}
    label_counts = Counter(next(iter(labels_by_url[url])) for url in retained)
    for url in retained:
        label = next(iter(labels_by_url[url]))
        entries = samples_by_url[url]
        sources_by_label[label].update(entry.source for entry in entries)
        groups_by_label[label].add(group_by_url[url])
        if any(entry.representation == "full_url" for entry in entries):
            full_url_by_label[label] += 1
        if any(entry.observed_at is not None for entry in entries):
            dated_by_label[label] += 1
        if all(entry.license_confirmed for entry in entries):
            licensed_by_label[label] += 1

    sources_per_label = {
        str(label): sorted(sources_by_label[label]) for label in (0, 1)
    }

    readiness_failures = []
    for label, label_name in ((0, "benign"), (1, "phishing")):
        count = label_counts[label]
        if count < min_samples_per_label:
            readiness_failures.append(
                f"{label_name} label requires at least "
                f"{min_samples_per_label} unique URLs"
            )
        if len(sources_per_label[str(label)]) < 2:
            readiness_failures.append(
                f"{label_name} label requires at least two independent sources"
            )
        if not count or full_url_by_label[label] / count < 0.95:
            readiness_failures.append(
                f"{label_name} label requires at least 95% genuine full URLs"
            )
        if not count or dated_by_label[label] / count < 0.8:
            readiness_failures.append(
                f"{label_name} label requires at least 80% timestamp coverage"
            )
        if not count or licensed_by_label[label] != count:
            readiness_failures.append(
                f"{label_name} label contains samples without confirmed training rights"
            )

    shared_label_groups = groups_by_label[0] & groups_by_label[1]
    if shared_label_groups:
        readiness_failures.append(
            "registrable domains with conflicting labels require adjudication"
        )

    return {
        "contract_version": 2,
        "min_samples_per_label": min_samples_per_label,
        "input_rows": len(samples),
        "unique_urls": len(labels_by_url),
        "retained_urls": len(retained),
        "invalid_rows": invalid_rows,
        "conflicting_urls": len(conflicts),
        "cross_source_duplicate_urls": sum(
            len(sources) > 1 for sources in sources_by_url.values()
        ),
        "labels": {"benign": label_counts[0], "phishing": label_counts[1]},
        "sources_per_label": sources_per_label,
        "timestamp_coverage": {
            "benign": dated_by_label[0] / label_counts[0] if label_counts[0] else 0.0,
            "phishing": dated_by_label[1] / label_counts[1] if label_counts[1] else 0.0,
        },
        "full_url_coverage": {
            "benign": full_url_by_label[0] / label_counts[0]
            if label_counts[0]
            else 0.0,
            "phishing": full_url_by_label[1] / label_counts[1]
            if label_counts[1]
            else 0.0,
        },
        "licensed_coverage": {
            "benign": licensed_by_label[0] / label_counts[0]
            if label_counts[0]
            else 0.0,
            "phishing": licensed_by_label[1] / label_counts[1]
            if label_counts[1]
            else 0.0,
        },
        "shared_label_groups": len(shared_label_groups),
        "training_ready": not readiness_failures,
        "readiness_failures": readiness_failures,
    }


def require_training_ready(report: dict) -> None:
    """Prevent training when minimum diversity and temporal gates fail."""
    failures = report.get("readiness_failures") or []
    if not report.get("training_ready") or failures:
        detail = "; ".join(str(failure) for failure in failures)
        raise CorpusReadinessError(f"Corpus is not training-ready: {detail}")
