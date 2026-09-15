"""Audit pinned open training splits before any model fitting occurs."""

import argparse
import csv
import io
import json
import re
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path

from ml_pipeline.acquire_open_corpus import (
    acquire_phishvn,
    acquire_phreshphish,
    load_open_manifest,
)
from ml_pipeline.corpus import (
    URLSample,
    audit_corpus,
    quarantine_cross_label_groups,
)
from ml_pipeline.dataset import DatasetIntegrityError


def _phreshphish_samples(path: Path) -> Iterator[URLSample]:
    required_columns = {"sha256", "url", "label", "date"}
    with path.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise DatasetIntegrityError("The PhreshPhish schema is invalid.")
        for row_number, row in enumerate(reader, start=2):
            if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
                raise DatasetIntegrityError(
                    f"Invalid PhreshPhish identifier at row {row_number}."
                )
            label_value = row["label"].strip().lower()
            if label_value not in {"benign", "phish"}:
                raise DatasetIntegrityError(
                    f"Invalid PhreshPhish label at row {row_number}."
                )
            try:
                observed_at = datetime.strptime(row["date"], "%Y-%m-%d").replace(
                    tzinfo=UTC
                )
            except ValueError as exc:
                raise DatasetIntegrityError(
                    f"Invalid PhreshPhish date at row {row_number}."
                ) from exc
            yield URLSample(
                row["url"],
                int(label_value == "phish"),
                "phreshphish-v1.0.1",
                observed_at,
                True,
            )


def _phishvn_samples(path: Path, source_manifest: dict) -> Iterator[URLSample]:
    required_columns = {"label", "tier", "split", "url_norm", "collected_at"}
    eligible_tiers = set(source_manifest["eligible_tiers"])
    eligible_splits = set(source_manifest["eligible_splits"])
    with (
        zipfile.ZipFile(path) as archive,
        archive.open(source_manifest["csv_member"]) as binary_source,
        io.TextIOWrapper(binary_source, encoding="utf-8-sig", newline="") as source,
    ):
        reader = csv.DictReader(source)
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise DatasetIntegrityError("The PhishVN schema is invalid.")
        for row_number, row in enumerate(reader, start=2):
            if row["tier"] not in eligible_tiers or row["split"] not in eligible_splits:
                continue
            label_value = row["label"].strip().lower()
            if label_value not in {"benign", "phishing"}:
                raise DatasetIntegrityError(
                    f"Invalid PhishVN label at row {row_number}."
                )
            collected_at = row["collected_at"].strip()
            try:
                observed_at = (
                    datetime.strptime(collected_at, "%d/%m/%Y").replace(tzinfo=UTC)
                    if collected_at
                    else None
                )
            except ValueError as exc:
                raise DatasetIntegrityError(
                    f"Invalid PhishVN date at row {row_number}."
                ) from exc
            yield URLSample(
                row["url_norm"],
                int(label_value == "phishing"),
                "phishvn-v3.1.0",
                observed_at,
                True,
                representation="origin",
            )


def audit_open_sources(data_directory: Path) -> dict:
    """Audit training splits while preserving all published holdouts."""
    retained_samples, pre_adjudication, quarantine = load_open_training_samples(
        data_directory
    )
    report = audit_corpus(retained_samples)
    report["pre_adjudication"] = pre_adjudication
    report["quarantine"] = quarantine
    report["audited_sources"] = ["phreshphish-v1.0.1", "phishvn-v3.1.0"]
    report["preserved_holdouts"] = [
        "PhreshPhish published test split",
        "PhishVN published validation and test splits",
    ]
    return report


def load_open_training_samples(
    data_directory: Path,
) -> tuple[list[URLSample], dict, dict]:
    """Load verified training rows and quarantine ambiguous registrable domains."""
    manifest = load_open_manifest()
    phreshphish_path, _output_hash = acquire_phreshphish(data_directory, manifest)
    phishvn_path = acquire_phishvn(data_directory, manifest)
    samples = list(
        chain(
            _phreshphish_samples(phreshphish_path),
            _phishvn_samples(phishvn_path, manifest["phishvn"]),
        )
    )
    pre_adjudication = audit_corpus(samples)
    retained_samples, quarantine = quarantine_cross_label_groups(samples)
    return retained_samples, pre_adjudication, quarantine


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/OPEN_CORPUS_READINESS.json")
    )
    arguments = parser.parse_args()
    report = audit_open_sources(arguments.data)
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
