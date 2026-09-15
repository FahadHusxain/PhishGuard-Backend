"""Audit currently held full-URL sources against the v2 corpus contract."""

import argparse
import bz2
import csv
import json
from collections.abc import Iterator
from datetime import datetime
from itertools import chain
from pathlib import Path

from ml_pipeline.corpus import URLSample, audit_corpus
from ml_pipeline.dataset import (
    DatasetIntegrityError,
    acquire_archive,
    iter_labeled_urls,
    sha256_file,
)

PIPELINE_DIRECTORY = Path(__file__).parent
EXTERNAL_MANIFEST_PATH = PIPELINE_DIRECTORY / "external_evaluation_manifest.json"
SOURCE_REGISTRY_PATH = PIPELINE_DIRECTORY / "source_registry.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _verified_external_path(data_directory: Path, source: dict) -> Path:
    path = data_directory / source["local_filename"]
    if not path.is_file() or sha256_file(path) != source["sha256"]:
        raise DatasetIntegrityError(f"External source is missing or invalid: {path}")
    return path


def _phiusiil_samples(path: Path, license_confirmed: bool) -> Iterator[URLSample]:
    for url, label in iter_labeled_urls(path):
        yield URLSample(url, label, "phiusiil", None, license_confirmed)


def _phishtank_samples(path: Path, license_confirmed: bool) -> Iterator[URLSample]:
    required_columns = {"url", "verification_time", "verified"}
    with bz2.open(path, "rt", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise DatasetIntegrityError(
                "The PhishTank schema does not match its manifest."
            )
        for row_number, row in enumerate(reader, start=2):
            if row["verified"].strip().lower() != "yes":
                raise DatasetIntegrityError(
                    f"Unverified PhishTank record at CSV row {row_number}."
                )
            try:
                observed_at = datetime.fromisoformat(row["verification_time"].strip())
            except ValueError as exc:
                raise DatasetIntegrityError(
                    f"Invalid PhishTank timestamp at CSV row {row_number}."
                ) from exc
            yield URLSample(
                row["url"].strip(),
                1,
                "phishtank-2026-09-10",
                observed_at,
                license_confirmed,
            )


def audit_current_sources(data_directory: Path) -> dict:
    """Audit eligible full-URL holdings without fitting or scoring a model."""
    external_manifest = _load_json(EXTERNAL_MANIFEST_PATH)
    registry = _load_json(SOURCE_REGISTRY_PATH)
    phiusiil_path = acquire_archive(data_directory / "phiusiil.zip")
    phishtank_path = _verified_external_path(
        data_directory, external_manifest["sources"]["phishing"]
    )
    samples = chain(
        _phiusiil_samples(
            phiusiil_path,
            registry["sources"]["phiusiil"]["training_rights_confirmed"],
        ),
        _phishtank_samples(
            phishtank_path,
            registry["sources"]["phishtank_snapshot_2026_09_10"][
                "training_rights_confirmed"
            ],
        ),
    )
    report = audit_corpus(samples)
    report["audited_sources"] = ["phiusiil", "phishtank-2026-09-10"]
    report["excluded_sources"] = {
        "tranco-2026-09-10": "bare domains are not genuine benign full URLs"
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument(
        "--report", type=Path, default=Path("ml_models/CORPUS_READINESS.json")
    )
    arguments = parser.parse_args()
    report = audit_current_sources(arguments.data)
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
