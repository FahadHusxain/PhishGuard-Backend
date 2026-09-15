"""Verified acquisition and parsing of the versioned training dataset."""

import csv
import hashlib
import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import Path

import requests

MANIFEST_PATH = Path(__file__).with_name("dataset_manifest.json")


class DatasetIntegrityError(RuntimeError):
    """Raised when downloaded data does not match its committed manifest."""


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def acquire_archive(destination: Path) -> Path:
    """Download once and always verify the exact archive bytes."""
    manifest = load_manifest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        temporary_path = destination.with_suffix(f"{destination.suffix}.part")
        try:
            archive_url = manifest["archive_url"]
            if not archive_url.startswith("https://archive.ics.uci.edu/"):
                raise DatasetIntegrityError(
                    "The dataset source is not an approved UCI URL."
                )
            with requests.get(archive_url, stream=True, timeout=60) as response:
                response.raise_for_status()
                with temporary_path.open("wb") as output:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        output.write(chunk)
            temporary_path.replace(destination)
        finally:
            temporary_path.unlink(missing_ok=True)

    actual_hash = sha256_file(destination)
    if actual_hash != manifest["archive_sha256"]:
        raise DatasetIntegrityError(
            f"Dataset SHA-256 mismatch: expected {manifest['archive_sha256']}, "
            f"received {actual_hash}."
        )
    return destination


def iter_labeled_urls(archive_path: Path) -> Iterator[tuple[str, int]]:
    """Yield URL and internal label, where 1 means phishing."""
    manifest = load_manifest()
    expected_columns = {manifest["url_column"], manifest["label_column"]}
    with zipfile.ZipFile(archive_path) as archive:
        try:
            member = archive.open(manifest["csv_member"])
        except KeyError as exc:
            raise DatasetIntegrityError(
                "The expected CSV is absent from the archive."
            ) from exc

        with (
            member,
            io.TextIOWrapper(
                member, encoding="utf-8-sig", errors="replace", newline=""
            ) as text,
        ):
            reader = csv.DictReader(text)
            if not reader.fieldnames or not expected_columns.issubset(
                reader.fieldnames
            ):
                raise DatasetIntegrityError(
                    "The dataset schema does not match the manifest."
                )
            for row_number, row in enumerate(reader, start=2):
                url = row[manifest["url_column"]].strip()
                source_label = row[manifest["label_column"]].strip()
                if not url or source_label not in {"0", "1"}:
                    raise DatasetIntegrityError(
                        f"Invalid URL or label at CSV row {row_number}."
                    )
                yield url, int(source_label == "0")
