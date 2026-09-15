"""Acquire pinned open corpus sources without downloading captured page content."""

import argparse
import csv
import json
import re
from pathlib import Path

import requests

from ml_pipeline.dataset import DatasetIntegrityError, sha256_file

MANIFEST_PATH = Path(__file__).with_name("open_corpus_manifest.json")
HUGGING_FACE_PREFIX = "https://huggingface.co/datasets/phreshphish/phreshphish/resolve/"
MENDELEY_PREFIX = "https://data.mendeley.com/public-files/datasets/b97hxbxtpd/files/"


def load_open_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _download_verified(
    url: str,
    destination: Path,
    expected_sha256: str,
    allowed_prefix: str,
) -> Path:
    if not url.startswith(allowed_prefix):
        raise DatasetIntegrityError("Dataset URL is outside its approved origin.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        temporary_path = destination.with_suffix(f"{destination.suffix}.part")
        try:
            with requests.get(url, stream=True, timeout=60) as response:
                response.raise_for_status()
                with temporary_path.open("wb") as output:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        output.write(chunk)
            temporary_path.replace(destination)
        finally:
            temporary_path.unlink(missing_ok=True)
    if sha256_file(destination) != expected_sha256:
        raise DatasetIntegrityError(f"Dataset SHA-256 mismatch: {destination}")
    return destination


def acquire_phishvn(data_directory: Path, manifest: dict) -> Path:
    source = manifest["phishvn"]
    return _download_verified(
        source["archive_url"],
        data_directory / source["local_filename"],
        source["archive_sha256"],
        MENDELEY_PREFIX,
    )


def _phreshphish_urls(source: dict) -> list[str]:
    revision = source["revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise DatasetIntegrityError("PhreshPhish revision must be a commit SHA.")
    shard_count = source["shard_count"]
    if type(shard_count) is not int or shard_count < 1:
        raise DatasetIntegrityError("PhreshPhish shard count is invalid.")
    split = source.get("split", "train")
    if split not in {"train", "test"}:
        raise DatasetIntegrityError("PhreshPhish split is invalid.")
    return [
        f"{HUGGING_FACE_PREFIX}{revision}/data/{split}-{index:03d}.parquet"
        for index in range(shard_count)
    ]


def _csv_rows(path: Path) -> int:
    with path.open(encoding="utf-8", newline="") as source:
        return sum(1 for _row in csv.DictReader(source))


def acquire_phreshphish(
    data_directory: Path,
    manifest: dict,
    *,
    establish_lock: bool = False,
) -> tuple[Path, str]:
    """Project four metadata columns from pinned Parquet shards."""
    source = manifest["phreshphish"]
    destination = data_directory / source["local_filename"]
    expected_sha256 = source["output_sha256"]
    if not expected_sha256 and not establish_lock:
        raise DatasetIntegrityError(
            "PhreshPhish output lock is unset; maintainer bootstrap is required."
        )
    if destination.exists():
        actual_sha256 = sha256_file(destination)
    else:
        try:
            import duckdb
        except ImportError as exc:
            raise DatasetIntegrityError(
                "Install requirements-ml.txt before acquiring PhreshPhish."
            ) from exc

        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = destination.with_suffix(f"{destination.suffix}.part")
        temporary_path.unlink(missing_ok=True)
        try:
            relation = duckdb.connect().from_parquet(_phreshphish_urls(source))
            relation.project("sha256, url, label, date").order("sha256").write_csv(
                str(temporary_path), header=True
            )
            temporary_path.replace(destination)
        finally:
            temporary_path.unlink(missing_ok=True)
        actual_sha256 = sha256_file(destination)

    if expected_sha256 and actual_sha256 != expected_sha256:
        raise DatasetIntegrityError("Projected PhreshPhish SHA-256 mismatch.")
    actual_rows = _csv_rows(destination)
    if actual_rows != source["reported_rows"]:
        raise DatasetIntegrityError(
            f"PhreshPhish row mismatch: expected {source['reported_rows']}, "
            f"received {actual_rows}."
        )
    return destination, actual_sha256


def acquire_phreshphish_holdout(
    data_directory: Path,
    manifest: dict,
    *,
    establish_lock: bool = False,
) -> tuple[Path, str]:
    """Project the separately pinned published test split."""
    parent = manifest["phreshphish"]
    holdout = {**parent["holdout"], "revision": parent["revision"]}
    return acquire_phreshphish(
        data_directory,
        {"phreshphish": holdout},
        establish_lock=establish_lock,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(".ml-data"))
    parser.add_argument("--establish-lock", action="store_true")
    parser.add_argument("--include-holdout", action="store_true")
    arguments = parser.parse_args()
    manifest = load_open_manifest()
    phishvn_path = acquire_phishvn(arguments.data, manifest)
    phreshphish_path, projected_hash = acquire_phreshphish(
        arguments.data, manifest, establish_lock=arguments.establish_lock
    )
    result = {
        "phishvn": str(phishvn_path),
        "phreshphish": str(phreshphish_path),
        "phreshphish_output_sha256": projected_hash,
    }
    if arguments.include_holdout:
        holdout_path, holdout_hash = acquire_phreshphish_holdout(
            arguments.data,
            manifest,
            establish_lock=arguments.establish_lock,
        )
        result["phreshphish_holdout"] = str(holdout_path)
        result["phreshphish_holdout_output_sha256"] = holdout_hash
    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
