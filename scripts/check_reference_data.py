"""Validate the attributed domain-reference snapshot against its manifest."""

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "data" / "reference_domains_manifest.json"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    output_name = manifest["output"]
    if Path(output_name).name != output_name:
        raise SystemExit("Reference-data output must be a filename")
    snapshot = MANIFEST_PATH.parent / output_name
    actual_hash = file_sha256(snapshot)
    if actual_hash != manifest["output_sha256"]:
        raise SystemExit(
            f"Reference-data checksum mismatch: expected {manifest['output_sha256']}, "
            f"got {actual_hash}"
        )

    seen = set()
    previous_rank = 0
    count = 0
    with snapshot.open("r", encoding="utf-8", newline="") as source:
        for line_number, row in enumerate(csv.reader(source), start=1):
            if len(row) != 2:
                raise SystemExit(f"Malformed reference-data row {line_number}")
            rank = int(row[0])
            domain = row[1]
            if rank <= previous_rank:
                raise SystemExit(f"Ranks are not increasing at row {line_number}")
            if domain != domain.lower() or domain in seen:
                raise SystemExit(f"Invalid or duplicate domain at row {line_number}")
            previous_rank = rank
            seen.add(domain)
            count += 1

    if count != manifest["retained_rows"]:
        raise SystemExit(
            f"Reference-data row mismatch: expected {manifest['retained_rows']}, got {count}"
        )
    print(f"Reference data valid: {count} rows, SHA-256 {actual_hash}.")


if __name__ == "__main__":
    main()
