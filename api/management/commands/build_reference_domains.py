"""Build the compact, attributed domain-reference snapshot from Majestic CSV."""

import csv
import hashlib
from pathlib import Path

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from api.domains import normalize_whitelist_domain

EXPECTED_FIELDS = (
    "GlobalRank",
    "TldRank",
    "Domain",
    "TLD",
    "RefSubNets",
    "RefIPs",
    "IDN_Domain",
    "IDN_TLD",
    "PrevGlobalRank",
    "PrevTldRank",
    "PrevRefSubNets",
    "PrevRefIPs",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_snapshot(source: Path, destination: Path, *, limit: int) -> tuple[int, int]:
    if limit < 1:
        raise ValueError("limit must be positive")

    rows = []
    seen = set()
    skipped = 0
    with source.open("r", encoding="utf-8-sig", newline="") as source_file:
        reader = csv.DictReader(source_file)
        if tuple(reader.fieldnames or ()) != EXPECTED_FIELDS:
            raise ValueError(
                "Majestic source schema does not match the frozen contract"
            )
        for source_row in reader:
            try:
                rank = int(source_row["GlobalRank"])
                domain = normalize_whitelist_domain(source_row["Domain"])
            except (TypeError, ValueError, ValidationError):
                skipped += 1
                continue
            if rank < 1:
                skipped += 1
                continue
            if domain in seen:
                skipped += 1
                continue
            seen.add(domain)
            rows.append((rank, domain))
            if len(rows) == limit:
                break

    if len(rows) != limit:
        raise ValueError(f"Majestic source contains fewer than {limit} valid domains")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.writer(output_file, lineterminator="\n")
        writer.writerows(rows)
    return len(rows), skipped


class Command(BaseCommand):
    help = "Build a checksum-verified domain-reference snapshot from Majestic CSV"

    def add_arguments(self, parser):
        parser.add_argument("--input", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--expected-sha256", required=True)
        parser.add_argument("--limit", type=int, default=100_000)

    def handle(self, *args, **options):
        source = options["input"]
        destination = options["output"]
        try:
            actual_hash = file_sha256(source)
        except OSError as exc:
            raise CommandError(f"Unable to read Majestic source: {exc}") from exc
        expected_hash = options["expected_sha256"].lower()
        if actual_hash.lower() != expected_hash:
            raise CommandError(
                "Majestic source checksum mismatch: "
                f"expected {expected_hash}, got {actual_hash}"
            )
        try:
            count, skipped = build_snapshot(source, destination, limit=options["limit"])
        except (OSError, UnicodeError, csv.Error, ValueError) as exc:
            raise CommandError(
                f"Unable to build domain-reference snapshot: {exc}"
            ) from exc
        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {count} attributed domain-reference rows to {destination}; "
                f"skipped {skipped} invalid or duplicate rows"
            )
        )
