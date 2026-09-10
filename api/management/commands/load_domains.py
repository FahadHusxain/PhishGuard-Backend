"""Import ranked domains into the PhishGuard whitelist."""

import csv
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from rest_framework.serializers import ValidationError

from api.models import WhitelistDomain
from api.serializers import normalize_hostname


class Command(BaseCommand):
    help = "Import ranked whitelist domains from a two-column CSV file"

    def add_arguments(self, parser):
        parser.add_argument(
            "--file",
            type=Path,
            default=Path("top1m.csv"),
            help="CSV path containing rank and domain columns",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=5000,
            help="Number of validated records written per database batch",
        )

    def handle(self, *args, **options):
        file_path = options["file"]
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be at least 1")
        if not file_path.is_file():
            raise CommandError(f"CSV file does not exist: {file_path}")

        queued = 0
        skipped = 0
        batch = []

        try:
            with file_path.open("r", encoding="utf-8", newline="") as csv_file:
                for line_number, row in enumerate(csv.reader(csv_file), start=1):
                    try:
                        rank = int(row[0])
                        domain = normalize_hostname(row[1])
                        if rank < 1:
                            raise ValueError
                    except (IndexError, ValueError, ValidationError):
                        skipped += 1
                        self.stderr.write(
                            f"Skipping malformed CSV row {line_number}",
                            self.style.WARNING,
                        )
                        continue

                    batch.append(WhitelistDomain(domain=domain, rank=rank))
                    queued += 1
                    if len(batch) >= batch_size:
                        self._write_batch(batch)
                        batch.clear()

            if batch:
                self._write_batch(batch)
        except (OSError, UnicodeError, csv.Error) as exc:
            raise CommandError(f"Unable to import {file_path}: {exc}") from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Import complete: {queued} valid rows queued, {skipped} skipped"
            )
        )

    @staticmethod
    def _write_batch(batch):
        WhitelistDomain.objects.bulk_create(batch, ignore_conflicts=True)
