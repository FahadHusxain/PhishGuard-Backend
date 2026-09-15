"""Import reviewed phishing feeds while retaining only exact URL hashes."""

import csv
import hashlib
import io
from pathlib import Path

import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from api.models import ThreatFeedSnapshot, ThreatIndicator
from api.threat_intelligence import indicator_digest

OPENPHISH_COMMUNITY_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)
MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_SOURCES = {"openphish-community", "phishtank"}


class Command(BaseCommand):
    help = "Import an exact-URL phishing feed into the privacy-reduced local store."

    def add_arguments(self, parser):
        parser.add_argument("--source", required=True, choices=sorted(ALLOWED_SOURCES))
        parser.add_argument("--file", type=Path)
        parser.add_argument("--format", choices=("txt", "csv"), default="txt")
        parser.add_argument("--retrieved-at")
        parser.add_argument("--accept-openphish-terms", action="store_true")

    def handle(self, *args, **options):
        source = options["source"]
        path = options["file"]
        if path is None:
            if source != "openphish-community":
                raise CommandError("A local --file is required for this source.")
            if not options["accept_openphish_terms"]:
                raise CommandError(
                    "Downloading the OpenPhish Community Feed requires "
                    "--accept-openphish-terms. Review https://openphish.com/terms.html first."
                )
            content = self._download_openphish()
        else:
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise CommandError(f"Unable to read feed file: {exc}") from exc
            if len(content) > MAX_DOWNLOAD_BYTES:
                raise CommandError("Feed file exceeds the 10 MiB safety limit.")

        retrieved_at = timezone.now()
        if options["retrieved_at"]:
            retrieved_at = parse_datetime(options["retrieved_at"])
            if retrieved_at is None or timezone.is_naive(retrieved_at):
                raise CommandError(
                    "--retrieved-at must be a timezone-aware ISO 8601 value."
                )

        urls = self._parse_urls(content, options["format"])
        digests = set()
        rejected = 0
        for url in urls:
            try:
                digests.add(indicator_digest(url))
            except (TypeError, ValueError, UnicodeError):
                rejected += 1
        if not digests:
            raise CommandError("Feed contained no valid HTTP or HTTPS indicators.")

        now = timezone.now()
        with transaction.atomic():
            ThreatIndicator.objects.filter(source=source).exclude(
                url_sha256__in=digests
            ).update(active=False)
            ThreatIndicator.objects.bulk_create(
                [
                    ThreatIndicator(
                        source=source,
                        url_sha256=digest,
                        first_seen=now,
                        last_seen=retrieved_at,
                        active=True,
                    )
                    for digest in digests
                ],
                update_conflicts=True,
                update_fields=("last_seen", "active"),
                unique_fields=("source", "url_sha256"),
            )
            ThreatFeedSnapshot.objects.update_or_create(
                source=source,
                defaults={
                    "retrieved_at": retrieved_at,
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                    "indicator_count": len(digests),
                },
            )
        self.stdout.write(
            self.style.SUCCESS(
                f"Imported {len(digests)} active {source} indicators; "
                f"rejected {rejected}. Raw URLs were not stored."
            )
        )

    def _download_openphish(self):
        try:
            response = requests.get(
                OPENPHISH_COMMUNITY_URL,
                headers={"User-Agent": "PhishGuard-Academic/1.0"},
                timeout=(5, 30),
                stream=True,
            )
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_content(64 * 1024):
                body.extend(chunk)
                if len(body) > MAX_DOWNLOAD_BYTES:
                    raise CommandError(
                        "Downloaded feed exceeds the 10 MiB safety limit."
                    )
            return bytes(body)
        except requests.RequestException as exc:
            raise CommandError(f"OpenPhish download failed: {exc}") from exc

    def _parse_urls(self, content, feed_format):
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise CommandError("Feed must be UTF-8 text.") from exc
        if feed_format == "txt":
            return [line.strip() for line in text.splitlines() if line.strip()]
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise CommandError("CSV feed must contain a url column.")
        rows = []
        for row in reader:
            verified = str(row.get("verified", "yes")).lower()
            online = str(row.get("online", "yes")).lower()
            if verified in {"yes", "true", "1", "y"} and online in {
                "yes",
                "true",
                "1",
                "y",
            }:
                rows.append(row.get("url", ""))
        return rows
