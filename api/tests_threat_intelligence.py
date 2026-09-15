from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from .models import ThreatFeedSnapshot, ThreatIndicator
from .threat_intelligence import (
    canonicalize_indicator_url,
    find_active_threat,
    indicator_digest,
)


@override_settings(
    PHISHGUARD_THREAT_INTELLIGENCE_ENABLED=True,
    PHISHGUARD_THREAT_FEED_MAX_AGE_HOURS=36,
)
class ThreatIntelligenceTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = "https://malicious.example/credential?id=7"
        now = timezone.now()
        ThreatIndicator.objects.create(
            source="openphish-community",
            url_sha256=indicator_digest(self.url),
            first_seen=now,
            last_seen=now,
        )
        ThreatFeedSnapshot.objects.create(
            source="openphish-community",
            retrieved_at=now,
            content_sha256="a" * 64,
            indicator_count=1,
        )

    def test_canonicalization_normalizes_safe_equivalents(self):
        canonical = canonicalize_indicator_url(
            "HTTPS://MALICIOUS.EXAMPLE:443/credential?id=7#ignored"
        )
        self.assertEqual(canonical, self.url)

    def test_exact_match_does_not_expand_to_other_path(self):
        self.assertIsNotNone(find_active_threat(self.url))
        self.assertIsNone(find_active_threat("https://malicious.example/other"))

    def test_stale_snapshot_is_not_used(self):
        ThreatFeedSnapshot.objects.update(
            retrieved_at=timezone.now() - timedelta(hours=37)
        )
        self.assertIsNone(find_active_threat(self.url))

    def test_feed_match_overrides_low_rule_score(self):
        response = self.client.post(
            reverse("predict"), {"url": self.url}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "PHISHING")
        self.assertEqual(response.data["risk_score"], 100.0)
        self.assertEqual(response.data["confidence_basis"], "threat-intelligence")
        self.assertEqual(response.data["engine"], "threat-intelligence-rules")
        self.assertIn("Exact URL matches", response.data["signals"][0])

    @override_settings(PHISHGUARD_THREAT_INTELLIGENCE_ENABLED=False)
    def test_feature_can_be_disabled_without_deleting_indicators(self):
        self.assertIsNone(find_active_threat(self.url))
        self.assertEqual(ThreatIndicator.objects.count(), 1)


class SyncThreatFeedCommandTests(TestCase):
    def test_text_snapshot_hashes_urls_and_deactivates_removed_rows(self):
        with TemporaryDirectory() as directory:
            first = Path(directory, "first.txt")
            second = Path(directory, "second.txt")
            first.write_text(
                "https://one.example/login\nhttps://two.example/verify\nnot-a-url\n",
                encoding="utf-8",
            )
            second.write_text("https://two.example/verify\n", encoding="utf-8")
            call_command(
                "sync_threat_feed",
                source="openphish-community",
                file=first,
            )
            self.assertEqual(ThreatIndicator.objects.filter(active=True).count(), 2)
            self.assertFalse(
                ThreatIndicator.objects.filter(
                    url_sha256__contains="one.example"
                ).exists()
            )

            call_command(
                "sync_threat_feed",
                source="openphish-community",
                file=second,
            )
            self.assertEqual(ThreatIndicator.objects.filter(active=True).count(), 1)
            self.assertEqual(ThreatIndicator.objects.filter(active=False).count(), 1)
            snapshot = ThreatFeedSnapshot.objects.get(source="openphish-community")
            self.assertEqual(snapshot.indicator_count, 1)

    def test_csv_import_keeps_only_verified_online_rows(self):
        with TemporaryDirectory() as directory:
            path = Path(directory, "feed.csv")
            path.write_text(
                "url,verified,online\n"
                "https://kept.example/,yes,yes\n"
                "https://unverified.example/,no,yes\n"
                "https://offline.example/,yes,no\n",
                encoding="utf-8",
            )
            call_command(
                "sync_threat_feed", source="phishtank", file=path, format="csv"
            )
        self.assertEqual(ThreatIndicator.objects.filter(active=True).count(), 1)

    def test_empty_or_invalid_snapshot_does_not_replace_current_data(self):
        now = timezone.now()
        ThreatIndicator.objects.create(
            source="openphish-community",
            url_sha256=indicator_digest("https://existing.example/"),
            first_seen=now,
            last_seen=now,
        )
        with TemporaryDirectory() as directory:
            path = Path(directory, "invalid.txt")
            path.write_text("not-a-url\n", encoding="utf-8")
            with self.assertRaisesMessage(Exception, "no valid HTTP or HTTPS"):
                call_command(
                    "sync_threat_feed",
                    source="openphish-community",
                    file=path,
                )
        self.assertTrue(ThreatIndicator.objects.get().active)
