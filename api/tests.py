import os
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from backend.settings import env_bool, env_list
from .ml_classifier import URLCNNClassifier
from .ml_logic import predict_url_security
from .models import ScanLog, WhitelistDomain
from .views import get_ip_location


class EnvironmentSettingsTests(SimpleTestCase):
    def test_env_bool_uses_default_when_variable_is_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(env_bool("MISSING_SETTING", default=True))

    def test_env_bool_accepts_conventional_true_values(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"BOOLEAN_SETTING": value}):
                    self.assertTrue(env_bool("BOOLEAN_SETTING"))

    def test_env_list_removes_empty_items_and_whitespace(self):
        with patch.dict(
            os.environ,
            {"LIST_SETTING": "localhost, 127.0.0.1, ,example.com"},
        ):
            self.assertEqual(
                env_list("LIST_SETTING"),
                ["localhost", "127.0.0.1", "example.com"],
            )


class URLApiTests(APITestCase):
    def test_predict_rejects_malformed_urls(self):
        response = self.client.post(
            reverse("predict"),
            {"url": "this is not a URL"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(ScanLog.objects.count(), 0)

    def test_predict_rejects_embedded_credentials(self):
        response = self.client.post(
            reverse("predict"),
            {"url": "https://admin:password@example.com/login"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_whitelist_does_not_match_lookalike_domains(self):
        WhitelistDomain.objects.create(domain="example.com", rank=1)

        with (
            patch(
                "api.views.predict_url_security",
                return_value={
                    "status": "PHISHING",
                    "confidence": 90,
                    "message": "Suspicious",
                },
            ),
            patch("api.views.get_ip_location", return_value=(None, "Unknown")),
        ):
            response = self.client.post(
                reverse("predict"),
                {"url": "https://notexample.com/login"},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "PHISHING")

    def test_scan_logs_store_only_the_url_origin(self):
        with (
            patch(
                "api.views.predict_url_security",
                return_value={
                    "status": "SAFE",
                    "confidence": 95,
                    "message": "Safe",
                },
            ),
            patch("api.views.get_ip_location", return_value=(None, "Unknown")),
        ):
            response = self.client.post(
                reverse("predict"),
                {"url": "https://example.com/reset/secret?token=private#fragment"},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ScanLog.objects.get().url, "https://example.com")

    def test_whitelist_matches_a_real_subdomain(self):
        WhitelistDomain.objects.create(domain="example.com", rank=1)

        response = self.client.post(
            reverse("predict"),
            {"url": "https://accounts.example.com/login"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "SAFE")
        self.assertEqual(response.data["confidence"], 100)

    def test_dashboard_does_not_expose_full_urls_or_ip_addresses(self):
        ScanLog.objects.create(
            url="https://example.com/reset?token=secret",
            status="SAFE",
            confidence=95,
            ip_address="8.8.8.8",
            country="United States",
        )

        response = self.client.get(reverse("dashboard_stats"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        recent_log = response.data["recent_logs"][0]
        self.assertEqual(recent_log["domain"], "example.com")
        self.assertNotIn("url", recent_log)
        self.assertNotIn("ip_address", recent_log)

    def test_removed_fix_endpoint_returns_not_found(self):
        response = self.client.get("/api/fix-now/")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class WhitelistAdministrationTests(APITestCase):
    def test_anonymous_user_cannot_add_whitelist_entries(self):
        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(WhitelistDomain.objects.exists())

    def test_staff_user_can_add_a_normalized_whitelist_entry(self):
        user = get_user_model().objects.create_user(
            username="administrator",
            password="not-used-in-this-test",
            is_staff=True,
        )
        self.client.force_authenticate(user=user)

        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://EXAMPLE.com./login"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            WhitelistDomain.objects.filter(domain="example.com", rank=50).exists()
        )


class GeolocationSafetyTests(SimpleTestCase):
    @override_settings(PHISHGUARD_GEOLOCATION_ENABLED=True)
    def test_private_addresses_are_never_sent_to_geolocation_service(self):
        private_result = [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]

        with (
            patch("api.views.socket.getaddrinfo", return_value=private_result),
            patch("api.views.requests.get") as request_get,
        ):
            result = get_ip_location("http://localhost/admin")

        self.assertEqual(result, (None, "Unknown"))
        request_get.assert_not_called()


class MLClassifierTests(SimpleTestCase):
    def test_committed_cnn_loads_and_distinguishes_reference_samples(self):
        classifier = URLCNNClassifier(
            settings.PHISHGUARD_MODEL_PATH,
            settings.PHISHGUARD_TOKENIZER_PATH,
        )

        benign_risk = classifier.predict_probability("https://github.com/openai")
        suspicious_risk = classifier.predict_probability(
            "http://192.168.1.10/login/verify-account"
        )

        self.assertGreaterEqual(benign_risk, 0.0)
        self.assertLessEqual(suspicious_risk, 1.0)
        self.assertGreater(suspicious_risk, benign_risk)

    def test_strong_ml_signal_can_trigger_a_phishing_verdict(self):
        with patch("api.ml_logic._model_probability", return_value=0.9):
            result = predict_url_security("https://ordinary-example.test")

        self.assertEqual(result["status"], "PHISHING")
        self.assertEqual(result["engine"], "hybrid-cnn-rules")
        self.assertGreaterEqual(result["risk_score"], 50)

    def test_rules_only_fallback_is_explicit_and_inconclusive(self):
        with patch("api.ml_logic._model_probability", return_value=None):
            result = predict_url_security("https://ordinary-example.test")

        self.assertEqual(result["engine"], "rules-only")
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["confidence"], 0)
