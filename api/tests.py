import base64
import json
import logging
import os
import uuid
from datetime import timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.conf import settings
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, IntegrityError, transaction
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from backend.logging import JSONFormatter, RequestContextFilter
from backend.request_context import current_request_id
from backend.settings import env_bool, env_list

from .admin import ScanLogAdmin, WhitelistAuditEventAdmin
from .domains import (
    normalize_hostname,
    normalize_whitelist_domain,
    whitelist_candidates,
)
from .ml_classifier import URLCNNClassifier
from .ml_logic import predict_url_security
from .models import ScanLog, WhitelistAuditEvent, WhitelistDomain
from .views import get_ip_location


class EnvironmentSettingsTests(SimpleTestCase):
    def test_env_bool_uses_default_when_variable_is_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(env_bool("MISSING_SETTING", default=True))

    def test_env_bool_accepts_conventional_true_values(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"BOOLEAN_SETTING": value}),
            ):
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


class OperationalEndpointTests(APITestCase):
    def test_liveness_does_not_depend_on_the_database(self):
        response = self.client.get(reverse("health_live"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), {"status": "ok"})
        uuid.UUID(response["X-Request-ID"])

    def test_readiness_reports_database_availability(self):
        response = self.client.get(reverse("health_ready"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), {"status": "ready"})

    def test_readiness_failure_is_generic(self):
        with patch("backend.health._database_is_ready", return_value=False):
            response = self.client.get(reverse("health_ready"))

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.json(), {"status": "unavailable"})

    def test_valid_request_id_is_preserved(self):
        request_id = "frontend-request_123"

        response = self.client.get(
            reverse("health_live"),
            headers={"X-Request-ID": request_id},
        )

        self.assertEqual(response["X-Request-ID"], request_id)

    def test_unsafe_request_id_is_replaced(self):
        response = self.client.get(
            reverse("health_live"),
            headers={"X-Request-ID": "unsafe request\nvalue"},
        )

        uuid.UUID(response["X-Request-ID"])


class StructuredLoggingTests(SimpleTestCase):
    def test_request_context_is_injected_and_serialized(self):
        context_token = current_request_id.set("request-123")
        try:
            record = logging.LogRecord(
                name="phishguard.test",
                level=logging.INFO,
                pathname=__file__,
                lineno=1,
                msg="test_event",
                args=(),
                exc_info=None,
            )
            RequestContextFilter().filter(record)
            payload = json.loads(JSONFormatter().format(record))
        finally:
            current_request_id.reset(context_token)

        self.assertEqual(payload["event"], "test_event")
        self.assertEqual(payload["request_id"], "request-123")
        self.assertEqual(payload["level"], "INFO")


class APIContractTests(APITestCase):
    def test_versioned_and_compatibility_routes_share_the_error_contract(self):
        endpoints = [reverse("predict"), reverse("api-v1:predict")]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.post(
                    endpoint,
                    {"url": "not-a-url"},
                    format="json",
                )

                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(response.data["error"]["code"], "invalid")
                self.assertIn("url", response.data["error"]["details"])
                self.assertEqual(response.data["request_id"], response["X-Request-ID"])

    def test_method_errors_use_the_standard_envelope(self):
        response = self.client.get(reverse("api-v1:predict"))

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response.data["error"]["code"], "method_not_allowed")

    def test_openapi_schema_contains_only_the_versioned_contract(self):
        response = self.client.get(
            reverse("api_schema"),
            headers={"Accept": "application/vnd.oai.openapi+json"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        schema = json.loads(response.content)
        self.assertIn("/api/v1/predict/", schema["paths"])
        self.assertNotIn("/api/predict/", schema["paths"])
        self.assertEqual(schema["info"]["version"], "1.0.0")
        predict_request = schema["paths"]["/api/v1/predict/"]["post"]["requestBody"]
        report_request = schema["paths"]["/api/v1/report-safe/"]["post"]["requestBody"]
        self.assertEqual(
            predict_request["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/URLSubmissionRequest",
        )
        self.assertEqual(
            report_request["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/WhitelistSubmissionRequest",
        )

    def test_interactive_api_documentation_is_available(self):
        response = self.client.get(reverse("api_docs"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertContains(response, "swagger-ui")


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
        self.assertEqual(ScanLog.objects.get().origin, "https://example.com")

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

    def test_whitelist_does_not_cross_private_suffix_tenant_boundaries(self):
        WhitelistDomain.objects.create(domain="trusted-user.github.io", rank=1)

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
                {"url": "https://attacker.github.io/login"},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "PHISHING")

    def test_dashboard_does_not_expose_full_urls_or_ip_addresses(self):
        ScanLog.objects.create(
            origin="https://example.com/reset?token=secret",
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


class DomainIntegrityTests(APITestCase):
    def test_normalizer_canonicalizes_unicode_case_and_trailing_dot(self):
        self.assertEqual(
            normalize_hostname(" BÜCHER.Example. "),
            "xn--bcher-kva.example",
        )

    def test_model_writes_are_canonicalized(self):
        entry = WhitelistDomain.objects.create(domain=" EXAMPLE.COM. ", rank=1)

        self.assertEqual(entry.domain, "example.com")
        self.assertTrue(WhitelistDomain.objects.filter(domain="example.com").exists())

    def test_model_rejects_an_invalid_hostname(self):
        with self.assertRaises(DjangoValidationError):
            WhitelistDomain.objects.create(domain="invalid_domain", rank=1)

    def test_database_rejects_case_insensitive_duplicates(self):
        WhitelistDomain.objects.create(domain="example.com", rank=1)

        with self.assertRaises(IntegrityError), transaction.atomic():
            WhitelistDomain.objects.bulk_create(
                [WhitelistDomain(domain="EXAMPLE.COM", rank=2)]
            )

    def test_whitelist_candidates_stop_at_the_registrable_domain(self):
        self.assertEqual(
            whitelist_candidates("signin.accounts.example.co.uk"),
            [
                "signin.accounts.example.co.uk",
                "accounts.example.co.uk",
                "example.co.uk",
            ],
        )

    def test_private_suffix_keeps_tenants_isolated(self):
        self.assertEqual(
            whitelist_candidates("repo.user.github.io"),
            ["repo.user.github.io", "user.github.io"],
        )

    def test_public_suffix_cannot_be_whitelisted(self):
        with self.assertRaises(DjangoValidationError):
            normalize_whitelist_domain("co.uk")

    def test_ip_address_is_its_own_whitelist_boundary(self):
        self.assertEqual(whitelist_candidates("2001:0db8::1"), ["2001:db8::1"])


class WhitelistAdministrationTests(APITestCase):
    def authenticate_staff_user(self):
        user = get_user_model().objects.create_user(
            username="administrator",
            password="not-used-in-this-test",
            is_staff=True,
        )
        self.client.force_authenticate(user=user)
        return user

    def test_anonymous_user_cannot_add_whitelist_entries(self):
        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"]["code"], "not_authenticated")
        self.assertFalse(WhitelistDomain.objects.exists())

    def test_staff_user_cannot_whitelist_a_public_suffix(self):
        self.authenticate_staff_user()

        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://co.uk", "reason": "Invalid trust boundary"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(WhitelistDomain.objects.exists())

    def test_http_basic_authentication_is_disabled(self):
        get_user_model().objects.create_user(
            username="administrator",
            password="test-password",
            is_staff=True,
        )
        credentials = base64.b64encode(b"administrator:test-password").decode()

        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://example.com"},
            format="json",
            headers={"Authorization": f"Basic {credentials}"},
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(WhitelistDomain.objects.exists())

    def test_staff_user_can_add_a_normalized_whitelist_entry(self):
        user = self.authenticate_staff_user()

        response = self.client.post(
            reverse("report_safe"),
            {
                "url": "https://EXAMPLE.com./login",
                "reason": "Verified institutional domain",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            WhitelistDomain.objects.filter(domain="example.com", rank=50).exists()
        )
        audit_event = WhitelistAuditEvent.objects.get()
        self.assertEqual(audit_event.action, WhitelistAuditEvent.Action.ADDED)
        self.assertEqual(audit_event.actor, user)
        self.assertEqual(audit_event.actor_username, "administrator")
        self.assertEqual(audit_event.domain, "example.com")
        self.assertIsNone(audit_event.previous_rank)
        self.assertEqual(audit_event.new_rank, 50)
        self.assertEqual(audit_event.reason, "Verified institutional domain")
        self.assertEqual(audit_event.request_id, response["X-Request-ID"])

        user.delete()
        audit_event.refresh_from_db()
        self.assertIsNone(audit_event.actor)
        self.assertEqual(audit_event.actor_username, "administrator")

    def test_promoting_an_untrusted_entry_records_the_rank_transition(self):
        self.authenticate_staff_user()
        WhitelistDomain.objects.create(domain="example.com", rank=0)

        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://example.com", "reason": "False positive review"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        audit_event = WhitelistAuditEvent.objects.get()
        self.assertEqual(audit_event.action, WhitelistAuditEvent.Action.PROMOTED)
        self.assertEqual(audit_event.previous_rank, 0)
        self.assertEqual(audit_event.new_rank, 50)

    def test_repeating_an_existing_trusted_domain_does_not_fake_a_change(self):
        self.authenticate_staff_user()
        WhitelistDomain.objects.create(domain="example.com", rank=25)

        response = self.client.post(
            reverse("report_safe"),
            {"url": "https://example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(WhitelistAuditEvent.objects.exists())

    def test_whitelist_mutation_rolls_back_if_audit_creation_fails(self):
        self.authenticate_staff_user()

        with (
            self.assertLogs("django.request", level="ERROR"),
            patch(
                "api.views.WhitelistAuditEvent.objects.create",
                side_effect=DatabaseError("audit unavailable"),
            ),
            self.assertRaises(DatabaseError),
        ):
            self.client.post(
                reverse("report_safe"),
                {"url": "https://example.com"},
                format="json",
            )

        self.assertFalse(WhitelistDomain.objects.exists())


class WhitelistAuditAdminTests(SimpleTestCase):
    def test_audit_events_cannot_be_added_or_deleted_through_admin(self):
        model_admin = WhitelistAuditEventAdmin(WhitelistAuditEvent, AdminSite())

        self.assertFalse(model_admin.has_add_permission(None))
        self.assertFalse(model_admin.has_change_permission(None))
        self.assertFalse(model_admin.has_delete_permission(None))


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

    def test_unseen_credential_lure_url_triggers_multiple_independent_signals(self):
        with patch("api.ml_logic._model_probability", return_value=None):
            result = predict_url_security(
                "https://secure-login.verify-account.customer.example.com/"
                "password/update"
            )

        self.assertEqual(result["status"], "PHISHING")
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertGreaterEqual(len(result["signals"]), 3)

    def test_keywords_are_tokenized_instead_of_matched_as_substrings(self):
        with patch("api.ml_logic._model_probability", return_value=None):
            result = predict_url_security("https://example.com/bankruptcy-report")

        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["risk_score"], 0)

    def test_structural_signals_are_detected_independently(self):
        cases = (
            (
                "http://example.com/account",
                "Sensitive page is served over unencrypted HTTP",
            ),
            (
                "https://8.8.8.8/",
                "URL uses an IP address instead of a domain",
            ),
            (
                "https://example.com/?next=https%3A%2F%2Fevil.example",
                "Query embeds another URL and may conceal a redirect",
            ),
            (
                f"https://example.com/{'a' * 210}",
                "URL is unusually long",
            ),
            (
                "https://example.com/@trusted.example",
                "URL contains a misleading @ character",
            ),
            (
                "https://one.two.three.four.example.com/",
                "Hostname has an extremely deep subdomain chain",
            ),
            (
                "https://xn--bcher-kva.example/",
                "Hostname uses internationalized-domain encoding",
            ),
            (
                "https://one-two-three-four-five.example/",
                "Hostname contains many hyphens",
            ),
            (
                "https://1234567890abc.example/",
                "Hostname contains an unusual concentration of digits",
            ),
            (
                "https://example.com/%41%42%43",
                "URL contains heavy percent encoding",
            ),
            (
                "https://example.com:8443/",
                "URL uses a nonstandard network port",
            ),
        )

        with patch("api.ml_logic._model_probability", return_value=None):
            for url, expected_signal in cases:
                with self.subTest(url=url):
                    result = predict_url_security(url)
                    self.assertIn(expected_signal, result["signals"])


class LoadDomainsCommandTests(APITestCase):
    def test_loader_preserves_rank_and_skips_malformed_rows(self):
        with TemporaryDirectory() as temporary_directory:
            csv_path = Path(temporary_directory) / "domains.csv"
            csv_path.write_text(
                "1,Example.COM.\n2,sub.example.org\ninvalid,row\n3\n0,zero.test\n",
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()

            call_command(
                "load_domains",
                file=csv_path,
                batch_size=1,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(
            list(
                WhitelistDomain.objects.order_by("rank").values_list("rank", "domain")
            ),
            [(1, "example.com"), (2, "sub.example.org")],
        )
        self.assertIn("3 skipped", stdout.getvalue())


class ScanLogDataTests(APITestCase):
    def test_database_rejects_an_invalid_scan_status(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanLog.objects.create(
                origin="https://example.com",
                status="UNSUPPORTED",
                confidence=50,
            )

    def test_database_rejects_confidence_outside_percentage_range(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanLog.objects.create(
                origin="https://example.com",
                status=ScanLog.Status.SAFE,
                confidence=101,
            )


class ScanLogAdminTests(SimpleTestCase):
    def test_scan_logs_cannot_be_added_or_deleted_through_admin(self):
        model_admin = ScanLogAdmin(ScanLog, AdminSite())

        self.assertFalse(model_admin.has_add_permission(None))
        self.assertFalse(model_admin.has_delete_permission(None))


class PurgeScanLogsCommandTests(APITestCase):
    def setUp(self):
        self.old_scan = ScanLog.objects.create(
            origin="https://old.example.com",
            status=ScanLog.Status.UNKNOWN,
            confidence=0,
        )
        self.recent_scan = ScanLog.objects.create(
            origin="https://recent.example.com",
            status=ScanLog.Status.SAFE,
            confidence=90,
        )
        ScanLog.objects.filter(pk=self.old_scan.pk).update(
            timestamp=timezone.now() - timedelta(days=31)
        )

    @override_settings(PHISHGUARD_SCAN_RETENTION_DAYS=30)
    def test_dry_run_reports_without_deleting_then_purge_removes_only_old_rows(self):
        dry_run_output = StringIO()
        call_command("purge_scan_logs", dry_run=True, stdout=dry_run_output)

        self.assertEqual(ScanLog.objects.count(), 2)
        self.assertIn("Would delete 1", dry_run_output.getvalue())

        purge_output = StringIO()
        call_command("purge_scan_logs", stdout=purge_output)

        self.assertFalse(ScanLog.objects.filter(pk=self.old_scan.pk).exists())
        self.assertTrue(ScanLog.objects.filter(pk=self.recent_scan.pk).exists())
        self.assertIn("Deleted 1", purge_output.getvalue())

    def test_retention_days_must_be_positive(self):
        with self.assertRaisesMessage(CommandError, "at least 1"):
            call_command("purge_scan_logs", days=0)
