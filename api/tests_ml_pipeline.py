import bz2
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from django.conf import settings
from django.test import SimpleTestCase
from sklearn.ensemble import HistGradientBoostingClassifier

from api.ensemble_classifier import (
    PortableLexicalCandidate,
    RuntimeEnsembleClassifier,
)
from ml_pipeline import acquire_open_corpus, audit_current, audit_open
from ml_pipeline.audit_current import _phishtank_samples
from ml_pipeline.candidate import (
    CandidateModelError,
    LexicalCandidate,
    V2LexicalCandidate,
)
from ml_pipeline.corpus import (
    CorpusReadinessError,
    CorpusValidationError,
    URLSample,
    audit_corpus,
    normalize_corpus_url,
    quarantine_cross_label_groups,
    require_training_ready,
)
from ml_pipeline.dataset import (
    DatasetIntegrityError,
    acquire_archive,
    iter_labeled_urls,
    load_manifest,
    sha256_file,
)
from ml_pipeline.ensemble import ENSEMBLE_FEATURE_NAMES, EnsembleCandidate
from ml_pipeline.evaluate_external import (
    _benign_urls,
    _phishing_urls,
    _score_in_batches,
    _verified_path,
    evaluate,
)
from ml_pipeline.evaluate_v2_holdout import (
    HoldoutRecord,
    _base_rate_metrics,
    _benchmark,
    _gate_metrics,
    _prepare_records,
    _score,
    _slices,
)
from ml_pipeline.evaluate_v4_future import (
    FROZEN_POLICY_SHA256,
    FutureHoldoutError,
    _future_samples,
    _require_data_gate,
    _timestamp,
    evaluate_future,
)
from ml_pipeline.structural import (
    FEATURE_NAMES as STRUCTURAL_FEATURE_NAMES,
)
from ml_pipeline.structural import (
    StructuralCandidate,
    structural_features,
)
from ml_pipeline.train import (
    FEATURE_COUNT,
    _load_splits,
    _split_for_group,
    _write_deterministic_npz,
)
from ml_pipeline.train_ensemble import _gate as ensemble_gate
from ml_pipeline.train_ensemble import _load_policy as load_ensemble_policy
from ml_pipeline.train_open import (
    _deduplicated_splits,
    _lower_threshold,
    _triage_metrics,
    _upper_threshold,
)
from ml_pipeline.train_structural import _serialized_trees


class RuntimeEnsembleTests(SimpleTestCase):
    def test_portable_lexical_scorer_matches_training_implementation(self):
        model_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"
        portable = PortableLexicalCandidate(model_path)
        training = V2LexicalCandidate(model_path)
        urls = [
            "https://github.com/openai",
            "http://192.168.1.1/login",
            "https://www.linkedin.com/feed/",
            "https://www13.yts.lu/",
            "https://secure-login.verify-account.example/password",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertAlmostEqual(
                    portable.decision_function(url),
                    float(training.decision_function([url])[0]),
                    places=12,
                )

    def test_runtime_bundle_matches_evaluation_ensemble(self):
        ensemble_path = (
            settings.BASE_DIR / "ml_models" / "url_ensemble_candidate_v4.npz"
        )
        lexical_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"
        structural_path = (
            settings.BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz"
        )
        runtime = RuntimeEnsembleClassifier(
            ensemble_path, lexical_path, structural_path
        )
        evaluation = EnsembleCandidate(ensemble_path, lexical_path, structural_path)
        for url in (
            "https://github.com/openai",
            "http://192.168.1.1/login/verify",
            "https://www13.yts.lu/",
        ):
            with self.subTest(url=url):
                self.assertAlmostEqual(
                    runtime.predict_probability(url),
                    evaluation.predict_probability(url),
                    places=12,
                )

    def test_runtime_bundle_rejects_changed_artifact(self):
        with TemporaryDirectory() as temporary_directory:
            changed = Path(temporary_directory) / "changed.npz"
            shutil.copyfile(
                settings.BASE_DIR / "ml_models" / "url_ensemble_candidate_v4.npz",
                changed,
            )
            changed.write_bytes(changed.read_bytes() + b"changed")
            with self.assertRaisesRegex(CandidateModelError, "checksum"):
                RuntimeEnsembleClassifier(
                    changed,
                    settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz",
                    settings.BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz",
                )


def _future_manifest(directory: Path, candidate_sha256: str) -> Path:
    files = []
    fixtures = {
        "future-benign": (
            "benign",
            ["https://safe-one.com/path", "https://safe-two.org/page"],
        ),
        "future-phishing": (
            "phishing",
            ["https://bad-one.net/login", "https://bad-two.co.uk/verify"],
        ),
    }
    for source_id, (label, urls) in fixtures.items():
        path = directory / f"{source_id}.csv"
        path.write_text(
            "url,label,observed_at\n"
            + "".join(f"{url},{label},2026-09-13T00:00:00+00:00\n" for url in urls),
            encoding="utf-8",
        )
        files.append(
            {
                "source_id": source_id,
                "local_filename": path.name,
                "sha256": sha256_file(path),
                "byte_size": path.stat().st_size,
                "source_url": f"https://sources.example/{source_id}",
                "terms_url": f"https://sources.example/{source_id}/terms",
                "evaluation_rights_reviewed": True,
                "label_method": "controlled test fixture",
                "expected_columns": ["url", "label", "observed_at"],
            }
        )
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "manifest_version": 1,
                "snapshot_id": "future-fixture-2026-09-13",
                "candidate_sha256": candidate_sha256,
                "acquired_at": "2026-09-13T00:00:00+00:00",
                "files": files,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


class DatasetPipelineTests(SimpleTestCase):
    def test_future_holdout_loader_enforces_time_rights_and_checksums(self):
        policy = json.loads(
            (
                settings.BASE_DIR / "ml_pipeline" / "v4_future_evaluation_policy.json"
            ).read_text(encoding="utf-8")
        )
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest_path = _future_manifest(directory, policy["candidate_sha256"])

            samples, evidence = _future_samples(directory, manifest_path, policy)

            self.assertEqual(len(samples), 4)
            self.assertEqual(evidence["snapshot_id"], "future-fixture-2026-09-13")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["evaluation_rights_reviewed"] = False
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(FutureHoldoutError):
                _future_samples(directory, manifest_path, policy)

        with self.assertRaises(FutureHoldoutError):
            _timestamp("2026-09-13T00:00:00", "test_time")

    def test_future_holdout_data_gate_rejects_insufficient_evidence(self):
        policy = {
            "data_contract": {
                "minimum_retained_rows_per_label": 1,
                "minimum_independent_sources_total": 2,
                "minimum_independent_sources_per_label": 1,
            }
        }
        records = [
            HoldoutRecord(
                "https://safe.example/", 0, {"only-source"}, None, "safe.example"
            )
        ]

        with self.assertRaises(FutureHoldoutError):
            _require_data_gate(records, policy)

    def test_future_evaluator_writes_aggregate_no_tuning_report(self):
        policy_source = (
            settings.BASE_DIR / "ml_pipeline" / "v4_future_evaluation_policy.json"
        )
        policy = json.loads(policy_source.read_text(encoding="utf-8"))
        policy["data_contract"].update(
            {
                "minimum_retained_rows_per_label": 1,
                "minimum_independent_sources_total": 2,
                "minimum_independent_sources_per_label": 1,
                "minimum_rows_per_reported_slice": 1,
            }
        )
        policy["aggregate_gate"] = {
            "pr_auc_at_least": 0,
            "safe_precision_at_least": 0,
            "phishing_precision_at_least": 0,
            "decisive_coverage_at_least": 0,
            "false_safe_rate_at_most": 1,
            "false_phishing_rate_at_most": 1,
        }
        policy["source_quality_gate"] = {
            "minimum_retained_rows": 1,
            "false_safe_rate_at_most": 1,
            "false_phishing_rate_at_most": 1,
        }
        policy["operational_gate"] = {
            "total_artifact_size_bytes_at_most": 10_000_000,
            "single_url_p95_latency_ms_at_most": 100,
            "batch_throughput_urls_per_second_at_least": 1,
        }
        lexical_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"
        structural_path = (
            settings.BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz"
        )
        model_path = settings.BASE_DIR / "ml_models" / "url_ensemble_candidate_v4.npz"
        fake_candidate = SimpleNamespace(
            lower_threshold=0.2,
            upper_threshold=0.8,
            predict_probabilities=lambda urls: np.asarray(
                [0.01 if "safe" in url else 0.99 for url in urls]
            ),
        )
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            policy_path = directory / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            manifest_path = _future_manifest(directory, policy["candidate_sha256"])
            report_path = directory / "report.json"
            with (
                patch(
                    "ml_pipeline.evaluate_v4_future.FROZEN_POLICY_SHA256",
                    sha256_file(policy_path),
                ),
                patch(
                    "ml_pipeline.evaluate_v4_future._training_groups",
                    return_value=set(),
                ),
                patch(
                    "ml_pipeline.evaluate_v4_future.EnsembleCandidate",
                    return_value=fake_candidate,
                ),
                patch(
                    "ml_pipeline.evaluate_v4_future._benchmark",
                    return_value={
                        "artifact_size_bytes": model_path.stat().st_size,
                        "single_url_median_latency_ms": 1,
                        "single_url_p95_latency_ms": 2,
                        "batch_rows": 4,
                        "batch_throughput_urls_per_second": 1000,
                    },
                ),
            ):
                report = evaluate_future(
                    directory,
                    manifest_path,
                    policy_path,
                    model_path,
                    lexical_path,
                    structural_path,
                    report_path,
                )

            stored = report_path.read_text(encoding="utf-8")

        self.assertTrue(report["all_automated_gates_passed"])
        self.assertFalse(report["thresholds_changed"])
        self.assertFalse(report["promotion_ready"])
        self.assertNotRegex(stored, r"https?://")

    def test_ensemble_candidate_is_hash_bound_and_three_way(self):
        lexical_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"
        structural_path = (
            settings.BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz"
        )
        arrays = {
            "coefficients": np.asarray([[1.0, 1.0]]),
            "intercept": np.asarray([0.0]),
            "feature_names": np.asarray(ENSEMBLE_FEATURE_NAMES),
            "lexical_sha256": np.asarray([sha256_file(lexical_path)]),
            "structural_sha256": np.asarray([sha256_file(structural_path)]),
            "lower_threshold": np.asarray([0.25]),
            "upper_threshold": np.asarray([0.75]),
        }
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "ensemble.npz"
            _write_deterministic_npz(model_path, arrays)
            candidate = EnsembleCandidate(model_path, lexical_path, structural_path)

            with patch.object(
                candidate, "predict_probability", side_effect=[0.1, 0.5, 0.9]
            ):
                decisions = [
                    candidate.classify("https://example.test") for _ in range(3)
                ]

            arrays["lexical_sha256"] = np.asarray(["0" * 64])
            _write_deterministic_npz(model_path, arrays)
            with self.assertRaises(CandidateModelError):
                EnsembleCandidate(model_path, lexical_path, structural_path)

        self.assertEqual(decisions, ["SAFE", "UNKNOWN", "PHISHING"])

    def test_ensemble_development_gate_supports_both_bound_directions(self):
        metrics = {"precision": 0.99, "error_rate": 0.01}
        requirements = {
            "precision_at_least": 0.99,
            "error_rate_at_most": 0.005,
        }

        results, failures = ensemble_gate(metrics, requirements)

        self.assertTrue(results["precision_at_least"])
        self.assertFalse(results["error_rate_at_most"])
        self.assertEqual(failures, ["error_rate_at_most"])

        with self.assertRaises(RuntimeError):
            ensemble_gate(metrics, {"precision_equals": 0.99})

    def test_ensemble_policy_loader_rejects_contract_drift(self):
        source_path = settings.BASE_DIR / "ml_pipeline" / "v4_development_policy.json"
        policy = load_ensemble_policy(source_path)
        self.assertEqual(policy["candidate"], "v4_lexical_structural_ensemble")

        policy["partition_contract"]["historical_holdouts_must_not_be_loaded"] = False
        with TemporaryDirectory() as temporary_directory:
            invalid_path = Path(temporary_directory) / "policy.json"
            invalid_path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(RuntimeError):
                load_ensemble_policy(invalid_path)

    def test_structural_features_are_explicit_finite_and_scheme_neutral(self):
        urls = [
            "http://127.0.0.1:8080/login?verify=1",
            "https://xn--bcher-kva.example/account",
        ]

        features = structural_features(urls)
        positions = {name: index for index, name in enumerate(STRUCTURAL_FEATURE_NAMES)}

        self.assertEqual(features.shape, (2, len(STRUCTURAL_FEATURE_NAMES)))
        self.assertTrue(np.all(np.isfinite(features)))
        self.assertEqual(features[0, positions["ip_host"]], 1)
        self.assertEqual(features[0, positions["explicit_port"]], 1)
        self.assertEqual(features[1, positions["punycode_host"]], 1)
        self.assertNotIn("https", STRUCTURAL_FEATURE_NAMES)

    def test_structural_features_reject_malformed_urls(self):
        for url in ("not-a-url", "ftp://example.com/", "https://example.com:bad/"):
            with self.subTest(url=url), self.assertRaises(CandidateModelError):
                structural_features([url])

    def test_structural_candidate_matches_native_histogram_boosting_scores(self):
        urls = [
            f"https://safe{index}.example/path"
            if index % 2 == 0
            else f"http://192.0.2.{index % 250}/account/verify?id={index}"
            for index in range(80)
        ]
        labels = np.asarray([index % 2 for index in range(80)], dtype=np.int8)
        matrix = structural_features(urls)
        model = HistGradientBoostingClassifier(
            max_iter=4,
            max_leaf_nodes=5,
            min_samples_leaf=2,
            random_state=7,
        ).fit(matrix, labels)
        arrays = {
            **_serialized_trees(model),
            "baseline": np.asarray(model._baseline_prediction, dtype=np.float64),
            "calibration_coefficient": np.asarray([[1.0]]),
            "calibration_intercept": np.asarray([0.0]),
            "feature_names": np.asarray(STRUCTURAL_FEATURE_NAMES),
            "lower_threshold": np.asarray([0.25]),
            "upper_threshold": np.asarray([0.75]),
        }
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "structural.npz"
            _write_deterministic_npz(model_path, arrays)
            candidate = StructuralCandidate(model_path)

            portable = candidate.decision_function(urls)

        np.testing.assert_allclose(
            portable, model.decision_function(matrix), atol=1e-12
        )

    def test_structural_candidate_rejects_an_invalid_tree(self):
        arrays = {
            "values": np.asarray([0.0]),
            "features": np.asarray([0]),
            "thresholds": np.asarray([1.0]),
            "left": np.asarray([0]),
            "right": np.asarray([0]),
            "is_leaf": np.asarray([0]),
            "offsets": np.asarray([0, 1]),
            "baseline": np.asarray([0.0]),
            "calibration_coefficient": np.asarray([[1.0]]),
            "calibration_intercept": np.asarray([0.0]),
            "feature_names": np.asarray(STRUCTURAL_FEATURE_NAMES),
            "lower_threshold": np.asarray([0.25]),
            "upper_threshold": np.asarray([0.75]),
        }
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "invalid.npz"
            _write_deterministic_npz(model_path, arrays)

            with self.assertRaises(CandidateModelError):
                StructuralCandidate(model_path)

    def test_v2_source_registry_records_training_and_promotion_state(self):
        registry = json.loads(
            (settings.BASE_DIR / "ml_pipeline" / "source_registry.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(registry["contract_version"], 2)
        self.assertTrue(registry["training_ready"])
        self.assertFalse(registry["promotion_ready"])
        self.assertTrue(registry["promotion_blockers"])
        self.assertEqual(registry["sources"]["phiusiil"]["license"], "CC BY 4.0")
        self.assertTrue(registry["sources"]["phiusiil"]["training_rights_confirmed"])
        self.assertFalse(
            registry["sources"]["phishtank_snapshot_2026_09_10"][
                "training_rights_confirmed"
            ]
        )
        self.assertTrue(
            registry["sources"]["phreshphish_v1.0.1_train"]["training_rights_confirmed"]
        )
        self.assertEqual(
            registry["candidate_evaluations"]["v2_lexical"]["status"],
            "rejected_by_holdout_gate",
        )
        self.assertFalse(
            registry["candidate_evaluations"]["v2_lexical"][
                "thresholds_changed_after_holdout"
            ]
        )
        self.assertEqual(
            registry["candidate_evaluations"]["v3_structural"]["status"],
            "rejected_by_development_evidence",
        )
        self.assertFalse(
            registry["candidate_evaluations"]["v3_structural"][
                "opened_holdouts_used_for_training_or_selection"
            ]
        )
        self.assertEqual(
            registry["candidate_evaluations"]["v4_ensemble"]["status"],
            "development_selected_awaiting_future_holdout",
        )

    def test_open_corpus_manifest_is_immutable_and_url_only(self):
        manifest = acquire_open_corpus.load_open_manifest()

        self.assertRegex(manifest["phreshphish"]["revision"], r"^[0-9a-f]{40}$")
        self.assertEqual(
            manifest["phreshphish"]["projected_columns"],
            ["sha256", "url", "label", "date"],
        )
        self.assertNotIn("html", manifest["phreshphish"]["projected_columns"])
        self.assertRegex(manifest["phreshphish"]["output_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(manifest["phishvn"]["archive_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(manifest["phreshphish"]["holdout"]["split"], "test")
        self.assertEqual(manifest["phreshphish"]["holdout"]["reported_rows"], 168060)
        self.assertRegex(
            manifest["phreshphish"]["holdout"]["output_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_v2_corpus_normalization_is_stable_and_offline(self):
        normalized, group = normalize_corpus_url(
            "HTTPS://Example.COM:443/a/../login?q=1#private"
        )

        self.assertEqual(normalized, "https://example.com/a/../login?q=1")
        self.assertEqual(group, "example.com")

    def test_v2_corpus_rejects_credentials_and_naive_timestamps(self):
        with self.assertRaises(CorpusValidationError):
            normalize_corpus_url("https://user:secret@example.com/")
        with self.assertRaises(CorpusValidationError):
            URLSample(
                "https://example.com/",
                0,
                "source",
                datetime(2026, 1, 1),
                True,
            )
        with self.assertRaises(CorpusValidationError):
            URLSample("https://example.com/", True, "source", None, True)
        with self.assertRaises(CorpusValidationError):
            URLSample("https://example.com/", 0, "source", None, "yes")
        with self.assertRaises(CorpusValidationError):
            URLSample("", 0, "source", None, True)
        with self.assertRaises(CorpusValidationError):
            URLSample("https://example.com/", 0, "Source Name", None, True)
        with self.assertRaises(CorpusValidationError):
            normalize_corpus_url(None)

    def test_v2_corpus_gate_rejects_source_and_representation_shortcuts(self):
        observed_at = datetime(2026, 1, 1, tzinfo=UTC)
        samples = [
            URLSample("https://safe.example/", 0, "benign-feed", observed_at, True),
            URLSample(
                "https://other.example/",
                0,
                "domain-list",
                observed_at,
                True,
                representation="domain",
            ),
            URLSample("https://phish.test/login", 1, "phish-feed", observed_at, True),
        ]

        report = audit_corpus(samples, min_samples_per_label=2)

        self.assertFalse(report["training_ready"])
        self.assertLess(report["full_url_coverage"]["benign"], 0.95)
        with self.assertRaises(CorpusReadinessError):
            require_training_ready(report)

    def test_v2_corpus_gate_accepts_diverse_dated_full_urls(self):
        observed_at = datetime(2026, 1, 1, tzinfo=UTC)
        samples = [
            URLSample(
                "https://safe-one.example/path", 0, "benign-a", observed_at, True
            ),
            URLSample(
                "https://safe-two.example/path", 0, "benign-b", observed_at, True
            ),
            URLSample("https://bad-one.test/login", 1, "phish-a", observed_at, True),
            URLSample("https://bad-two.test/login", 1, "phish-b", observed_at, True),
        ]

        report = audit_corpus(samples, min_samples_per_label=2)

        self.assertTrue(report["training_ready"])
        require_training_ready(report)

    def test_v2_corpus_duplicates_cannot_inflate_readiness_coverage(self):
        observed_at = datetime(2026, 1, 1, tzinfo=UTC)
        duplicate = URLSample(
            "https://safe-one.com/path", 0, "benign-a", observed_at, True
        )
        samples = [
            duplicate,
            duplicate,
            URLSample("https://safe-two.org/", 0, "benign-b", None, True, "origin"),
            URLSample("https://bad-one.net/login", 1, "phish-a", observed_at, True),
            URLSample("https://bad-two.co.uk/", 1, "phish-b", observed_at, True),
        ]

        report = audit_corpus(samples, min_samples_per_label=2)

        self.assertEqual(report["labels"]["benign"], 2)
        self.assertEqual(report["timestamp_coverage"]["benign"], 0.5)
        self.assertEqual(report["full_url_coverage"]["benign"], 0.5)
        self.assertFalse(report["training_ready"])

    def test_v2_corpus_gate_rejects_unlicensed_samples(self):
        observed_at = datetime(2026, 1, 1, tzinfo=UTC)
        samples = [
            URLSample("https://safe-one.example/", 0, "benign-a", observed_at, True),
            URLSample("https://safe-two.example/", 0, "benign-b", observed_at, False),
            URLSample("https://bad-one.test/", 1, "phish-a", observed_at, True),
            URLSample("https://bad-two.test/", 1, "phish-b", observed_at, True),
        ]

        report = audit_corpus(samples)

        self.assertFalse(report["training_ready"])
        self.assertEqual(report["licensed_coverage"]["benign"], 0.5)

    def test_v2_corpus_removes_conflicting_normalized_urls(self):
        observed_at = datetime(2026, 1, 1, tzinfo=UTC)
        samples = [
            URLSample("https://example.com", 0, "source-a", observed_at, True),
            URLSample(
                "https://EXAMPLE.com:443/#fragment",
                1,
                "source-b",
                observed_at,
                True,
            ),
        ]

        report = audit_corpus(samples)

        self.assertEqual(report["conflicting_urls"], 1)
        self.assertEqual(report["retained_urls"], 0)

    def test_v2_corpus_quarantines_entire_cross_label_domains(self):
        samples = [
            URLSample("https://example.com/safe", 0, "source-a", None, True),
            URLSample("https://sub.example.com/phish", 1, "source-b", None, True),
            URLSample("not-a-url", 1, "source-b", None, True),
            URLSample("https://retained.org/", 0, "source-a", None, True),
        ]

        retained, report = quarantine_cross_label_groups(samples)

        self.assertEqual([sample.url for sample in retained], ["https://retained.org/"])
        self.assertEqual(report["quarantined_groups"], 1)
        self.assertEqual(report["quarantined_rows"], 2)
        self.assertEqual(report["invalid_rows"], 1)

    def test_v2_training_splits_are_deduplicated_and_group_isolated(self):
        samples = [
            URLSample("https://a.example.com/path", 0, "source-a", None, True),
            URLSample("https://a.example.com/path", 0, "source-b", None, True),
            URLSample("https://b.example.com/other", 0, "source-a", None, True),
            URLSample("https://malicious.test/login", 1, "source-a", None, True),
        ]

        splits, corpus = _deduplicated_splits(samples)

        self.assertEqual(corpus["unique_urls"], 3)
        self.assertEqual(corpus["duplicate_rows_removed"], 1)
        containing_splits = [
            name for name, split in splits.items() if "example.com" in split["groups"]
        ]
        self.assertEqual(len(containing_splits), 1)

    def test_v2_dual_thresholds_preserve_precision_and_unknown_region(self):
        labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.int8)
        probabilities = np.asarray([0.01, 0.02, 0.4, 0.6, 0.98, 0.99])

        lower = _lower_threshold(labels, probabilities)
        upper = _upper_threshold(labels, probabilities)
        metrics = _triage_metrics(labels, probabilities, lower, upper)

        self.assertEqual(lower, 0.4)
        self.assertEqual(upper, 0.6)
        self.assertEqual(metrics["safe_precision"], 1.0)
        self.assertEqual(metrics["phishing_precision"], 1.0)
        self.assertLess(lower, upper)

    def test_v2_thresholds_do_not_split_tied_probability_groups(self):
        tied_probabilities = np.asarray([0.5, 0.5])

        with self.assertRaises(RuntimeError):
            _lower_threshold(np.asarray([0, 1], dtype=np.int8), tied_probabilities)
        with self.assertRaises(RuntimeError):
            _upper_threshold(np.asarray([1, 0], dtype=np.int8), tied_probabilities)

    def test_v2_holdout_preparation_excludes_contamination_and_conflicts(self):
        samples = [
            URLSample("https://train.example.org/new", 0, "source-a", None, True),
            URLSample("https://a.example.com/safe", 0, "source-a", None, True),
            URLSample("https://b.example.com/phish", 1, "source-b", None, True),
            URLSample("https://retained.example.net/path", 1, "source-a", None, True),
            URLSample("https://retained.example.net/path", 1, "source-b", None, True),
            URLSample("not-a-url", 1, "source-b", None, True),
        ]

        records, exclusions = _prepare_records(samples, {"example.org"})

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].sources, {"source-a", "source-b"})
        self.assertEqual(exclusions["training_overlap_rows_removed"], 1)
        self.assertEqual(exclusions["ambiguous_groups_quarantined"], 1)
        self.assertEqual(exclusions["ambiguous_rows_quarantined"], 2)
        self.assertEqual(exclusions["duplicate_rows_removed"], 1)
        self.assertEqual(exclusions["invalid_rows"], 1)

    def test_v2_holdout_gate_and_base_rate_math_are_explicit(self):
        metrics = {
            "pr_auc": 0.96,
            "safe_precision": 0.995,
            "phishing_precision": 0.995,
            "decisive_coverage": 0.6,
            "false_safe_rate": 0.005,
            "false_phishing_rate": 0.001,
            "benign_recall": 0.8,
            "phishing_recall": 0.6,
        }
        gate = {
            "pr_auc_at_least": 0.95,
            "safe_precision_at_least": 0.99,
            "phishing_precision_at_least": 0.99,
            "decisive_coverage_at_least": 0.5,
            "false_safe_rate_at_most": 0.01,
            "false_phishing_rate_at_most": 0.005,
        }

        passed, failures = _gate_metrics(metrics, gate)
        scenarios = _base_rate_metrics(metrics, [0.01])

        self.assertTrue(passed)
        self.assertEqual(failures, [])
        self.assertEqual(scenarios[0]["phishing_prevalence"], 0.01)
        self.assertGreater(scenarios[0]["estimated_safe_precision"], 0.99)

    def test_v2_holdout_slices_and_operational_benchmark_are_aggregate_only(self):
        records = [
            HoldoutRecord(
                "https://example.com/login?confirm=1",
                1,
                {"source-a"},
                datetime(2025, 1, 2, tzinfo=UTC),
                "example.com",
            ),
            HoldoutRecord(
                "http://127.0.0.1/",
                1,
                {"source-a"},
                None,
                "127.0.0.1",
            ),
            HoldoutRecord(
                "https://xn--bcher-kva.example/",
                0,
                {"source-b"},
                datetime(2025, 2, 3, tzinfo=UTC),
                "xn--bcher-kva.example",
            ),
        ]
        labels = np.asarray([1, 1, 0], dtype=np.int8)
        probabilities = np.asarray([0.99, 0.5, 0.01])

        slices = _slices(records, labels, probabilities, 0.1, 0.9, 1)

        self.assertEqual(slices["host_type"]["ip"]["rows"], 1)
        self.assertEqual(slices["host_type"]["idn"]["rows"], 1)
        self.assertEqual(slices["query"]["present"]["rows"], 1)
        self.assertEqual(slices["lure_terms"]["present"]["rows"], 1)
        self.assertIn("2025-01", slices["month"])

        fake_candidate = SimpleNamespace(
            predict_probabilities=lambda urls: np.full(len(urls), 0.25),
            predict_probability=lambda _url: 0.25,
        )
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "model.npz"
            model_path.write_bytes(b"model")
            scores = _score(fake_candidate, [record.url for record in records])
            benchmark = _benchmark(
                fake_candidate, [record.url for record in records], model_path
            )

        self.assertEqual(scores.tolist(), [0.25, 0.25, 0.25])
        self.assertEqual(benchmark["artifact_size_bytes"], 5)
        self.assertGreater(benchmark["batch_throughput_urls_per_second"], 0)

    def test_open_corpus_phreshphish_parser_preserves_labels_and_dates(self):
        content = (
            "sha256,url,label,date\n"
            f"{'a' * 64},https://safe.example/path,benign,2025-01-02\n"
            f"{'b' * 64},https://bad.test/login,phish,2025-01-03\n"
        )
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "projected.csv"
            path.write_text(content, encoding="utf-8")

            samples = list(audit_open._phreshphish_samples(path))

        self.assertEqual([sample.label for sample in samples], [0, 1])
        self.assertEqual(samples[0].observed_at, datetime(2025, 1, 2, tzinfo=UTC))
        self.assertTrue(all(sample.representation == "full_url" for sample in samples))

    def test_open_corpus_phishvn_parser_filters_holdouts_and_bronze(self):
        header = "label,tier,split,url_norm,collected_at\n"
        content = (
            header
            + "benign,gold,train,https://safe.example/,02/01/2025\n"
            + "phishing,bronze,train,https://bronze.test/,03/01/2025\n"
            + "phishing,silver,test,https://holdout.test/,04/01/2025\n"
        )
        source_manifest = {
            "eligible_tiers": ["gold", "silver"],
            "eligible_splits": ["train"],
            "csv_member": "data/dataset_url.csv",
        }
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "phishvn.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(source_manifest["csv_member"], content)

            samples = list(audit_open._phishvn_samples(path, source_manifest))

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].source, "phishvn-v3.1.0")
        self.assertEqual(samples[0].representation, "origin")

    def test_projected_open_corpus_is_verified_without_network(self):
        content = f"sha256,url,label,date\n{'a' * 64},https://safe.example,benign,2025-01-02\n"
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "projected.csv"
            path.write_text(content, encoding="utf-8")
            source = {
                "local_filename": path.name,
                "output_sha256": sha256_file(path),
                "reported_rows": 1,
            }

            result_path, result_hash = acquire_open_corpus.acquire_phreshphish(
                Path(temporary_directory), {"phreshphish": source}
            )

        self.assertEqual(result_path, path)
        self.assertEqual(result_hash, source["output_sha256"])

    def test_phreshphish_holdout_wrapper_inherits_pinned_revision(self):
        manifest = {
            "phreshphish": {
                "revision": "a" * 40,
                "holdout": {"split": "test", "shard_count": 2},
            }
        }
        expected = (Path("holdout.csv"), "b" * 64)
        with patch(
            "ml_pipeline.acquire_open_corpus.acquire_phreshphish",
            return_value=expected,
        ) as acquire:
            result = acquire_open_corpus.acquire_phreshphish_holdout(
                Path("data"), manifest
            )

        self.assertEqual(result, expected)
        projected = acquire.call_args.args[1]["phreshphish"]
        self.assertEqual(projected["revision"], "a" * 40)
        self.assertEqual(projected["split"], "test")

    def test_v2_phishtank_parser_preserves_time_and_unconfirmed_rights(self):
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "phishtank.csv.bz2"
            with bz2.open(path, "wt", encoding="utf-8", newline="") as source:
                source.write(
                    "url,verification_time,verified\n"
                    "https://bad.example/login,2026-09-10T12:30:00+00:00,yes\n"
                )

            samples = list(_phishtank_samples(path, license_confirmed=False))

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].source, "phishtank-2026-09-10")
        self.assertEqual(samples[0].observed_at.tzinfo, UTC)
        self.assertFalse(samples[0].license_confirmed)

    def test_v2_phishtank_parser_rejects_unverified_rows(self):
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "phishtank.csv.bz2"
            with bz2.open(path, "wt", encoding="utf-8", newline="") as source:
                source.write(
                    "url,verification_time,verified\n"
                    "https://unknown.example/,2026-09-10T12:30:00+00:00,no\n"
                )

            with self.assertRaises(DatasetIntegrityError):
                list(_phishtank_samples(path, license_confirmed=False))

    def test_v2_current_audit_verifies_external_snapshot_hash(self):
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "source.bin"
            path.write_bytes(b"verified snapshot")
            source = {"local_filename": path.name, "sha256": sha256_file(path)}

            self.assertEqual(
                audit_current._verified_external_path(
                    Path(temporary_directory), source
                ),
                path,
            )
            source["sha256"] = "0" * 64
            with self.assertRaises(DatasetIntegrityError):
                audit_current._verified_external_path(Path(temporary_directory), source)

    def test_v2_current_audit_reports_only_eligible_full_url_sources(self):
        observed_at = datetime(2026, 1, 1, tzinfo=UTC)
        registry = {
            "sources": {
                "phiusiil": {"training_rights_confirmed": True},
                "phishtank_snapshot_2026_09_10": {"training_rights_confirmed": False},
            }
        }
        external_manifest = {"sources": {"phishing": {}}}
        with (
            patch(
                "ml_pipeline.audit_current._load_json",
                side_effect=[external_manifest, registry],
            ),
            patch(
                "ml_pipeline.audit_current.acquire_archive",
                return_value=Path("phiusiil.zip"),
            ),
            patch(
                "ml_pipeline.audit_current._verified_external_path",
                return_value=Path("phishtank.csv.bz2"),
            ),
            patch(
                "ml_pipeline.audit_current._phiusiil_samples",
                return_value=iter(
                    [URLSample("https://safe.example/", 0, "phiusiil", None, True)]
                ),
            ),
            patch(
                "ml_pipeline.audit_current._phishtank_samples",
                return_value=iter(
                    [
                        URLSample(
                            "https://bad.test/",
                            1,
                            "phishtank-2026-09-10",
                            observed_at,
                            False,
                        )
                    ]
                ),
            ),
        ):
            report = audit_current.audit_current_sources(Path(".ml-data"))

        self.assertFalse(report["training_ready"])
        self.assertEqual(
            report["excluded_sources"],
            {"tranco-2026-09-10": "bare domains are not genuine benign full URLs"},
        )

    def test_v2_current_audit_cli_writes_aggregate_report(self):
        with TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "nested" / "report.json"
            with (
                patch(
                    "sys.argv",
                    ["audit_current", "--report", str(report_path)],
                ),
                patch(
                    "ml_pipeline.audit_current.audit_current_sources",
                    return_value={"training_ready": False},
                ),
                patch("builtins.print"),
            ):
                audit_current.main()

            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report, {"training_ready": False})

    def test_committed_manifest_has_required_provenance(self):
        manifest = load_manifest()

        self.assertEqual(manifest["uci_id"], 967)
        self.assertEqual(manifest["license"], "CC BY 4.0")
        self.assertEqual(len(manifest["archive_sha256"]), 64)
        self.assertTrue(manifest["paper_doi"].startswith("https://doi.org/"))

    def test_archive_hash_mismatch_is_rejected(self):
        with TemporaryDirectory() as temporary_directory:
            archive_path = Path(temporary_directory) / "dataset.zip"
            archive_path.write_bytes(b"not the expected archive")

            with self.assertRaises(DatasetIntegrityError):
                acquire_archive(archive_path)

    def test_parser_maps_source_zero_to_internal_phishing_label(self):
        manifest = load_manifest()
        content = "URL,label\nhttps://safe.example,1\nhttps://bad.example,0\n"
        with TemporaryDirectory() as temporary_directory:
            archive_path = Path(temporary_directory) / "dataset.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(manifest["csv_member"], content)

            rows = list(iter_labeled_urls(archive_path))

        self.assertEqual(
            rows,
            [("https://safe.example", 0), ("https://bad.example", 1)],
        )

    def test_domain_groups_never_cross_splits_and_duplicates_are_removed(self):
        rows = [
            ("https://a.example.com/path", 0),
            ("https://b.example.com/login", 1),
            ("https://a.example.com/path", 0),
            ("https://other.example.org", 1),
        ]
        with patch("ml_pipeline.train.iter_labeled_urls", return_value=iter(rows)):
            splits, source_rows, duplicates, conflicts = _load_splits(Path("unused"))

        containing_splits = [
            name for name, split in splits.items() if "example.com" in split["groups"]
        ]
        self.assertEqual(containing_splits, [_split_for_group("example.com")])
        self.assertEqual(source_rows, 4)
        self.assertEqual(duplicates, 1)
        self.assertEqual(conflicts, 0)

    def test_candidate_artifact_matches_report_and_contains_no_pickle(self):
        model_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate.npz"
        report = json.loads(
            (settings.BASE_DIR / "ml_models" / "CANDIDATE_EVALUATION.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(sha256_file(model_path), report["model_sha256"])
        self.assertEqual(report["candidate_status"], "NOT_PROMOTED")
        self.assertFalse(report["promotion_gate"]["metric_gate_passed"])
        with np.load(model_path, allow_pickle=False) as artifact:
            self.assertEqual(artifact["coefficients"].shape, (1, FEATURE_COUNT))
            self.assertEqual(artifact["ngram_range"].tolist(), [3, 5])

        external_report = json.loads(
            (settings.BASE_DIR / "ml_models" / "EXTERNAL_EVALUATION.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(external_report["model_sha256"], report["model_sha256"])
        self.assertFalse(external_report["metric_gate_passed"])

    def test_v2_candidate_artifact_matches_frozen_development_report(self):
        model_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"
        report = json.loads(
            (
                settings.BASE_DIR / "ml_models" / "V2_CANDIDATE_DEVELOPMENT.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(sha256_file(model_path), report["model_sha256"])
        self.assertEqual(report["pipeline_version"], 2)
        self.assertEqual(report["candidate_status"], "NOT_PROMOTED")
        self.assertFalse(report["final_holdouts_opened"])
        self.assertTrue(all(not passed for passed in report["promotion_gate"].values()))
        for split in report["splits"].values():
            self.assertEqual(split["rows"], split["benign"] + split["phishing"])

        candidate = V2LexicalCandidate(model_path)
        self.assertLess(candidate.lower_threshold, candidate.upper_threshold)
        self.assertIn(
            candidate.classify("https://example.com/login"),
            {"SAFE", "UNKNOWN", "PHISHING"},
        )

    def test_v2_holdout_policy_is_frozen_to_candidate_before_evaluation(self):
        policy = json.loads(
            (settings.BASE_DIR / "ml_pipeline" / "v2_evaluation_policy.json").read_text(
                encoding="utf-8"
            )
        )
        model_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"

        self.assertEqual(policy["candidate_sha256"], sha256_file(model_path))
        self.assertTrue(policy["thresholds_are_frozen"])
        self.assertEqual(len(policy["holdouts"]), 2)
        self.assertTrue(
            policy["contamination_policy"][
                "exclude_any_registrable_domain_seen_in_training"
            ]
        )
        self.assertGreaterEqual(
            policy["aggregate_gate"]["safe_precision_at_least"], 0.99
        )
        self.assertGreaterEqual(
            policy["aggregate_gate"]["phishing_precision_at_least"], 0.99
        )

    def test_v3_structural_artifact_matches_rejected_development_report(self):
        model_path = settings.BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz"
        report = json.loads(
            (
                settings.BASE_DIR / "ml_models" / "V3_STRUCTURAL_DEVELOPMENT.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(report["model_sha256"], sha256_file(model_path))
        self.assertEqual(report["candidate_status"], "REJECTED_BY_DEVELOPMENT_EVIDENCE")
        self.assertFalse(report["opened_holdouts_used_for_training_or_selection"])
        self.assertFalse(report["promotion_ready"])
        self.assertTrue(
            all(not passed for passed in report["development_gate"].values())
        )
        self.assertTrue(
            all(
                comparison["delta"] < 0
                for comparison in report["v2_development_comparison"].values()
            )
        )
        StructuralCandidate(model_path)

    def test_v4_development_policy_is_frozen_to_both_components(self):
        policy = json.loads(
            (
                settings.BASE_DIR / "ml_pipeline" / "v4_development_policy.json"
            ).read_text(encoding="utf-8")
        )

        for component in policy["components"].values():
            artifact_path = (
                settings.BASE_DIR / "ml_pipeline" / component["artifact"]
            ).resolve()
            self.assertEqual(component["sha256"], sha256_file(artifact_path))
        self.assertTrue(
            policy["partition_contract"]["historical_holdouts_must_not_be_loaded"]
        )
        self.assertGreaterEqual(
            policy["development_acceptance_gate"]["safe_precision_at_least"],
            0.99,
        )
        self.assertGreaterEqual(
            policy["development_acceptance_gate"]["phishing_precision_at_least"],
            0.99,
        )
        self.assertIn("new future temporal holdout", policy["if_gate_passes"])

    def test_v4_future_policy_is_bound_before_snapshot_acquisition(self):
        policy_path = (
            settings.BASE_DIR / "ml_pipeline" / "v4_future_evaluation_policy.json"
        )
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        development_report = json.loads(
            (
                settings.BASE_DIR / "ml_models" / "V4_ENSEMBLE_DEVELOPMENT.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(
            policy["candidate_commit"],
            "b62de62baef9cc12a0a90b1dce411678ed82b997",
        )
        self.assertEqual(FROZEN_POLICY_SHA256, sha256_file(policy_path))
        self.assertEqual(policy["candidate_sha256"], development_report["model_sha256"])
        self.assertEqual(
            policy["component_sha256"], development_report["component_sha256"]
        )
        self.assertTrue(policy["thresholds_are_frozen"])
        self.assertTrue(
            policy["data_contract"]["every_observation_after_candidate_freeze"]
        )
        self.assertGreaterEqual(
            policy["data_contract"]["minimum_retained_rows_per_label"], 2000
        )

        example = json.loads(
            (
                settings.BASE_DIR
                / "ml_pipeline"
                / "future_holdout_manifest.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(example["files"][0]["evaluation_rights_reviewed"])

    def test_v4_ensemble_artifact_matches_selected_development_report(self):
        model_path = settings.BASE_DIR / "ml_models" / "url_ensemble_candidate_v4.npz"
        policy_path = settings.BASE_DIR / "ml_pipeline" / "v4_development_policy.json"
        lexical_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"
        structural_path = (
            settings.BASE_DIR / "ml_models" / "url_structural_candidate_v3.npz"
        )
        report_path = settings.BASE_DIR / "ml_models" / "V4_ENSEMBLE_DEVELOPMENT.json"
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)

        self.assertEqual(report["model_sha256"], sha256_file(model_path))
        self.assertEqual(report["policy_sha256"], sha256_file(policy_path))
        self.assertEqual(
            report["candidate_status"],
            "DEVELOPMENT_SELECTED_AWAITING_FUTURE_HOLDOUT",
        )
        self.assertTrue(report["development_gate"]["passed"])
        self.assertTrue(all(report["development_gate"]["results"].values()))
        self.assertFalse(report["opened_holdouts_used_for_training_or_selection"])
        self.assertFalse(report["promotion_ready"])
        self.assertNotRegex(report_text, r"https?://")

        candidate = EnsembleCandidate(model_path, lexical_path, structural_path)
        probability = candidate.predict_probability("https://example.com/login")
        self.assertGreaterEqual(probability, 0)
        self.assertLessEqual(probability, 1)

    def test_v2_holdout_report_preserves_failed_frozen_evaluation(self):
        report_path = settings.BASE_DIR / "ml_models" / "V2_HOLDOUT_EVALUATION.json"
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)
        policy_path = settings.BASE_DIR / "ml_pipeline" / "v2_evaluation_policy.json"
        model_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate_v2.npz"

        self.assertEqual(report["candidate_sha256"], sha256_file(model_path))
        self.assertEqual(report["policy_sha256"], sha256_file(policy_path))
        self.assertEqual(report["candidate_status"], "REJECTED_BY_HOLDOUT_GATE")
        self.assertFalse(report["thresholds_changed"])
        self.assertFalse(report["all_required_gates_passed"])
        self.assertFalse(report["promotion_ready"])
        self.assertTrue(report["operational_gate_passed"])
        self.assertIn("safe_precision", report["aggregate_gate_failures"])
        self.assertNotRegex(report_text, r"https?://")

    def test_candidate_archive_writer_is_byte_reproducible(self):
        arrays = {
            "weights": np.asarray([[1.0, 2.0]], dtype=np.float32),
            "threshold": np.asarray([0.5], dtype=np.float32),
        }
        with TemporaryDirectory() as temporary_directory:
            first = Path(temporary_directory) / "first.npz"
            second = Path(temporary_directory) / "second.npz"
            _write_deterministic_npz(first, arrays)
            _write_deterministic_npz(second, arrays)

            self.assertEqual(sha256_file(first), sha256_file(second))

    def test_candidate_adapter_scores_without_loading_executable_objects(self):
        model_path = settings.BASE_DIR / "ml_models" / "url_lexical_candidate.npz"
        candidate = LexicalCandidate(model_path)

        probability = candidate.predict_probability("https://example.com/login")

        self.assertGreaterEqual(probability, 0.0)
        self.assertLessEqual(probability, 1.0)
        self.assertIsInstance(candidate.predict("https://example.com/login"), bool)

    def test_candidate_adapter_rejects_an_incomplete_artifact(self):
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "invalid.npz"
            np.savez(model_path, unrelated=np.asarray([1]))

            with self.assertRaises(CandidateModelError):
                LexicalCandidate(model_path)

    def test_v2_candidate_returns_safe_unknown_and_phishing(self):
        arrays = {
            "calibration_coefficient": np.asarray([[1.0]], dtype=np.float32),
            "calibration_intercept": np.asarray([0.0], dtype=np.float32),
            "coefficients": np.zeros((1, 4), dtype=np.float32),
            "feature_count": np.asarray([4], dtype=np.int64),
            "intercept": np.asarray([0.0], dtype=np.float32),
            "lower_threshold": np.asarray([0.2], dtype=np.float32),
            "ngram_range": np.asarray([3, 5], dtype=np.int64),
            "threshold": np.asarray([0.8], dtype=np.float32),
            "upper_threshold": np.asarray([0.8], dtype=np.float32),
        }
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "v2.npz"
            _write_deterministic_npz(model_path, arrays)
            candidate = V2LexicalCandidate(model_path)

            with patch.object(
                candidate, "predict_probability", side_effect=[0.1, 0.5, 0.9]
            ):
                decisions = [
                    candidate.classify("https://example.test") for _ in range(3)
                ]

        self.assertEqual(decisions, ["SAFE", "UNKNOWN", "PHISHING"])

    def test_external_source_hash_and_parsers(self):
        with TemporaryDirectory() as temporary_directory:
            data_directory = Path(temporary_directory)
            phishing_path = data_directory / "phishing.csv.bz2"
            with bz2.open(phishing_path, "wt", encoding="utf-8") as source:
                source.write(
                    "url\nhttps://bad.example/login\nhttps://excluded.example/path\n"
                )
            source_config = {
                "local_filename": phishing_path.name,
                "sha256": sha256_file(phishing_path),
            }
            self.assertEqual(
                _verified_path(data_directory, source_config), phishing_path
            )
            phishing_urls, phishing_groups = _phishing_urls(
                phishing_path, {"excluded.example"}
            )

            benign_path = data_directory / "benign.zip"
            with zipfile.ZipFile(benign_path, "w") as archive:
                archive.writestr(
                    "top-1m.csv",
                    "1,excluded.example\n2,safe.example.org\n3,other.example.net\n",
                )
            benign_urls, benign_groups = _benign_urls(
                benign_path,
                {"excluded.example"},
                2,
            )

        self.assertEqual(phishing_urls, ["https://bad.example/login"])
        self.assertEqual(phishing_groups, {"bad.example"})
        self.assertEqual(
            benign_urls,
            ["https://safe.example.org/", "https://other.example.net/"],
        )
        self.assertEqual(benign_groups, {"example.org", "example.net"})

    def test_external_evaluation_writes_a_no_tuning_report(self):
        fake_candidate = SimpleNamespace(threshold=0.5)
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            model_path = directory / "model.npz"
            model_path.write_bytes(b"candidate")
            report_path = directory / "report.json"
            with (
                patch("ml_pipeline.evaluate_external.acquire_archive"),
                patch(
                    "ml_pipeline.evaluate_external._training_groups",
                    return_value={"training.example"},
                ),
                patch(
                    "ml_pipeline.evaluate_external._verified_path",
                    return_value=directory / "source",
                ),
                patch(
                    "ml_pipeline.evaluate_external._phishing_urls",
                    return_value=(["https://bad.example"], {"bad.example"}),
                ),
                patch(
                    "ml_pipeline.evaluate_external._benign_urls",
                    return_value=(["https://safe.example"], {"safe.example"}),
                ),
                patch(
                    "ml_pipeline.evaluate_external.LexicalCandidate",
                    return_value=fake_candidate,
                ),
                patch(
                    "ml_pipeline.evaluate_external._score_in_batches",
                    return_value=np.asarray([0.1, 0.9]),
                ),
            ):
                report = evaluate(directory, model_path, report_path)

            stored_report = json.loads(report_path.read_text())

        self.assertTrue(report["metric_gate_passed"])
        self.assertEqual(report["evaluation_type"], "frozen cross-source, no tuning")
        self.assertEqual(stored_report, report)

    def test_batch_scorer_concatenates_candidate_outputs(self):
        candidate = SimpleNamespace(
            predict_probabilities=lambda urls: np.full(len(urls), 0.25)
        )

        scores = _score_in_batches(candidate, ["url"] * 10_001)

        self.assertEqual(scores.shape, (10_001,))
        self.assertTrue(np.all(scores == 0.25))
