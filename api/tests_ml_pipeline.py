import bz2
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from django.conf import settings
from django.test import SimpleTestCase

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
from ml_pipeline.evaluate_external import (
    _benign_urls,
    _phishing_urls,
    _score_in_batches,
    _verified_path,
    evaluate,
)
from ml_pipeline.train import (
    FEATURE_COUNT,
    _load_splits,
    _split_for_group,
    _write_deterministic_npz,
)
from ml_pipeline.train_open import (
    _deduplicated_splits,
    _lower_threshold,
    _triage_metrics,
    _upper_threshold,
)


class DatasetPipelineTests(SimpleTestCase):
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
