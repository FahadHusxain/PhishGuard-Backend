import bz2
import json
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from django.conf import settings
from django.test import SimpleTestCase

from ml_pipeline.candidate import CandidateModelError, LexicalCandidate
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


class DatasetPipelineTests(SimpleTestCase):
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
