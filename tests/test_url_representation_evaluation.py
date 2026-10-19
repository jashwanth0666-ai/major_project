import unittest
import csv
import tempfile
from pathlib import Path

import numpy as np

from api.inference.evaluate_url_representations import (
    _assert_hosts_disjoint,
    _cohort_masks,
    _probability_metrics,
    _read_evaluation_rows,
)


class UrlRepresentationEvaluationTests(unittest.TestCase):
    def test_metrics_use_the_frozen_threshold_and_return_confusion_rates(self):
        result = _probability_metrics(
            np.asarray([0, 0, 1, 1], dtype=np.int8),
            np.asarray([0.1, 0.4, 0.35, 0.8], dtype=float),
        )

        self.assertEqual(result["confusion_matrix"]["matrix"], [[1, 1], [0, 2]])
        self.assertAlmostEqual(result["precision"], 2 / 3)
        self.assertEqual(result["recall"], 1.0)
        self.assertAlmostEqual(result["f1"], 0.8)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertEqual(result["false_negative_rate"], 0.0)
        self.assertIn("brier_score", result)
        self.assertIn("expected_calibration_error_10_bins", result)

    def test_hostname_overlap_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "hostname leakage"):
            _assert_hosts_disjoint({"example.com", "training.example"}, ["example.com", "test.example"])

    def test_required_behavioral_cohorts_are_detected(self):
        urls = [
            "https://shop.example/orders/1572296968793876056",
            "https://example.net/account/verify?next=secure",
            "https://example.org/help/article",
        ]
        labels = np.asarray([0, 1, 0], dtype=np.int8)
        cohorts = _cohort_masks(urls, labels)

        self.assertEqual(cohorts["benign_with_long_numeric_path_segment"].tolist(), [True, False, False])
        self.assertEqual(cohorts["phishing_with_suspicious_path_or_query_keyword"].tolist(), [False, True, False])

    def test_csv_schema_keeps_paired_http_samples_and_counts_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "validation.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["url", "label", "source"])
                writer.writeheader()
                writer.writerow({"url": "https://one.example/path", "label": "benign", "source": "test"})
                writer.writerow({"url": "ftp://two.example/file", "label": "phishing", "source": "test"})

            urls, labels, eligible_hosts, all_group_hosts, excluded = _read_evaluation_rows(path)

        self.assertEqual(urls, ["https://one.example/path"])
        self.assertEqual(labels.tolist(), [0])
        self.assertEqual(len(eligible_hosts), 1)
        self.assertEqual(len(all_group_hosts), 2)
        self.assertEqual(excluded, {"unsupported_scheme": 1, "invalid_url": 0})


if __name__ == "__main__":
    unittest.main()
