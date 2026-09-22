import json
import math
import unittest
import ast
from pathlib import Path

import numpy as np
import pandas as pd

from create_master import extract_features as training_extract_features
from create_master import normalize_url as training_normalize_url
from phase5_inference import FEATURES, build_model_input, extract_features


def load_phase4_engineer():
    source_path = Path(__file__).with_name("phase4_calibration_threshold.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    function_nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"entropy", "engineer"}
    ]
    namespace = {"np": np, "pd": pd}
    exec(compile(ast.Module(function_nodes, type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["engineer"]


PHASE4_ENGINEER = load_phase4_engineer()


class Phase5FeatureParityTest(unittest.TestCase):
    def test_feature_order_matches_phase4_configuration(self):
        config_path = Path(__file__).parents[1] / "data" / "phase4" / "risk_engine_config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(FEATURES, config["features"])
        self.assertEqual(25, len(FEATURES))

    def test_representative_training_semantics(self):
        fixtures = {
            "https://example.com": {
                "url_length": 19,
                "domain_length": 11,
                "subdomain_count": 0,
                "path_length": 0,
                "query_length": 0,
                "has_ip": 0,
                "has_https": 1,
                "has_dash": 0,
                "has_multiple_subdomains": 0,
                "special_char_count": 4,
                "digit_count": 0,
                "has_shortener": 0,
                "suspicious_keyword_count": 0,
                "dot_count": 1,
                "slash_count": 2,
                "hyphen_count": 0,
                "percent_encoded_count": 0,
                "query_parameter_count": 0,
                "uppercase_count": 0,
                "domain_digit_count": 0,
                "path_segment_count": 0,
            },
            "https://a.b.example.com/login?next=1&empty=": {
                "subdomain_count": 2,
                "has_multiple_subdomains": 1,
                "path_segment_count": 1,
                "query_parameter_count": 2,
                "suspicious_keyword_count": 1,
                "digit_count": 1,
            },
            "http://192.168.1.20/login/verify": {
                "subdomain_count": 0,
                "has_ip": 1,
                "has_multiple_subdomains": 0,
                "suspicious_keyword_count": 2,
                "has_https": 0,
            },
            "https://bit.ly/a": {
                "has_shortener": 1,
                "subdomain_count": 0,
                "path_segment_count": 1,
            },
            "https://safe-example.com/a-b": {
                "has_dash": 1,
                "hyphen_count": 2,
            },
            "https://éxample.com/路径?x=1": {
                "special_char_count": 10,
                "uppercase_count": 0,
                "digit_count": 1,
                "query_parameter_count": 1,
            },
        }

        for url, expected in fixtures.items():
            with self.subTest(url=url):
                features = extract_features(url)
                normalized_url = training_normalize_url(url)
                training_features = training_extract_features(normalized_url)
                for name, value in expected.items():
                    self.assertEqual(value, features[name], name)
                for name in (
                    "url_length",
                    "domain_length",
                    "subdomain_count",
                    "path_length",
                    "query_length",
                    "has_ip",
                    "has_https",
                    "has_at",
                    "has_dash",
                    "has_multiple_subdomains",
                    "special_char_count",
                    "digit_count",
                    "entropy",
                    "has_shortener",
                    "suspicious_keyword_count",
                ):
                    self.assertEqual(training_features[name], features[name], name)

                base_row = {
                    "url": normalized_url,
                    "domain": training_features["domain"],
                    **{
                        name: training_features[name]
                        for name in FEATURES[:15]
                    },
                }
                phase4_row = PHASE4_ENGINEER(pd.DataFrame([base_row])).iloc[0]
                for name in FEATURES[15:]:
                    self.assertEqual(phase4_row[name], features[name], name)

                self.assertEqual(set(FEATURES), set(features))
                self.assertTrue(all(math.isfinite(float(features[name])) for name in FEATURES))

    def test_model_input_is_ordered_float32(self):
        frame = build_model_input(extract_features("https://example.com/login?q=1"))
        self.assertEqual(FEATURES, list(frame.columns))
        self.assertEqual((1, len(FEATURES)), frame.shape)
        self.assertTrue(all(dtype == np.dtype("float32") for dtype in frame.dtypes))

    def test_empty_and_malformed_urls_fail_without_features(self):
        for url in ("", "   ", "http://", "http://["):
            with self.subTest(url=url):
                self.assertIsNone(training_normalize_url(url))
                with self.assertRaises(ValueError):
                    extract_features(url)


if __name__ == "__main__":
    unittest.main()
