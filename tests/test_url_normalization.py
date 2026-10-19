import unittest
import contextlib
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

from api.inference import detector as detector_module
from api.inference.detector import FEATURES, WatchDogDetector, build_model_input, extract_features
from api.inference.url_normalization import normalize_host_inference_url
from api.server import app
from test_pe_analyzer import asgi_post


class CapturingModel:
    def __init__(self):
        self.received = None

    def predict_proba(self, features):
        self.received = features.copy()
        return np.array([[0.1, 0.9]])


def detector_with_fake_model():
    detector = WatchDogDetector.__new__(WatchDogDetector)
    detector.model = CapturingModel()
    return detector


class PathInferenceUrlNormalizationTests(unittest.TestCase):
    def test_production_detector_passes_path_cues_to_model_and_preserves_original(self):
        original = "https://stitch.withgoogle.com/projects/1572296968793876056"
        expected = "https://stitch.withgoogle.com/projects/1572296968793876056"
        detector = detector_with_fake_model()

        response = detector.predict(original)

        self.assertEqual(response["url"], original)
        pd.testing.assert_frame_equal(
            detector.model.received.reset_index(drop=True),
            build_model_input(extract_features(expected)).reset_index(drop=True),
        )

    def test_path_reaches_model_but_query_and_fragment_do_not(self):
        cases = [
            ("https://shop.example/orders/1572296968793876056", "https://shop.example/orders/1572296968793876056"),
            ("https://example.com/account/verify?redirect=secure#form", "https://example.com/account/verify"),
            ("https://example.com/a?next=https%3A%2F%2Flogin.example", "https://example.com/a"),
        ]
        for original, expected in cases:
            with self.subTest(original=original):
                detector = detector_with_fake_model()
                response = detector.predict(original)
                self.assertEqual(response["url"], original)
                self.assertEqual(
                    detector.model.received.iloc[0].to_dict(),
                    build_model_input(extract_features(expected)).iloc[0].to_dict(),
                )
                self.assertGreater(detector.model.received.loc[0, "path_length"], 0)
                self.assertEqual(detector.model.received.loc[0, "query_length"], 0)
                self.assertGreater(detector.model.received.loc[0, "path_segment_count"], 0)

    def test_ipv4_ipv6_and_ports_are_normalized_before_production_prediction(self):
        cases = [
            ("http://192.0.2.10:8080/private/path", "http://192.0.2.10:8080/private/path"),
            ("https://[2001:db8::1]:8443/account?x=1", "https://[2001:db8::1]:8443/account"),
            ("http://example.com:80/a", "http://example.com/a"),
            ("https://example.com:443/a", "https://example.com/a"),
        ]
        for original, expected in cases:
            with self.subTest(original=original):
                detector = detector_with_fake_model()
                result = detector.predict(original)
                self.assertEqual(
                    detector.model.received.iloc[0].to_dict(),
                    build_model_input(extract_features(expected)).iloc[0].to_dict(),
                )

    def test_invalid_url_never_reaches_model(self):
        detector = detector_with_fake_model()
        for invalid in ("ftp://example.com/file", "https:///missing", "https://user@example.com/a", "https://example.com:99999/a"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    detector.predict(invalid)
                self.assertIsNone(detector.model.received)

    def test_fastapi_production_route_uses_path_features_and_keeps_original(self):
        original = "https://stitch.withgoogle.com/projects/1572296968793876056"
        detector = detector_with_fake_model()
        with patch("api.server.detector", detector), patch("api.server._service_token", return_value="a" * 64):
            status, payload = asgi_post(app, "/predict", {"url": original})

        import json
        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["url"], original)
        expected = build_model_input(extract_features("https://stitch.withgoogle.com/projects/1572296968793876056"))
        self.assertEqual(detector.model.received.loc[0, FEATURES].tolist(), expected.loc[0, FEATURES].tolist())

    def test_csv_batch_entry_point_uses_path_and_drops_query(self):
        original = "https://example.com/login?token=abc"
        detector = detector_with_fake_model()
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.csv"
            output_path = Path(directory) / "output.csv"
            input_path.write_text(f"url\n{original}\n", encoding="utf-8")
            detector.predict_batch(input_path, output_path)

        self.assertGreater(detector.model.received.loc[0, "path_length"], 0)
        self.assertEqual(detector.model.received.loc[0, "query_length"], 0)

    def test_single_url_cli_entry_point_uses_path_and_drops_query(self):
        original = "https://example.com/account/verify?redirect=secure"
        detector = detector_with_fake_model()
        with patch.object(detector_module, "WatchDogDetector", return_value=detector), patch(
            "sys.argv", ["detector", original]
        ), contextlib.redirect_stdout(io.StringIO()):
            detector_module.main()

        self.assertGreater(detector.model.received.loc[0, "path_length"], 0)
        self.assertEqual(detector.model.received.loc[0, "query_length"], 0)

    def test_supported_url_forms(self):
        cases = [
            ("HTTPS://Example.COM./a?b=1#section", "https://example.com"),
            ("http://example.com:80/a", "http://example.com"),
            ("https://example.com:443/a", "https://example.com"),
            ("https://example.com:8443/a", "https://example.com:8443"),
            ("http://192.0.2.10:8080/a", "http://192.0.2.10:8080"),
            ("https://[2001:db8::1]:8443/a", "https://[2001:db8::1]:8443"),
            ("https://bücher.example/path", "https://xn--bcher-kva.example"),
            ("https://example.com", "https://example.com"),
        ]
        for url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(normalize_host_inference_url(url), expected)

    def test_rejects_invalid_or_unsupported_inputs(self):
        invalid_urls = [
            "", "example.com/path", "ftp://example.com/file", "https:///missing-host",
            "https://user:secret@example.com/path", "https://example.com:99999/path",
            "https://bad host.example/path", " https://example.com/path",
        ]
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    normalize_host_inference_url(url)


if __name__ == "__main__":
    unittest.main()
