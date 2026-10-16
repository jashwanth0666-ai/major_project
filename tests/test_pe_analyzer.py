from __future__ import annotations

import asyncio
import hashlib
import json
import os
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

import pefile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from api.pe_analyzer.service import (  # noqa: E402
    StaticPEAnalyzer,
    detect_sensitive_imports,
    shannon_entropy,
)
from api.pe_analyzer.scoring import score_indicators  # noqa: E402
from api.server import app  # noqa: E402


def minimal_pe(section_data: bytes | None = None) -> bytes:
    """Build a tiny inert PE structure for parser tests; it is never executed."""
    if section_data is None:
        section_data = bytes(0x200)
    raw_size = ((len(section_data) + 0x1FF) // 0x200) * 0x200
    section_data = section_data.ljust(raw_size, b"\0")
    image_size = 0x1000 + max(raw_size, 0x1000)
    data = bytearray(0x200 + raw_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"

    file_header = struct.pack(
        "<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102,
    )
    data[0x84:0x98] = file_header
    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x010B)  # PE32
    struct.pack_into("<III", optional, 4, raw_size, 0, 0)
    struct.pack_into("<II", optional, 16, 0x1000, 0x1000)
    struct.pack_into("<I", optional, 24, 0x1000)
    struct.pack_into("<I", optional, 28, 0x00400000)
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 56, image_size)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<HH", optional, 68, 3, 0)
    struct.pack_into("<IIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", optional, 88, 0, 16)
    optional_start = 0x98
    data[optional_start:optional_start + len(optional)] = optional

    section_start = optional_start + len(optional)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", len(section_data), 0x1000,
        raw_size, 0x200, 0, 0, 0, 0, 0x60000020,
    )
    data[section_start:section_start + len(section)] = section
    data[0x200:] = section_data
    return bytes(data)


def asgi_post(application, path: str, body: dict) -> tuple[int, bytes]:
    raw_body = json.dumps(body).encode("utf-8")
    messages = []
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": raw_body, "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json"),
                    (b"content-length", str(len(raw_body)).encode())],
        "client": ("testclient", 50000), "server": ("testserver", 80),
    }
    asyncio.run(application(scope, receive, send))
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    )
    return start["status"], response_body


class StaticPEAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.analyzer = StaticPEAnalyzer([self.root], 2 * 1024 * 1024)

    def write_fixture(self, name: str = "sample.exe", data: bytes | None = None) -> Path:
        path = self.root / name
        path.write_bytes(minimal_pe() if data is None else data)
        return path

    def test_valid_pe_returns_sha_architecture_sections_and_neutral_heuristic(self):
        path = self.write_fixture()
        response, status = self.analyzer.analyze_path(str(path))

        self.assertEqual(200, status)
        self.assertEqual("ANALYZED", response.status)
        self.assertTrue(response.pe_valid)
        self.assertEqual("x86", response.architecture)
        self.assertEqual(1, response.section_count)
        self.assertEqual(".text", response.sections[0].name)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), response.sha256)
        self.assertEqual(10, response.risk_score)
        self.assertIn("does not establish", response.suspicious_indicators[0])

    def test_truncated_and_non_pe_files_return_invalid_pe_with_hash(self):
        for contents in (b"MZ", b"not a PE file"):
            with self.subTest(contents=contents):
                path = self.write_fixture(data=contents)
                result, status = self.analyzer.analyze_path(str(path))
                self.assertEqual(200, status)
                self.assertEqual("INVALID_PE", result.status)
                self.assertFalse(result.pe_valid)
                self.assertEqual(hashlib.sha256(contents).hexdigest(), result.sha256)

    def test_missing_file_and_unsupported_extension_have_structured_statuses(self):
        missing, missing_status = self.analyzer.analyze_path(str(self.root / "missing.exe"))
        unsupported_path = self.root / "notes.txt"
        unsupported_path.write_text("not executable", encoding="utf-8")
        unsupported, unsupported_status = self.analyzer.analyze_path(str(unsupported_path))
        self.assertEqual(("ANALYSIS_ERROR", "FILE_UNAVAILABLE", 404),
                         (missing.status, missing.error.code, missing_status))
        self.assertEqual(("UNSUPPORTED_FILE", "UNSUPPORTED_EXTENSION", 415),
                         (unsupported.status, unsupported.error.code, unsupported_status))

    def test_inaccessible_file_and_file_changed_during_read_are_structured_errors(self):
        inaccessible = self.write_fixture()
        with patch("api.pe_analyzer.service.Path.open", side_effect=PermissionError("blocked")):
            denied, denied_status = self.analyzer.analyze_path(str(inaccessible))
        self.assertEqual(("ANALYSIS_ERROR", "FILE_UNAVAILABLE", 403),
                         (denied.status, denied.error.code, denied_status))

        changed = self.write_fixture("changed.exe")
        real_fstat = os.fstat
        calls = 0

        def changing_fstat(file_descriptor):
            nonlocal calls
            calls += 1
            actual = real_fstat(file_descriptor)
            if calls == 1:
                return actual
            return SimpleNamespace(
                st_mode=actual.st_mode,
                st_size=actual.st_size,
                st_mtime_ns=actual.st_mtime_ns + 1,
                st_ino=actual.st_ino,
                st_dev=actual.st_dev,
            )

        with patch("api.pe_analyzer.service.os.fstat", side_effect=changing_fstat):
            changed_result, changed_status = self.analyzer.analyze_path(str(changed))
        self.assertEqual(("ANALYSIS_ERROR", "FILE_CHANGED", 409),
                         (changed_result.status, changed_result.error.code, changed_status))

    def test_file_size_is_rejected_before_full_read(self):
        path = self.write_fixture()
        result, status = StaticPEAnalyzer([self.root], 64).analyze_path(str(path))
        self.assertEqual(413, status)
        self.assertEqual("REJECTED_PATH", result.status)
        self.assertEqual("FILE_TOO_LARGE", result.error.code)
        self.assertIsNone(result.sha256)

    def test_paths_outside_approved_roots_and_traversal_are_rejected(self):
        outside = self.root.parent / (self.root.name + "-outside.exe")
        outside.write_bytes(minimal_pe())
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        outside_result, outside_status = self.analyzer.analyze_path(str(outside))
        traversal_result, traversal_status = self.analyzer.analyze_path(str(self.root / ".." / outside.name))
        self.assertEqual(("REJECTED_PATH", 403), (outside_result.status, outside_status))
        self.assertEqual(("REJECTED_PATH", 403), (traversal_result.status, traversal_status))

    def test_symlink_escape_is_rejected_when_platform_supports_symlinks(self):
        outside = self.root.parent / (self.root.name + "-escape.exe")
        outside.write_bytes(minimal_pe())
        link = self.root / "redirect.exe"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            outside.unlink(missing_ok=True)
            self.skipTest("symlink creation is not available in this environment")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        result, status = self.analyzer.analyze_path(str(link))
        self.assertEqual(("REJECTED_PATH", 403), (result.status, status))

    def test_section_bounds_anomaly_is_exposed_and_scored(self):
        malformed = bytearray(minimal_pe())
        section_header = 0x80 + 4 + 20 + 224
        struct.pack_into("<I", malformed, section_header + 20, 0x1000)
        result, status = self.analyzer.analyze_path(str(self.write_fixture(data=bytes(malformed))))
        self.assertEqual(200, status)
        self.assertEqual("ANALYZED", result.status)
        self.assertIn("SECTION_RAW_DATA_OUT_OF_BOUNDS", result.anomalies)
        self.assertGreaterEqual(result.risk_score, 30)

    def test_entropy_sensitive_import_detection_and_score_are_deterministic_and_bounded(self):
        self.assertAlmostEqual(8.0, shannon_entropy(bytes(range(256)) * 4), places=6)
        self.assertEqual(["CreateRemoteThread", "VirtualAlloc"], detect_sensitive_imports(
            ["VirtualAlloc", "CreateRemoteThread", "ReadFile", "virtualalloc"]
        ))
        kwargs = dict(
            writable_executable_section=True,
            high_entropy_section=True,
            sensitive_imports=True,
            file_boundary_anomaly=True,
            entry_point_anomaly=True,
        )
        self.assertEqual(score_indicators(**kwargs), score_indicators(**kwargs))
        self.assertLessEqual(score_indicators(**kwargs), 100)
        self.assertGreaterEqual(score_indicators(**kwargs), 0)

    def test_malformed_import_table_is_reported_without_a_malware_verdict(self):
        class BrokenImports:
            @staticmethod
            def parse_data_directories(**kwargs):
                raise pefile.PEFormatError("bad import table")

        from api.pe_analyzer.service import StaticPEAnalyzer as Analyzer
        imports, sensitive, anomaly = Analyzer._extract_imports(BrokenImports())
        self.assertEqual(([], [], "IMPORT_TABLE_MALFORMED"), (imports, sensitive, anomaly))


class StaticPEAnalyzerApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.analyzer = StaticPEAnalyzer([self.root], 2 * 1024 * 1024)
        self.patch = patch("api.pe_analyzer.router.analyzer", self.analyzer)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_analyze_file_endpoint_returns_structured_result(self):
        path = self.root / "api-sample.dll"
        path.write_bytes(minimal_pe())
        status, payload = asgi_post(app, "/api/analyze-file", {"path": str(path)})
        body = json.loads(payload)
        self.assertEqual(200, status)
        self.assertEqual("ANALYZED", body["status"])
        self.assertEqual("api-sample.dll", body["file_name"])
        self.assertEqual(64, len(body["sha256"]))
        self.assertIn("not a calibrated probability", body["risk_score_explanation"])

    def test_request_validation_does_not_echo_local_paths(self):
        status, payload = asgi_post(app, "/api/analyze-file", {"path": " "})
        body = json.loads(payload)
        self.assertEqual(422, status)
        self.assertNotIn("input", json.dumps(body))
        status, payload = asgi_post(app, "/api/analyze-file", {})
        self.assertEqual(422, status)

    def test_rejected_api_path_has_no_local_path_in_response(self):
        outside = self.root.parent / (self.root.name + "-api-outside.exe")
        outside.write_bytes(minimal_pe())
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        status, payload = asgi_post(app, "/api/analyze-file", {"path": str(outside)})
        body = json.loads(payload)
        self.assertEqual(403, status)
        self.assertEqual("REJECTED_PATH", body["status"])
        self.assertNotIn(str(outside), payload.decode("utf-8"))

    def test_existing_url_prediction_route_remains_available(self):
        class ExistingDetector:
            @staticmethod
            def predict(url):
                return {"url": url, "prediction": "BENIGN"}

        with patch("api.server.detector", ExistingDetector()):
            status, payload = asgi_post(app, "/predict", {"url": "https://example.com"})
        self.assertEqual(200, status)
        self.assertEqual(
            {"url": "https://example.com", "prediction": "BENIGN"},
            json.loads(payload),
        )


if __name__ == "__main__":
    unittest.main()
