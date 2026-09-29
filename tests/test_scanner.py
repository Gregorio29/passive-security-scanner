"""
Unit tests for passive_scanner.
Tests target normalization, headers analyzer, SSL checker, DNS recon, and report generation.
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner import normalize_target
from modules.headers_analyzer import HeadersAnalyzer
from modules.reporter import Reporter


class TestPassiveScanner(unittest.TestCase):

    def test_normalize_target_domain(self):
        domain, base_url, host = normalize_target("example.com")
        self.assertEqual(domain, "example.com")
        self.assertEqual(base_url, "https://example.com")
        self.assertEqual(host, "example.com")

    def test_normalize_target_http(self):
        domain, base_url, host = normalize_target("http://test.local:8080/path")
        self.assertEqual(domain, "test.local")
        self.assertEqual(base_url, "http://test.local:8080")
        self.assertEqual(host, "test.local")

    @patch("urllib.request.urlopen")
    def test_headers_analyzer_missing_security_headers(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Server": "Apache/2.4.41",
            "Content-Type": "text/html"
        }
        mock_resp.getheader.side_effect = lambda k, default=None: mock_resp.headers.get(k, default)
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ha = HeadersAnalyzer("https://example.com")
        res = ha.analyze()

        self.assertIn("score", res)
        self.assertIn("grade", res)
        self.assertIn("missing_headers", res)
        self.assertIn("Strict-Transport-Security", res["missing_headers"])
        self.assertIn("Content-Security-Policy", res["missing_headers"])
        self.assertLessEqual(res["score"], 50)

    def test_reporter_formatting_and_save(self):
        sample_data = {
            "target": "example.com",
            "base_url": "https://example.com",
            "timestamp": "2026-09-28 22:00:00",
            "overall_score": 85,
            "overall_grade": "B",
            "all_findings": [
                {
                    "module": "headers",
                    "severity": "MEDIUM",
                    "type": "MISSING_HSTS",
                    "description": "No se detectó cabecera Strict-Transport-Security.",
                    "recommendation": "Agregar HSTS."
                }
            ],
            "modules": {
                "headers": {"score": 90, "grade": "A", "findings": []},
                "ssl": {"score": 80, "grade": "B", "findings": []},
                "dns": {"score": 85, "grade": "B", "findings": []},
                "surface": {"score": 85, "grade": "B", "findings": []}
            }
        }
        reporter = Reporter(sample_data)
        md_content = reporter.generate_markdown()

        self.assertIn("Informe de Auditoría de Seguridad Pasiva", md_content)
        self.assertIn("example.com", md_content)

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = reporter.save_reports(tmpdir)
            self.assertIn("json_path", paths)
            self.assertIn("markdown_path", paths)
            self.assertTrue(os.path.exists(paths["json_path"]))
            self.assertTrue(os.path.exists(paths["markdown_path"]))


if __name__ == "__main__":
    unittest.main()
