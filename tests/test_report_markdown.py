import json
import sys
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch

from asustor_nas_cli.cli import main
from asustor_nas_cli.report_markdown import (
    MAX_REPORT_BYTES,
    ReportFormatError,
    parse_report_bytes,
    render_report_markdown,
)

EXAMPLES = Path(__file__).parents[1] / "examples" / "reports"


class MarkdownReportTests(unittest.TestCase):
    def test_health_summary_renders_structured_fields_and_omits_raw_sections(self):
        report = json.loads((EXAMPLES / "health-summary.json").read_text(encoding="utf-8"))

        markdown = render_report_markdown(report)

        self.assertIn("# ASUSTOR NAS CLI Health summary", markdown)
        self.assertIn("summary.temperature.maximum_celsius", markdown)
        self.assertIn("Raw SSH `sections` and path fields", markdown)
        self.assertNotIn("eth0: UP", markdown)

    def test_risk_signals_are_highlighted(self):
        report = json.loads((EXAMPLES / "risk-signals.json").read_text(encoding="utf-8"))

        markdown = render_report_markdown(report)

        self.assertIn("## Risk signals", markdown)
        self.assertIn("`critical` `smart_failed`", markdown)
        self.assertIn("SMART health failed on 1 device(s).", markdown)

    def test_unsupported_report_type_is_rejected(self):
        payload = json.dumps(
            {"schema_version": 1, "report_type": "health", "summary": {}}
        ).encode()
        with self.assertRaisesRegex(ReportFormatError, "supported report types"):
            parse_report_bytes(payload)

    def test_other_published_report_types_render(self):
        reports = {
            "security-audit": {"summary": {}, "checks": []},
            "incident-scan": {"summary": {}, "coverage": {}, "findings": []},
            "platform-status": {"dmi": {}, "modules": {}, "conflicts": [], "notes": []},
            "disk-topology": {
                "summary": {},
                "coverage": {},
                "disks": [],
                "partitions": [],
                "arrays": [],
                "volumes": [],
            },
            "smart-health": {"summary": {}, "devices": [], "notes": []},
            "temperature-observation": {"summary": {}, "sensors": [], "notes": []},
            "service-observations": {"coverage": "complete", "processes": [], "note": "counts only"},
            "ups-observations": {"coverage": "complete", "devices": [], "note": "names omitted"},
            "connection-observations": {
                "coverage": "complete",
                "protocol": "TCP",
                "ipv4": None,
                "ipv6": None,
            },
            "report-comparison": {"changes": {}, "counts": {}},
            "comparison": {"changes": {}, "counts": {}},
            "platform-module-operation": {
                "modules_before": {},
                "modules_after": {},
                "modules_expected": {},
            },
        }

        for report_type, fields in reports.items():
            with self.subTest(report_type=report_type):
                report = {"schema_version": 1, "report_type": report_type, **fields}
                parsed = parse_report_bytes(json.dumps(report).encode())
                markdown = render_report_markdown(parsed)

                self.assertIn(f"Report type: `{report_type}`", markdown)
                self.assertIn("Raw SSH `sections`", markdown)

    def test_incident_rendering_redacts_paths_credentials_and_addresses(self):
        report = {
            "schema_version": 1,
            "report_type": "incident-scan",
            "host": "NAS",
            "summary": {"state": "indicators_observed", "risk_signals": []},
            "coverage": {"files": "complete"},
            "findings": [
                {
                    "id": "deadbolt.file_suffix",
                    "path": "/volume1/Private/secret.deadbolt",
                    "evidence": "operator password=not-for-output saw 192.0.2.12",
                }
            ],
            "sections": {"raw": "must never appear"},
        }

        markdown = render_report_markdown(report)

        self.assertIn("findings[0].path", markdown)
        self.assertIn("[redacted]", markdown)
        self.assertNotIn("/volume1/Private", markdown)
        self.assertNotIn("not-for-output", markdown)
        self.assertNotIn("192.0.2.12", markdown)
        self.assertNotIn("must never appear", markdown)

    def test_non_object_and_non_v1_reports_are_rejected(self):
        with self.assertRaisesRegex(ReportFormatError, "must be an object"):
            parse_report_bytes(b"[]")
        payload = json.dumps(
            {"schema_version": 2, "report_type": "risk-signals", "summary": {}}
        ).encode()
        with self.assertRaisesRegex(ReportFormatError, "schema_version 1"):
            parse_report_bytes(payload)

    def test_invalid_json_constants_and_risk_signal_shapes_are_rejected(self):
        with self.assertRaisesRegex(ReportFormatError, "valid UTF-8 JSON"):
            parse_report_bytes(b'{"schema_version": NaN}')
        payload = json.dumps(
            {
                "schema_version": 1,
                "report_type": "risk-signals",
                "summary": {"risk_signals": ["not-an-object"]},
            }
        ).encode()
        with self.assertRaisesRegex(ReportFormatError, "risk_signals"):
            parse_report_bytes(payload)

    def test_oversized_input_is_rejected(self):
        with self.assertRaisesRegex(ReportFormatError, "1 MB report limit"):
            parse_report_bytes(b" " * (MAX_REPORT_BYTES + 1))

    def test_large_summary_field_lists_are_truncated(self):
        report = {
            "schema_version": 1,
            "report_type": "diagnostic-summary",
            "summary": {"observations": list(range(6_000))},
        }

        markdown = render_report_markdown(report)

        self.assertIn("additional fields omitted after 5000 entries", markdown)
        self.assertNotIn("summary.observations[5999]", markdown)

    def test_untrusted_multiline_values_cannot_add_markdown_sections(self):
        report = {
            "schema_version": 1,
            "report_type": "risk-signals",
            "host": "NAS\n\n# injected",
            "summary": {"state": "attention\n# injected", "risk_signals": []},
        }

        markdown = render_report_markdown(report)

        self.assertEqual(sum(line.startswith("# ") for line in markdown.splitlines()), 1)
        self.assertIn(r"attention\u000a# injected", markdown)
        self.assertIn("Host label: `NAS`", markdown)

    def test_ip_account_and_secret_fields_are_redacted(self):
        report = {
            "schema_version": 1,
            "report_type": "diagnostic-summary",
            "host": "198.51.100.22",
            "summary": {
                "state": "observed",
                "account": "nas-operator",
                "password": "not-for-output",
                "hostname": "192.0.2.10",
                "risk_signals": [],
            },
        }

        markdown = render_report_markdown(report)

        self.assertIn("Host label: `NAS`", markdown)
        self.assertIn("[redacted-ip]", markdown)
        self.assertNotIn("nas-operator", markdown)
        self.assertNotIn("not-for-output", markdown)
        self.assertNotIn("198.51.100.22", markdown)
        self.assertNotIn("192.0.2.10", markdown)

    def test_cli_renders_a_saved_report_without_nas_connection_options(self):
        report_path = EXAMPLES / "health-summary.json"
        output = StringIO()
        with patch.object(
            sys,
            "argv",
            ["adm", "report", "render", "--input", str(report_path)],
        ), redirect_stdout(output):
            result = main()

        self.assertEqual(result, 0)
        self.assertIn("# ASUSTOR NAS CLI Health summary", output.getvalue())

    def test_cli_reads_report_from_stdin(self):
        payload = (EXAMPLES / "risk-signals.json").read_bytes()
        output = StringIO()
        fake_stdin = type("BinaryStdin", (), {"buffer": BytesIO(payload)})()
        with (
            patch.object(sys, "argv", ["adm", "report", "render", "--input", "-"]),
            patch("asustor_nas_cli.cli_report.sys.stdin", fake_stdin),
            redirect_stdout(output),
        ):
            result = main()

        self.assertEqual(result, 0)
        self.assertIn("`critical` `smart_failed`", output.getvalue())


if __name__ == "__main__":
    unittest.main()
