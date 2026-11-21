import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from asustor_nas_cli.cli import main
from asustor_nas_cli.report_comparison import (
    compare_health_reports,
    load_structured_report,
)


def health_report(*, host_id="0123456789abcdef", coverage="complete", state="observed", signals=None):
    return {
        "schema_version": 1,
        "report_type": "diagnostic-summary",
        "generated_at": "2026-11-21T10:00:00Z",
        "command": "health",
        "host": "NAS",
        "host_id": host_id,
        "ssh_port": 22,
        "summary": {
            "state": state,
            "coverage": coverage,
            "risk_signals": signals or [],
            "recommended_exit_code": 0,
            "storage": {"maximum_use_percent": 55},
        },
        "sections": {"health": "raw source output"},
    }


class StructuredReportComparisonTests(unittest.TestCase):
    def test_detects_added_cleared_changed_and_unchanged_signals(self):
        before = health_report(
            signals=[
                {"code": "raid_degraded", "severity": "warning", "message": "md0 degraded"},
                {"code": "smart_failed", "severity": "critical", "message": "sda failed"},
            ]
        )
        after = health_report(
            state="attention",
            signals=[
                {"code": "raid_degraded", "severity": "warning", "message": "md0 rebuilding"},
                {"code": "temperature_high", "severity": "warning", "message": "thermal zone high"},
            ],
        )
        after["summary"]["storage"]["maximum_use_percent"] = 73

        report = compare_health_reports(before, after)

        self.assertEqual(report["report_type"], "report-comparison")
        self.assertEqual(report["changes"]["risk_added"][0]["code"], "temperature_high")
        self.assertEqual(report["changes"]["risk_cleared"][0]["code"], "smart_failed")
        self.assertEqual(report["changes"]["risk_changed"][0]["after"]["message"], "md0 rebuilding")
        self.assertIn(
            "summary.storage.maximum_use_percent",
            {change["field"] for change in report["changes"]["summary_changed"]},
        )

    def test_identical_risk_signal_is_unchanged(self):
        signals = [{"code": "smart_failed", "severity": "critical", "message": "sda failed"}]
        report = compare_health_reports(health_report(signals=signals), health_report(signals=signals))

        self.assertEqual(report["changes"]["risk_unchanged"][0]["code"], "smart_failed")

    def test_compares_risk_signals_report_without_leaking_command(self):
        before = health_report(signals=[])
        after = health_report(
            signals=[{"code": "temperature_high", "severity": "warning", "message": "thermal zone high"}]
        )
        for report in (before, after):
            report["report_type"] = "risk-signals"
            report.pop("command")
            report.pop("sections")

        comparison = compare_health_reports(before, after)

        self.assertIsNone(comparison["command"])
        self.assertEqual(comparison["changes"]["risk_added"][0]["code"], "temperature_high")

    def test_incomplete_followup_marks_missing_data_not_cleared(self):
        before = health_report(
            signals=[{"code": "smart_failed", "severity": "critical", "message": "sda failed"}]
        )
        after = health_report(coverage="partial")
        del after["summary"]["storage"]

        report = compare_health_reports(before, after)

        self.assertEqual(report["changes"]["risk_cleared"], [])
        self.assertEqual(report["changes"]["risk_not_reobserved"][0]["code"], "smart_failed")
        self.assertIn(
            "summary.storage.maximum_use_percent",
            {item["field"] for item in report["changes"]["summary_not_reobserved"]},
        )

    def test_summary_fields_newly_observed_and_removed_with_complete_coverage(self):
        before = health_report()
        after = health_report()
        del after["summary"]["storage"]
        after["summary"]["services"] = {"coverage": "complete"}

        report = compare_health_reports(before, after)

        self.assertEqual(
            report["changes"]["summary_removed"],
            [{"field": "summary.storage.maximum_use_percent", "value": "55"}],
        )
        self.assertEqual(
            report["changes"]["summary_newly_observed"],
            [{"field": "summary.services.coverage", "value": "complete"}],
        )

    def test_rejects_different_hosts_report_types_and_commands(self):
        before = health_report()
        with self.assertRaisesRegex(ValueError, "host_id"):
            compare_health_reports(before, health_report(host_id="fedcba9876543210"))
        with self.assertRaisesRegex(ValueError, "command"):
            compare_health_reports(before, {**health_report(), "command": "raid"})
        with self.assertRaisesRegex(ValueError, "report_type"):
            compare_health_reports(before, {**health_report(), "report_type": "risk-signals"})

    def test_rejects_untrusted_host_ids_and_timestamps(self):
        with self.assertRaisesRegex(ValueError, "host_id"):
            compare_health_reports(health_report(host_id="nas.example"), health_report(host_id="nas.example"))
        report = health_report()
        report["generated_at"] = "operator@example.invalid"
        with self.assertRaisesRegex(ValueError, "ISO 8601"):
            compare_health_reports(report, health_report())

    def test_report_comparison_cli_is_offline_and_emits_json(self):
        before = health_report()
        after = health_report(state="attention")
        with tempfile.TemporaryDirectory() as directory:
            before_path = Path(directory) / "before.json"
            after_path = Path(directory) / "after.json"
            before_path.write_text(json.dumps(before), encoding="utf-8")
            after_path.write_text(json.dumps(after), encoding="utf-8")
            output = tempfile.SpooledTemporaryFile(mode="w+t", encoding="utf-8")
            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "adm",
                        "report",
                        "compare",
                        "--before",
                        str(before_path),
                        "--after",
                        str(after_path),
                        "--json",
                    ],
                ),
                redirect_stdout(output),
            ):
                result = main()
            output.seek(0)
            report = json.loads(output.read())
            output.close()

        self.assertEqual(result, 0)
        self.assertEqual(report["report_type"], "report-comparison")
        self.assertEqual(report["summary_state_before"], "observed")
        self.assertEqual(report["summary_state_after"], "attention")

    def test_loader_rejects_duplicate_risk_signal_codes(self):
        report = health_report(
            signals=[
                {"code": "smart_failed", "severity": "critical", "message": "one"},
                {"code": "smart_failed", "severity": "critical", "message": "two"},
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "唯一"):
                load_structured_report(path)


if __name__ == "__main__":
    unittest.main()
