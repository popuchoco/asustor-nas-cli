import unittest

from asustor_nas_cli.security import (
    build_incident_report,
    build_scan_command,
    build_security_audit,
    compare_reports,
)

HOST = "192.0.2.10"
PORTAL_VERIFIED = {
    "http_status": 200,
    "asustor_marker": True,
    "tls_verified": True,
    "adm_version": "3.5.9.RWM1",
    "deadbolt_indicators": [],
}


class SecurityReportTests(unittest.TestCase):
    def test_scan_command_discovers_tools_and_checks_bounded_scan_support(self):
        command = build_scan_command(12, 4)
        self.assertIn("command -v find", command)
        self.assertIn("command -v timeout", command)
        self.assertIn("find_xdev_unsupported", command)
        self.assertIn("-t 12", command)
        self.assertIn("12s", command)
        self.assertNotIn("/usr/bin/timeout", command)

    def test_missing_scan_capability_reports_unavailable_not_clean(self):
        report = build_incident_report(
            HOST,
            22,
            scan_output=(
                "__ADM_VOLUME__=/volume1\n"
                "__ADM_SCAN_UNAVAILABLE__=find_xdev_unsupported\n"
                "__ADM_SCAN_EXIT__=125\n"
            ),
            portal=PORTAL_VERIFIED,
        )
        self.assertEqual(report["coverage"]["files"], "unavailable")
        self.assertEqual(report["summary"]["state"], "incomplete")
        self.assertIn("不支援 -xdev", report["coverage"]["files_reason"])

    def test_malformed_scan_markers_keep_coverage_partial(self):
        report = build_incident_report(
            HOST,
            22,
            scan_output=(
                "__ADM_VOLUME__=/volume1\n"
                "__ADM_SCAN_ELAPSED__=not-a-number\n"
            ),
            portal=PORTAL_VERIFIED,
        )
        self.assertEqual(report["coverage"]["files"], "partial")
        self.assertEqual(report["summary"]["state"], "incomplete")

    def test_rwm1_is_recognized_from_vendor_release_notes(self):
        report = build_security_audit(
            HOST,
            22,
            "__ADM_NETSTAT_UNAVAILABLE__",
            PORTAL_VERIFIED,
        )
        check = next(item for item in report["checks"] if item["id"] == "firmware.deadbolt_patch")
        self.assertEqual(check["status"], "pass")
        self.assertIn("release_notes", check["sources"][1])

    def test_unknown_build_is_not_ordered_lexically(self):
        portal = {**PORTAL_VERIFIED, "adm_version": "3.5.9.RZZ9"}
        report = build_security_audit(HOST, 22, "", portal)
        check = next(item for item in report["checks"] if item["id"] == "firmware.deadbolt_patch")
        self.assertEqual(check["status"], "unknown")

    def test_default_ports_are_reported_as_warning(self):
        listeners = (
            "Proto Recv-Q Send-Q Local Address Foreign Address State\n"
            "tcp 0 0 0.0.0.0:8000 0.0.0.0:* LISTEN\n"
            "tcp 0 0 0.0.0.0:8001 0.0.0.0:* LISTEN\n"
        )
        report = build_security_audit(HOST, 22, listeners, PORTAL_VERIFIED)
        check = next(item for item in report["checks"] if item["id"] == "management.default_ports")
        self.assertEqual(check["status"], "warn")
        self.assertEqual(check["observed_ports"], [8000, 8001])

    def test_hit_limit_marks_coverage_partial_and_keeps_positive_finding(self):
        output = (
            "__ADM_VOLUME__=/volume1\n"
            "/volume1/one.deadbolt\n"
            "__ADM_SCAN_TRUNCATED__\n"
            "__ADM_SCAN_ELAPSED__=2\n"
            "__ADM_SCAN_EXIT__=141\n"
        )
        report = build_incident_report(
            HOST,
            22,
            scan_output=output,
            portal=PORTAL_VERIFIED,
            max_seconds=30,
            max_hits=1,
        )
        self.assertEqual(report["coverage"]["files"], "partial")
        self.assertEqual(report["summary"]["state"], "indicators_observed")
        self.assertEqual(len(report["findings"]), 1)

    def test_unverified_portal_does_not_produce_complete_scan(self):
        portal = {**PORTAL_VERIFIED, "tls_verified": False}
        output = "__ADM_VOLUME__=/volume1\n__ADM_SCAN_ELAPSED__=1\n__ADM_SCAN_EXIT__=0\n"
        report = build_incident_report(HOST, 22, scan_output=output, portal=portal)
        self.assertEqual(report["coverage"]["files"], "complete")
        self.assertEqual(report["coverage"]["portal"], "partial")
        self.assertEqual(report["summary"]["state"], "incomplete")

    def test_comparison_finds_new_file_indicator(self):
        before_output = "__ADM_VOLUME__=/volume1\n__ADM_SCAN_ELAPSED__=1\n__ADM_SCAN_EXIT__=0\n"
        after_output = (
            "__ADM_VOLUME__=/volume1\n"
            "/volume1/encrypted.deadbolt\n"
            "__ADM_SCAN_ELAPSED__=1\n"
            "__ADM_SCAN_EXIT__=0\n"
        )
        before = build_incident_report(HOST, 22, scan_output=before_output, portal=PORTAL_VERIFIED)
        after = build_incident_report(HOST, 22, scan_output=after_output, portal=PORTAL_VERIFIED)
        comparison = compare_reports(before, after)
        self.assertEqual(comparison["counts"]["newly_observed"], 1)

    def test_comparison_rejects_different_hosts(self):
        report = build_incident_report(
            HOST,
            22,
            scan_output="__ADM_VOLUME__=/volume1\n__ADM_SCAN_ELAPSED__=1\n__ADM_SCAN_EXIT__=0\n",
            portal=PORTAL_VERIFIED,
        )
        other = build_incident_report(
            "192.0.2.11",
            22,
            scan_output="__ADM_VOLUME__=/volume1\n__ADM_SCAN_ELAPSED__=1\n__ADM_SCAN_EXIT__=0\n",
            portal=PORTAL_VERIFIED,
        )
        with self.assertRaisesRegex(ValueError, "host"):
            compare_reports(report, other)

    def test_removed_volume_does_not_claim_old_indicator_disappeared(self):
        before = build_incident_report(
            HOST,
            22,
            scan_output=(
                "__ADM_VOLUME__=/volume1\n"
                "/volume1/old.deadbolt\n"
                "__ADM_SCAN_ELAPSED__=1\n"
                "__ADM_SCAN_EXIT__=0\n"
            ),
            portal=PORTAL_VERIFIED,
        )
        after = build_incident_report(
            HOST,
            22,
            scan_output=(
                "__ADM_VOLUME__=/volume0\n"
                "__ADM_VOLUME__=/volume1\n"
                "__ADM_SCAN_ELAPSED__=1\n"
                "__ADM_SCAN_EXIT__=0\n"
            ),
            portal=PORTAL_VERIFIED,
        )
        comparison = compare_reports(before, after)
        self.assertTrue(comparison["scope_changed"])
        self.assertEqual(comparison["counts"]["no_longer_observed"], 0)
        self.assertEqual(comparison["counts"]["not_reobserved_in_incomplete_scan"], 1)


if __name__ == "__main__":
    unittest.main()
