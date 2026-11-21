import unittest

from asustor_nas_cli.smart_health import parse_smart_health_output
from asustor_nas_cli.summaries import (
    build_diagnostic_summary,
    build_health_summary,
    format_diagnostic_summary,
    parse_raid_summary,
    parse_storage_summary,
    parse_system_summary,
)
from asustor_nas_cli.temperature import parse_temperature_output

SYSTEM = """hostname: nas
kernel: Linux 3.4.26
uptime: up 12 days
cpu: ARM processor
memory (MiB):
              total        used        free
Mem:            512         250         262
"""
STORAGE = """Filesystem      Size  Used Avail Use% Mounted on
/dev/md1        1.8T  1.0T  800G  56% /volume1
tmpfs           250M  1.0M  249M   1% /run
"""
RAID = """Personalities : [raid1]
md1 : active raid1 sda4[0] sdb4[1]
      450000000 blocks [2/1] [U_]
"""


class StructuredSummaryTests(unittest.TestCase):
    def test_system_summary_extracts_safe_observations(self):
        summary = parse_system_summary(SYSTEM)
        self.assertEqual(summary["kernel"], "Linux 3.4.26")
        self.assertEqual(summary["memory_mib"], {"total_mib": 512, "used_mib": 250, "free_mib": 262})
        self.assertEqual(summary["coverage"], "complete")

    def test_system_summary_marks_malformed_memory_row_partial(self):
        summary = parse_system_summary("kernel: Linux 3.4\nMem: unknown")
        self.assertEqual(summary["parse_errors"], 1)
        self.assertEqual(summary["coverage"], "partial")

    def test_storage_summary_parses_filesystem_rows_and_marks_bad_rows(self):
        summary = parse_storage_summary(STORAGE + "unparsed output\n")
        self.assertEqual(summary["filesystem_count"], 2)
        self.assertEqual(summary["maximum_use_percent"], 56)
        self.assertEqual(summary["coverage"], "partial")
        self.assertEqual(summary["parse_errors"], 1)

    def test_storage_summary_requires_the_df_header_for_complete_coverage(self):
        summary = parse_storage_summary("/dev/md1 1T 500G 500G 50% /volume1")
        self.assertEqual(summary["coverage"], "partial")

    def test_raid_summary_detects_degraded_array(self):
        summary = parse_raid_summary(RAID)
        self.assertEqual(summary["state"], "degraded")
        self.assertEqual(summary["degraded_arrays"], ["md1"])

    def test_raid_summary_does_not_treat_arbitrary_text_as_complete(self):
        summary = parse_raid_summary("unexpected or truncated response")
        self.assertEqual(summary["state"], "unknown")
        self.assertEqual(summary["coverage"], "partial")

    def test_raid_summary_requires_the_proc_mdstat_footer(self):
        summary = parse_raid_summary("Personalities : [raid1]\nmd1 : active raid1 sda4[0] sdb4[1]\n      [2/2] [UU]")
        self.assertEqual(summary["coverage"], "partial")

    def test_raid_report_retains_raw_section_and_recommends_nonzero_exit(self):
        report = build_diagnostic_summary(
            "raid",
            {"raid": RAID},
            host="nas.example",
            ssh_port=22,
        )
        self.assertEqual(report["sections"]["raid"], RAID)
        self.assertEqual(report["summary"]["recommended_exit_code"], 2)
        self.assertEqual(report["host"], "NAS")
        text = format_diagnostic_summary(report)
        self.assertIn("raid_degraded", text)
        self.assertIn("raw raid", text)

    def test_health_summary_signals_smart_temperature_and_degraded_raid(self):
        smart = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n"
            "__ADM_SMART_DEVICE__=sda\n"
            "__ADM_SMART_HEALTH__=failed\n"
            "__ADM_SMART_EXIT__=8\n"
            "__ADM_SMART_END__"
        )
        temperature = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n"
            "__ADM_TEMP_SENSOR__=thermal_zone0|85000\n"
            "__ADM_TEMP_END__"
        )
        report = build_health_summary(
            {"system": SYSTEM, "storage": STORAGE, "raid": RAID},
            smart,
            temperature,
            host="nas.example",
            ssh_port=22,
            warning_celsius=80.0,
        )
        summary = report["summary"]
        self.assertEqual(summary["state"], "attention")
        self.assertEqual(summary["recommended_exit_code"], 2)
        self.assertEqual(
            {signal["code"] for signal in summary["risk_signals"]},
            {"raid_degraded", "smart_failed", "temperature_high"},
        )
        self.assertEqual(summary["temperature"]["high_sensors"], [{"sensor": "thermal_zone0", "celsius": 85.0}])

    def test_health_summary_marks_missing_observations_unknown(self):
        smart = parse_smart_health_output("")
        temperature = parse_temperature_output("__ADM_TEMP_BEGIN__\n__ADM_TEMP_NO_SENSORS__\n__ADM_TEMP_END__")
        report = build_health_summary(
            {"system": SYSTEM, "storage": STORAGE, "raid": "Personalities : [raid1]"},
            smart,
            temperature,
            host="nas.example",
            ssh_port=22,
            warning_celsius=80.0,
        )
        self.assertEqual(report["summary"]["state"], "unknown")
        self.assertEqual(report["summary"]["recommended_exit_code"], 1)
        self.assertEqual(report["summary"]["risk_signals"], [])


if __name__ == "__main__":
    unittest.main()
