import unittest

from asustor_nas_cli.cli_parser import build_parser
from asustor_nas_cli.smart_health import (
    build_smart_health_command,
    format_smart_health,
    parse_smart_health_output,
)


class SmartHealthTests(unittest.TestCase):
    def test_command_is_read_only_and_skips_standby_devices(self):
        command = build_smart_health_command()
        self.assertIn("smartctl -H -n standby", command)
        self.assertIn("/dev/sd[a-z]", command)
        self.assertNotIn("smartctl -t", command)
        self.assertNotIn("serial", command.lower())

    def test_parses_ata_and_scsi_health_results_without_raw_smartctl_text(self):
        output = (
            "__ADM_SMART_BEGIN__\n"
            "__ADM_SMART_DEVICE__=sda\n"
            "__ADM_SMART_HEALTH__=passed\n"
            "__ADM_SMART_EXIT__=0\n"
            "__ADM_SMART_DEVICE__=sdb\n"
            "__ADM_SMART_HEALTH__=passed\n"
            "__ADM_SMART_EXIT__=0\n"
            "__ADM_SMART_END__\n"
        )
        report = parse_smart_health_output(output, host="NAS", ssh_port=22)
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(report["summary"]["state"], "passed")
        self.assertEqual(report["summary"]["device_count"], 2)
        self.assertNotIn("serial", str(report).lower())
        self.assertIn("/dev/sda=passed", format_smart_health(report))

    def test_failed_health_is_positive_failure_and_exit_status_is_retained(self):
        output = (
            "__ADM_SMART_BEGIN__\n"
            "__ADM_SMART_DEVICE__=sda\n"
            "__ADM_SMART_HEALTH__=failed\n"
            "__ADM_SMART_EXIT__=4\n"
            "__ADM_SMART_END__\n"
        )
        report = parse_smart_health_output(output)
        self.assertEqual(report["coverage"], "partial")
        self.assertEqual(report["summary"]["state"], "failed")
        self.assertEqual(report["devices"][0]["tool_exit_code"], 4)

    def test_missing_tool_partial_markers_and_invalid_devices_fail_closed(self):
        missing_tool = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n__ADM_SMART_ERROR__=smartctl_unavailable\n__ADM_SMART_END__"
        )
        partial = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n__ADM_SMART_DEVICE__=sda\n__ADM_SMART_HEALTH__=passed"
        )
        invalid_device = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n__ADM_SMART_DEVICE__=sda;evil\n__ADM_SMART_END__"
        )
        self.assertEqual(missing_tool["coverage"], "unavailable")
        self.assertEqual(partial["coverage"], "partial")
        self.assertEqual(invalid_device["coverage"], "partial")
        self.assertEqual(invalid_device["devices"], [])

    def test_parser_exposes_smart_command(self):
        args = build_parser().parse_args(
            ["smart", "--host", "nas.example", "--user", "nas-user"]
        )
        self.assertEqual(args.command, "smart")


if __name__ == "__main__":
    unittest.main()
