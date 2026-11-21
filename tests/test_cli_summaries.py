import io
import json
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest.mock import patch

from asustor_nas_cli.cli import run_health
from asustor_nas_cli.cli_parser import build_parser
from asustor_nas_cli.commands import DOCTOR_SECTIONS, HEALTH_OBSERVATION_SECTIONS
from asustor_nas_cli.smart_health import parse_smart_health_output
from asustor_nas_cli.temperature import parse_temperature_output


class SummaryCliTests(unittest.TestCase):
    def test_summary_options_are_available_on_the_expected_commands(self):
        parser = build_parser()
        status = parser.parse_args(["status", "--host", "nas.example", "--user", "nas-user", "--summary"])
        health = parser.parse_args(
            [
                "health",
                "--host",
                "nas.example",
                "--user",
                "nas-user",
                "--summary",
                "--exit-on-warning",
                "--temperature-warning-celsius",
                "75",
            ]
        )
        raid = parser.parse_args(
            ["raid", "--host", "nas.example", "--user", "nas-user", "--summary", "--exit-on-warning"]
        )
        self.assertTrue(status.summary)
        self.assertTrue(health.summary)
        self.assertTrue(health.exit_on_warning)
        self.assertEqual(health.temperature_warning_celsius, 75)
        self.assertTrue(raid.exit_on_warning)

    def test_health_summary_exit_code_and_raw_sections(self):
        sections = {
            "system": "kernel: Linux 6.1.0\nMem: 1024 512 512",
            "storage": "Filesystem Size Used Avail Use% Mounted on\n/dev/md1 1T 500G 500G 50% /volume1",
            "raid": "Personalities : [raid1]\nunused devices: <none>",
            "network": "interfaces: observed",
            "disks": "devices: sda",
        }
        smart = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n"
            "__ADM_SMART_DEVICE__=sda\n"
            "__ADM_SMART_HEALTH__=failed\n"
            "__ADM_SMART_EXIT__=8\n"
            "__ADM_SMART_END__"
        )
        temperature = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n__ADM_TEMP_SENSOR__=thermal_zone0|45000\n__ADM_TEMP_END__"
        )
        args = Namespace(
            command="health",
            host="nas.example",
            user="nas-user",
            port=22,
            timeout=8,
            identity_file=None,
            summary=True,
            json=True,
            exit_on_warning=True,
            temperature_warning_celsius=80.0,
        )
        output = io.StringIO()
        with (
            patch("asustor_nas_cli.cli.run_ssh_sections", return_value=sections) as collect_sections,
            patch("asustor_nas_cli.cli.collect_smart_health", return_value=(smart, None)),
            patch("asustor_nas_cli.cli.collect_temperature", return_value=(temperature, None)),
            redirect_stdout(output),
        ):
            exit_code = run_health(args)

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(report["summary"]["recommended_exit_code"], 2)
        self.assertEqual(report["summary"]["smart"]["failed_devices"], ["sda"])
        self.assertEqual(
            set(report["summary"]["observations"]),
            {"services", "ups", "connections"},
        )
        self.assertEqual(report["sections"], sections)
        collect_sections.assert_called_once_with(
            args, (*DOCTOR_SECTIONS, *HEALTH_OBSERVATION_SECTIONS)
        )


if __name__ == "__main__":
    unittest.main()
