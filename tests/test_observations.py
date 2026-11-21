import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from asustor_nas_cli.cli import main
from asustor_nas_cli.commands import SERVICE_PROCESS_NAMES, build_remote_command
from asustor_nas_cli.observations import (
    build_connections_report,
    build_services_report,
    build_ups_report,
    parse_connections_output,
    parse_services_output,
    parse_ups_output,
)
from asustor_nas_cli.smart_health import parse_smart_health_output
from asustor_nas_cli.summaries import build_health_summary, build_risk_signals_report
from asustor_nas_cli.temperature import parse_temperature_output


def service_output(counts=None):
    counts = counts or {name: 1 for name in SERVICE_PROCESS_NAMES}
    rows = [f"__ADM_SERVICE__={name}|{counts[name]}" for name in SERVICE_PROCESS_NAMES if name in counts]
    return "\n".join(("__ADM_SERVICES_BEGIN__", *rows, "__ADM_SERVICES_END__"))


def ups_output(status="online", charge="87.5", count=1):
    return "\n".join(
        (
            "__ADM_UPS_BEGIN__",
            "__ADM_UPS_SOURCE__=nut",
            f"__ADM_UPS_COUNT__={count}",
            f"__ADM_UPS_DEVICE__=1|{status}|{charge}",
            "__ADM_UPS_END__",
        )
    )


def connections_output():
    return "\n".join(
        (
            "__ADM_CONNECTIONS_BEGIN__",
            "__ADM_TCP__=tcp|12|2|4",
            "__ADM_TCP__=tcp6|5|1|3",
            "__ADM_CONNECTIONS_END__",
        )
    )


class ObservationParserTests(unittest.TestCase):
    def test_remote_observation_commands_are_fixed_and_read_only(self):
        command = build_remote_command(("services", "ups", "connections"))

        self.assertIn("/proc/[0-9]*/comm", command)
        self.assertIn("upsc -l localhost", command)
        self.assertIn("/proc/net/$table", command)
        self.assertNotIn("upscmd", command)
        self.assertNotIn("upsrw", command)
        self.assertNotIn("kill ", command)

    def test_services_reports_only_allowlisted_process_counts(self):
        result = parse_services_output(service_output({"sshd": 2, "nginx": 3}))

        self.assertEqual(result["coverage"], "partial")
        self.assertEqual(result["processes"], [
            {"name": "sshd", "process_count": 2},
            {"name": "nginx", "process_count": 3},
        ])
        self.assertNotIn("password", json.dumps(result).lower())

    def test_services_rejects_unknown_names_and_duplicate_rows(self):
        output = service_output({"sshd": 1}) + "\n__ADM_SERVICE__=operator|1\n__ADM_SERVICE__=sshd|2"

        result = parse_services_output(output)

        self.assertEqual(result["coverage"], "partial")
        self.assertEqual(len(result["processes"]), 1)

    def test_ups_parses_status_charge_and_hides_device_names(self):
        result = parse_ups_output(ups_output(status="on_battery", charge="42"))

        self.assertEqual(result["coverage"], "complete")
        self.assertEqual(result["source"], "nut")
        self.assertEqual(result["devices"][0]["status"], "on_battery")
        self.assertEqual(result["devices"][0]["battery_charge_percent"], 42.0)
        self.assertNotIn("ups_name", result)

    def test_ups_marks_unavailable_and_malformed_values_without_exposing_them(self):
        unavailable = parse_ups_output(
            "__ADM_UPS_BEGIN__\n__ADM_UPS_SOURCE__=none\n__ADM_UPS_END__"
        )
        malformed = parse_ups_output(ups_output(charge="100000"))
        stray = parse_ups_output(
            "__ADM_UPS_SOURCE__=nut\n__ADM_UPS_COUNT__=1\n"
            "__ADM_UPS_DEVICE__=1|online|100"
        )

        self.assertEqual(unavailable["coverage"], "unavailable")
        self.assertEqual(malformed["coverage"], "partial")
        self.assertIsNone(malformed["devices"][0]["battery_charge_percent"])
        self.assertEqual(stray["coverage"], "unavailable")
        self.assertEqual(stray["devices"], [])

    def test_ups_marks_multiple_devices_partial_when_only_first_is_observed(self):
        result = parse_ups_output(ups_output(count=2))

        self.assertEqual(result["coverage"], "partial")
        self.assertEqual(result["device_count"], 2)
        self.assertEqual(len(result["devices"]), 1)

    def test_connections_reports_state_counts_without_addresses(self):
        result = parse_connections_output(connections_output())

        self.assertEqual(result["coverage"], "complete")
        self.assertEqual(result["ipv4"], {"total": 12, "established": 2, "listening": 4})
        self.assertEqual(result["ipv6"]["total"], 5)
        self.assertNotIn("192.0.2.1", json.dumps(result))

    def test_connections_marks_missing_family_as_partial(self):
        result = parse_connections_output(
            "__ADM_CONNECTIONS_BEGIN__\n__ADM_TCP__=tcp|2|1|1\n__ADM_CONNECTIONS_END__"
        )

        self.assertEqual(result["coverage"], "partial")
        self.assertIsNone(result["ipv6"])

    def test_reports_have_redacted_host_and_cli_is_read_only(self):
        host = "nas.example.invalid"
        reports = (
            build_services_report(service_output(), host, 22, "0123456789abcdef"),
            build_ups_report(ups_output(), host, 22, "0123456789abcdef"),
            build_connections_report(connections_output(), host, 22, "0123456789abcdef"),
        )
        self.assertEqual(
            [report["report_type"] for report in reports],
            ["service-observations", "ups-observations", "connection-observations"],
        )
        self.assertTrue(all(report["host"] == "NAS" for report in reports))

        stdout = io.StringIO()
        with (
            patch.object(sys, "argv", ["adm", "connections", "--host", host, "--user", "operator", "--json"]),
            patch("asustor_nas_cli.cli_observations.run_ssh_sections", return_value={"connections": connections_output()}),
            redirect_stdout(stdout),
        ):
            result = main()
        response = json.loads(stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(response["host"], "NAS")
        self.assertNotIn(host, stdout.getvalue())
        self.assertNotIn("operator", stdout.getvalue())

    def test_optional_observations_reach_health_and_risk_reports_without_health_verdict(self):
        base_sections = {
            "system": "kernel: Linux 3.4.26\nuptime: up 1 day\nMem: 512 200 312",
            "storage": "Filesystem Size Used Avail Use% Mounted on\n/dev/md1 1T 500G 500G 50% /volume1",
            "raid": "Personalities : [raid1]\nunused devices: <none>",
            "network": "available",
            "disks": "available",
        }
        smart = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n__ADM_SMART_ERROR__=smartctl_unavailable\n__ADM_SMART_END__"
        )
        temperature = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n__ADM_TEMP_NO_SENSORS__\n__ADM_TEMP_END__"
        )
        without_optional = build_health_summary(
            base_sections, smart, temperature, "nas.example.invalid", 22, 80
        )
        observed_sections = {
            **base_sections,
            "services": service_output(),
            "ups": ups_output(),
            "connections": connections_output(),
        }
        with_optional = build_health_summary(
            observed_sections, smart, temperature, "nas.example.invalid", 22, 80
        )
        risk_report = build_risk_signals_report(with_optional)

        self.assertEqual(with_optional["summary"]["observations"]["services"]["coverage"], "complete")
        self.assertEqual(with_optional["summary"]["observations"]["ups"]["coverage"], "complete")
        self.assertEqual(with_optional["summary"]["observations"]["connections"]["coverage"], "complete")
        self.assertEqual(risk_report["summary"]["observations"], with_optional["summary"]["observations"])
        self.assertEqual(
            (with_optional["summary"]["state"], with_optional["summary"]["coverage"], with_optional["summary"]["recommended_exit_code"]),
            (without_optional["summary"]["state"], without_optional["summary"]["coverage"], without_optional["summary"]["recommended_exit_code"]),
        )


if __name__ == "__main__":
    unittest.main()
