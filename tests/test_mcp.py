import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from asustor_nas_cli.mcp import TOOLS, McpError, call_tool, handle_line
from asustor_nas_cli.security import build_incident_report


class McpProtocolTests(unittest.TestCase):
    def test_initialize_and_tool_list(self):
        initialized = handle_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "asustor-nas-cli")
        listed = handle_line(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        tools = listed["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertEqual(len(tools), len(TOOLS))
        self.assertIn("adm_platform_status", names)
        self.assertIn("adm_smart", names)
        self.assertIn("adm_temperature", names)
        self.assertIn("adm_health_summary", names)
        self.assertIn("adm_risk_signals", names)
        self.assertIn("adm_security_compare", names)
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
        self.assertNotIn("adm_platform_module", names)

    def test_health_summary_and_risk_signals_use_read_only_observations(self):
        sections = {
            "system": "hostname: example-nas\nkernel: Linux 6.1.0\nuptime: up 1 day\nMem: 1024 512 512",
            "storage": "Filesystem Size Used Avail Use% Mounted on\n/dev/md0 1T 500G 500G 50% /volume1",
            "raid": "Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n      [2/1] [U_]\nunused devices: <none>",
            "network": "eth0 UP",
            "disks": "devices: /dev/sda /dev/sdb",
        }
        args = SimpleNamespace(
            host="example.invalid",
            user="nas-user",
            port=22,
            timeout=8,
            identity_file=None,
            https_port=8001,
            ca=None,
            insecure=False,
        )

        def run_ssh(_host, _user, _port, command, _timeout, **_kwargs):
            if "__ADM_SMART_BEGIN__" in command:
                return (
                    "__ADM_SMART_BEGIN__\n__ADM_SMART_DEVICE__=sda\n"
                    "__ADM_SMART_HEALTH__=failed\n__ADM_SMART_EXIT__=8\n__ADM_SMART_END__"
                )
            if "__ADM_TEMP_BEGIN__" in command:
                return "__ADM_TEMP_BEGIN__\n__ADM_TEMP_SENSOR__=thermal_zone0|85000\n__ADM_TEMP_END__"
            raise AssertionError("unexpected SSH command")

        with (
            patch("asustor_nas_cli.mcp._settings", return_value=args),
            patch("asustor_nas_cli.mcp._ssh_sections", return_value=sections),
            patch("asustor_nas_cli.mcp.run_ssh", side_effect=run_ssh),
        ):
            health = call_tool("adm_health_summary", {"temperature_warning_celsius": 80})
            risk = call_tool("adm_risk_signals", {"temperature_warning_celsius": 80})

        self.assertEqual(health["report_type"], "diagnostic-summary")
        self.assertEqual(health["sections"], sections)
        self.assertEqual(risk["report_type"], "risk-signals")
        self.assertNotIn("sections", risk)
        self.assertEqual(risk["summary"]["recommended_exit_code"], 2)
        self.assertEqual(
            {signal["code"] for signal in risk["summary"]["risk_signals"]},
            {"raid_degraded", "smart_failed", "temperature_high"},
        )

    def test_health_summary_rejects_invalid_temperature_threshold(self):
        with self.assertRaisesRegex(McpError, "temperature_warning_celsius"):
            call_tool("adm_health_summary", {"temperature_warning_celsius": True})

    def test_security_compare_uses_report_objects_without_nas_configuration(self):
        before = build_incident_report(
            "NAS",
            22,
            scan_output="__ADM_VOLUME__=/volume1\n__ADM_SCAN_ELAPSED__=1\n__ADM_SCAN_EXIT__=0\n",
            host_id="fixture-host",
        )
        after = build_incident_report(
            "NAS",
            22,
            scan_output="__ADM_VOLUME__=/volume1\n__ADM_SCAN_ELAPSED__=1\n__ADM_SCAN_EXIT__=0\n",
            host_id="fixture-host",
        )
        with patch("asustor_nas_cli.mcp._settings", side_effect=AssertionError("NAS config is not needed")):
            result = call_tool("adm_security_compare", {"before": before, "after": after})
        self.assertEqual(result["report_type"], "comparison")
        self.assertEqual(result["host_id"], "fixture-host")

    def test_security_compare_rejects_unsupported_report_objects(self):
        with self.assertRaisesRegex(McpError, "supported ADM CLI report"):
            call_tool(
                "adm_security_compare",
                {"before": {"schema_version": 99}, "after": {"schema_version": 99}},
            )

    def test_invalid_json_returns_parse_error(self):
        response = handle_line("{")
        self.assertEqual(response["error"]["code"], -32700)

    def test_notifications_do_not_emit_response(self):
        self.assertIsNone(handle_line(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})))


if __name__ == "__main__":
    unittest.main()
