import json
import unittest
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
        self.assertIn("adm_security_compare", names)
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
        self.assertNotIn("adm_platform_module", names)

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
