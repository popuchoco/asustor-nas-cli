import json
import unittest

from asustor_nas_cli.mcp import TOOLS, handle_line


class McpProtocolTests(unittest.TestCase):
    def test_initialize_and_tool_list(self):
        initialized = handle_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "asustor-nas-cli")
        listed = handle_line(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        tools = listed["result"]["tools"]
        self.assertEqual(len(tools), len(TOOLS))
        self.assertIn("adm_platform_status", {tool["name"] for tool in tools})
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
        self.assertNotIn("adm_platform_module", {tool["name"] for tool in tools})

    def test_invalid_json_returns_parse_error(self):
        response = handle_line("{")
        self.assertEqual(response["error"]["code"], -32700)

    def test_notifications_do_not_emit_response(self):
        self.assertIsNone(handle_line(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})))


if __name__ == "__main__":
    unittest.main()
