import json
import unittest

from tw_law_mcp.server import TwLawMcpServer


class LocalRuleMcpSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.server = TwLawMcpServer()

    def test_run_phase_acceptance_exposes_local_rule_lifecycle_gate(self):
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "run_phase_acceptance", "arguments": {}},
            }
        )
        self.assertIsNotNone(response)
        result = response["result"]
        self.assertFalse(result["isError"])
        payload = json.loads(result["content"][0]["text"])
        self.assertIn("local_rule_lifecycle", payload["gates"])
        self.assertTrue(payload["gates"]["local_rule_lifecycle"])
        self.assertIn("local_rule_lifecycle", payload["details"])

    def test_initialize_reports_package_version(self):
        response = self.server.handle(
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["result"]["serverInfo"]["version"], "0.5.0")


if __name__ == "__main__":
    unittest.main()
