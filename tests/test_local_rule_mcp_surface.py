import copy
import json
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from tw_law_mcp import __version__
from tw_law_mcp.local_rule_lifecycle import load_local_rule_records
from tw_law_mcp.server import TwLawMcpServer


REPO_ROOT = Path(__file__).resolve().parents[1]
NTPC_RULE_NAME = "新北市建築物室內裝修審核及查驗作業事項規範"


class LocalRuleMcpSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.server = TwLawMcpServer()

    def _call_tool(self, name, arguments):
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        self.assertIsNotNone(response)
        result = response["result"]
        self.assertFalse(result["isError"])
        return json.loads(result["content"][0]["text"])

    def test_run_phase_acceptance_exposes_local_rule_lifecycle_gate(self):
        payload = self._call_tool("run_phase_acceptance", {})
        self.assertIn("local_rule_lifecycle", payload["gates"])
        self.assertTrue(payload["gates"]["local_rule_lifecycle"])
        self.assertIn("local_rule_lifecycle", payload["details"])

    def test_current_local_rule_is_lifecycle_bound(self):
        payload = self._call_tool(
            "get_local_rule",
            {"jurisdiction": "ntpc", "rule_name": NTPC_RULE_NAME},
        )
        self.assertTrue(payload["exists"])
        self.assertFalse(payload["human_review_required"])
        self.assertEqual(payload["official_identifier"], "C0170020")
        self.assertEqual(payload["legal_status"], "active")
        self.assertEqual(payload["lifecycle_status"], "current_active")
        self.assertIsNone(payload["effective_from"])
        self.assertGreaterEqual(len(payload["normalized_requirements"]), 5)

    def test_historical_local_rule_lookup_fails_closed_when_effective_from_unknown(self):
        payload = self._call_tool(
            "get_local_rule",
            {
                "jurisdiction": "ntpc",
                "rule_name": NTPC_RULE_NAME,
                "as_of_date": "2020-01-01",
            },
        )
        self.assertFalse(payload["exists"])
        self.assertTrue(payload["human_review_required"])
        self.assertEqual(payload["lifecycle_status"], "unknown_effective_from")
        self.assertEqual(payload["required_documents"], [])

    def test_pending_reverification_blocks_mcp_local_rule_lookup(self):
        records = copy.deepcopy(load_local_rule_records())
        records[0]["legal_status"] = "pending_reverification"
        with patch("tw_law_mcp.server.load_local_rule_records", return_value=records):
            payload = self._call_tool(
                "get_local_rule",
                {"jurisdiction": "ntpc", "rule_name": NTPC_RULE_NAME},
            )
        self.assertFalse(payload["exists"])
        self.assertTrue(payload["human_review_required"])
        self.assertEqual(payload["lifecycle_status"], "pending_reverification")
        self.assertEqual(payload["required_documents"], [])

    def test_missing_lifecycle_record_blocks_legacy_projection(self):
        with patch("tw_law_mcp.server.load_local_rule_records", return_value=[]):
            payload = self._call_tool(
                "get_local_rule",
                {"jurisdiction": "ntpc", "rule_name": NTPC_RULE_NAME},
            )
        self.assertFalse(payload["exists"])
        self.assertTrue(payload["human_review_required"])
        self.assertEqual(payload["lifecycle_status"], "lifecycle_record_missing")
        self.assertEqual(payload["required_documents"], [])

    def test_malformed_current_lifecycle_date_blocks_lookup(self):
        records = copy.deepcopy(load_local_rule_records())
        records[0]["effective_from"] = "not-a-date"
        with patch("tw_law_mcp.server.load_local_rule_records", return_value=records):
            payload = self._call_tool(
                "get_local_rule",
                {"jurisdiction": "ntpc", "rule_name": NTPC_RULE_NAME},
            )
        self.assertFalse(payload["exists"])
        self.assertTrue(payload["human_review_required"])
        self.assertEqual(payload["lifecycle_status"], "invalid_record_date")
        self.assertEqual(payload["required_documents"], [])

    def test_initialize_reports_package_version(self):
        response = self.server.handle(
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["result"]["serverInfo"]["version"], "0.5.1")
        self.assertEqual(response["result"]["serverInfo"]["version"], __version__)

    def test_distribution_metadata_matches_runtime_version(self):
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
