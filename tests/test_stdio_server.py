import json
import subprocess
import sys
import unittest


def send_json_rpc(process, payload):
    process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline())


class StdioServerTests(unittest.TestCase):
    def test_server_lists_and_calls_v1_tools(self):
        process = subprocess.Popen(
            [sys.executable, "scripts/tw_law_mcp_stdio.py"],
            cwd=".",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        try:
            initialize = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "unittest", "version": "0.1.0"},
                    },
                },
            )
            tools = send_json_rpc(
                process,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            call = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "verify_citation",
                        "arguments": {
                            "law_name": "建築物室內裝修管理辦法",
                            "article_no": "33",
                        },
                    },
                },
            )
            claim_support = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "check_claim_support",
                        "arguments": {
                            "article_text": "申請室內裝修審核時，應檢附申請書與圖說。",
                            "claim": "本案一定可通過",
                        },
                    },
                },
            )
            gates = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "run_audit_gates",
                        "arguments": {
                            "correction_items": [
                                {
                                    "law_name": "建築物室內裝修管理辦法",
                                    "article": "33",
                                    "source_authority_rank": 2,
                                    "source_license_status": "open_data_reusable",
                                    "claim_supported": True,
                                    "claim_support_confidence": 0.9,
                                    "text": "依規定需補交圖說。",
                                }
                            ],
                            "data_governance_state": {
                                "user_consent_record_id": "consent-001",
                                "collection_purpose": "pre_submission_check",
                                "raw_file_retention_policy": "raw_90d_then_archive",
                                "masked_file_retention_policy": "masked_30d_then_delete",
                                "raw_file_access_scope": "project_owner_only",
                                "pii_detection_status": "completed",
                                "pii_masking_status": "done",
                                "deletion_request_supported": True,
                                "audit_log_enabled": True,
                                "vectorization_allowed": True,
                            },
                        },
                    },
                },
            )

            self.assertEqual(initialize["result"]["serverInfo"]["name"], "tw-law-mcp")
            tool_names = {tool["name"] for tool in tools["result"]["tools"]}
            self.assertIn("verify_citation", tool_names)
            self.assertIn("get_source_policy", tool_names)
            self.assertIn("build_law_snapshot", tool_names)
            self.assertIn("check_claim_support", tool_names)
            self.assertIn("get_local_rule", tool_names)
            self.assertIn("detect_illegal_construction_reference", tool_names)
            self.assertIn("run_audit_gates", tool_names)

            citation_payload = json.loads(call["result"]["content"][0]["text"])
            self.assertTrue(citation_payload["exists"])
            self.assertEqual(citation_payload["canonical_name"], "建築物室內裝修管理辦法")

            claim_payload = json.loads(claim_support["result"]["content"][0]["text"])
            self.assertIn("supported", claim_payload)
            self.assertIn("confidence", claim_payload)

            gate_payload = json.loads(gates["result"]["content"][0]["text"])
            self.assertIn("run_meta", gate_payload)
            self.assertTrue(gate_payload["run_meta"]["all_passed"])
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
