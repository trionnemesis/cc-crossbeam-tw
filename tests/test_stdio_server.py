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
                            "article_no": "23",
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
                                    "article": "23",
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
            fixture_status = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "get_fixture_baseline_status",
                        "arguments": {},
                    },
                },
            )
            source_policy_acceptance = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "run_source_policy_acceptance",
                        "arguments": {},
                    },
                },
            )
            jurisdiction_acceptance = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "run_jurisdiction_registry_acceptance",
                        "arguments": {},
                    },
                },
            )
            packaging_acceptance = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "run_packaging_acceptance",
                        "arguments": {},
                    },
                },
            )
            phase_acceptance = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "run_phase_acceptance",
                        "arguments": {},
                    },
                },
            )
            scenario_acceptance = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 101,
                    "method": "tools/call",
                    "params": {
                        "name": "run_scenario_matrix_acceptance",
                        "arguments": {},
                    },
                },
            )
            stage_confidence = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": "resolve_procedure_stage_confidence",
                        "arguments": {
                            "text": "本案申請圖說審核，請補室內裝修圖說。",
                            "jurisdiction": "ntpc",
                        },
                    },
                },
            )
            parsed_document = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {
                        "name": "parse_masked_document",
                        "arguments": {
                            "text": (
                                "發文機關：新北市政府工務局\n"
                                "發文字號：REDACTED-STDIO\n"
                                "主旨：室內裝修圖說審核補正通知\n"
                                "說明一：請補申請書、室內裝修圖說。"
                            ),
                            "jurisdiction": "ntpc",
                        },
                    },
                },
            )
            fixture_acceptance = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "tools/call",
                    "params": {
                        "name": "run_fixture_pipeline_acceptance",
                        "arguments": {},
                    },
                },
            )
            hitl_confirmation = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 14,
                    "method": "tools/call",
                    "params": {
                        "name": "apply_hitl_confirmations",
                        "arguments": {
                            "procedure_stage_signal": {
                                "procedure_stage": None,
                                "confidence": 0.5,
                                "human_review_required": True,
                                "reason": "ambiguous_or_low_confidence",
                            },
                            "atomic_items": [
                                {
                                    "item_id": "auto-001",
                                    "source_span": "說明二：簽章確認",
                                    "adjudication": "需人工認定",
                                }
                            ],
                            "answers": [
                                {
                                    "question_key": "confirm_procedure_stage",
                                    "selected_option": "圖說審核",
                                },
                                {
                                    "question_key": "review_auto-001",
                                    "answer_text": "專業人員已確認需補簽章責任文件。",
                                },
                            ],
                        },
                    },
                },
            )

            self.assertEqual(initialize["result"]["serverInfo"]["name"], "tw-law-mcp")
            tool_names = {tool["name"] for tool in tools["result"]["tools"]}
            self.assertIn("verify_citation", tool_names)
            self.assertIn("get_source_policy", tool_names)
            self.assertIn("compare_source_policies", tool_names)
            self.assertIn("run_source_policy_acceptance", tool_names)
            self.assertIn("list_jurisdictions", tool_names)
            self.assertIn("run_jurisdiction_registry_acceptance", tool_names)
            self.assertIn("run_packaging_acceptance", tool_names)
            self.assertIn("run_phase_acceptance", tool_names)
            self.assertIn("run_scenario_matrix_acceptance", tool_names)
            self.assertIn("build_law_snapshot", tool_names)
            self.assertIn("check_claim_support", tool_names)
            self.assertIn("get_local_rule", tool_names)
            self.assertIn("resolve_procedure_stage_confidence", tool_names)
            self.assertIn("get_fixture_baseline_status", tool_names)
            self.assertIn("run_fixture_pipeline_acceptance", tool_names)
            self.assertIn("extract_file_metadata", tool_names)
            self.assertIn("parse_masked_document", tool_names)
            self.assertIn("normalize_atomic_correction_items", tool_names)
            self.assertIn("build_sheet_manifest", tool_names)
            self.assertIn("build_hitl_confirmation_packet", tool_names)
            self.assertIn("apply_hitl_confirmations", tool_names)
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

            fixture_payload = json.loads(fixture_status["result"]["content"][0]["text"])
            self.assertTrue(fixture_payload["g2_complete"])
            self.assertEqual(fixture_payload["case_count"], 12)
            self.assertEqual(fixture_payload["atomic_item_count"], 84)

            policy_acceptance_payload = json.loads(
                source_policy_acceptance["result"]["content"][0]["text"]
            )
            self.assertTrue(policy_acceptance_payload["all_passed"])
            self.assertEqual(policy_acceptance_payload["failures"], [])

            jurisdiction_payload = json.loads(jurisdiction_acceptance["result"]["content"][0]["text"])
            self.assertTrue(jurisdiction_payload["all_passed"])
            self.assertEqual(jurisdiction_payload["non_ntpc_count"], 2)

            packaging_payload = json.loads(packaging_acceptance["result"]["content"][0]["text"])
            self.assertTrue(packaging_payload["all_passed"])
            self.assertEqual(packaging_payload["decision"], "standalone_mcp_server_first")

            phase_payload = json.loads(phase_acceptance["result"]["content"][0]["text"])
            self.assertTrue(phase_payload["all_passed"])
            self.assertTrue(all(phase_payload["gates"].values()))
            self.assertIn("scenario_matrix", phase_payload["gates"])

            scenario_payload = json.loads(scenario_acceptance["result"]["content"][0]["text"])
            self.assertTrue(scenario_payload["all_passed"])
            self.assertEqual(scenario_payload["failures"], [])
            self.assertGreaterEqual(scenario_payload["query_count"], 6)

            stage_payload = json.loads(stage_confidence["result"]["content"][0]["text"])
            self.assertEqual(stage_payload["procedure_stage"], "圖說審核")
            self.assertFalse(stage_payload["human_review_required"])

            parsed_payload = json.loads(parsed_document["result"]["content"][0]["text"])
            self.assertEqual(parsed_payload["agency"], "新北市政府工務局")
            self.assertEqual(parsed_payload["document_no"], "REDACTED-STDIO")
            self.assertIn("procedure_stage_signal", parsed_payload)

            acceptance_payload = json.loads(fixture_acceptance["result"]["content"][0]["text"])
            self.assertTrue(acceptance_payload["all_cases_passed"])
            self.assertEqual(acceptance_payload["case_count"], 12)
            self.assertEqual(acceptance_payload["atomic_item_count"], 84)
            self.assertEqual(acceptance_payload["failed_cases"], [])

            hitl_payload = json.loads(hitl_confirmation["result"]["content"][0]["text"])
            self.assertEqual(hitl_payload["confirmation_status"], "complete")
            self.assertFalse(hitl_payload["human_review_required"])
            self.assertEqual(hitl_payload["procedure_stage_signal"]["procedure_stage"], "圖說審核")
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
