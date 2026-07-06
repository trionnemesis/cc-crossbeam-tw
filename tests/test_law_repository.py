import unittest

from tw_law_mcp.repository import load_default_repository


class LawRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repo = load_default_repository()

    def test_list_law_packs_returns_enabled_ntpc_interior_pack(self):
        packs = self.repo.list_law_packs(
            jurisdiction={"central": "TW", "local": "ntpc"},
            case_type="室內裝修",
            procedure_stage="圖說審核",
        )

        self.assertEqual(len(packs), 1)
        self.assertEqual(packs[0]["law_pack_id"], "tw-ntpc-interior-renovation-p0")
        self.assertTrue(packs[0]["enabled"])
        self.assertIn("建築物室內裝修管理辦法", packs[0]["laws"])

    def test_search_law_returns_source_bound_ranked_articles(self):
        results = self.repo.search_law("室內裝修 圖說 簽章", as_of_date="2026-07-06")

        self.assertGreaterEqual(len(results), 1)
        top = results[0]
        self.assertEqual(top["law_name"], "建築物室內裝修管理辦法")
        self.assertEqual(top["source_authority_rank"], 2)
        self.assertEqual(top["source_license_status"], "open_data_reusable")
        self.assertRegex(top["checksum"], r"^[0-9a-f]{64}$")
        self.assertGreater(top["score"], 0)

    def test_get_article_and_verify_citation_use_as_of_snapshot(self):
        article = self.repo.get_article(
            law_id="building-interior-renovation-regulations",
            article_no="33",
            as_of_date="2026-07-06",
        )
        citation = self.repo.verify_citation(
            law_name="建築物室內裝修管理辦法",
            article_no="33",
            effective_date="2024-01-01",
        )

        self.assertEqual(article["article"], "33")
        self.assertIn("室內裝修圖說", article["text"])
        self.assertTrue(citation["exists"])
        self.assertEqual(citation["canonical_name"], "建築物室內裝修管理辦法")
        self.assertEqual(citation["rank"], 2)

    def test_missing_citation_fails_closed(self):
        citation = self.repo.verify_citation(
            law_name="不存在的法規",
            article_no="999",
        )

        self.assertFalse(citation["exists"])
        self.assertEqual(citation["rank"], None)
        self.assertIn("not_found", citation["diff"])

    def test_source_policy_keeps_authority_and_license_separate(self):
        policy = self.repo.get_source_policy(
            "https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=D0070149"
        )

        self.assertEqual(policy["source_authority_rank"], 2)
        self.assertEqual(policy["source_license_status"], "open_data_reusable")
        self.assertEqual(policy["source_update_policy"], "adapter_checked")
        self.assertEqual(policy["crawl_policy"], "snapshot_with_checksum")

    def test_resolve_procedure_requirements_is_stage_specific(self):
        drawing_review = self.repo.resolve_procedure_requirements("圖說審核", "ntpc")
        completion_review = self.repo.resolve_procedure_requirements("竣工查驗", "ntpc")

        self.assertIn("室內裝修圖說", drawing_review["required_documents"])
        self.assertIn("竣工圖說", completion_review["required_documents"])
        self.assertNotEqual(
            drawing_review["required_documents"],
            completion_review["required_documents"],
        )

    def test_build_law_snapshot_returns_pack_entries_with_metadata(self):
        snapshot = self.repo.build_law_snapshot(
            jurisdiction={"central": "TW", "local": "ntpc"},
            case_type="室內裝修",
            procedure_stage="圖說審核",
            as_of_date="2026-07-06",
        )

        self.assertTrue(snapshot["law_snapshot_id"])
        self.assertEqual(snapshot["as_of_date"], "2026-07-06")
        self.assertIn("run_date", snapshot["as_of_date_basis"])
        self.assertTrue(snapshot["entries"])
        entry = snapshot["entries"][0]
        self.assertIn("law_id", entry)
        self.assertIn("source_adapter_id", entry)
        self.assertIn("source_update_policy", entry)
        self.assertIn("source_policy_state", snapshot)
        self.assertTrue(snapshot["source_policy_state"])

    def test_claim_support_fails_opened_for_unmatched_claim(self):
        support = self.repo.check_claim_support(
            article_text="室內裝修須提交申請書與圖說。",
            claim="本案一定可核准",
        )
        self.assertFalse(support["supported"])
        self.assertLess(support["confidence"], 0.6)
        self.assertEqual(support["unsupported_reason"], "claim 支持不足，需降級人工確認")

    def test_illegal_construction_reference_only_flags_for_manual_confirmation(self):
        signal = self.repo.detect_illegal_construction_reference(
            files=["違建項目簽證表_附件.docx", "施工圖.pdf"],
            text="補件檢附違建範圍資料。",
        )

        self.assertTrue(signal["present"])
        self.assertIn("違建項目簽證表", signal["evidence_type"])
        self.assertIn("僅標記文件存在與需人工確認", signal["handling"])

    def test_get_local_rule_resolves_ntpc_registry(self):
        rule = self.repo.get_local_rule(
            jurisdiction="ntpc",
            rule_name="新北市建築物室內裝修審核及查驗作業事項規範",
        )

        self.assertTrue(rule["exists"])
        self.assertIn("procedure_stages", rule)
        self.assertEqual(rule["jurisdiction"], "ntpc")

    def test_run_audit_gates_passes_with_compliant_items(self):
        gate_meta = self.repo.run_audit_gates(
            correction_items=[
                {
                    "law_name": "建築物室內裝修管理辦法",
                    "article": "33",
                    "source_authority_rank": 2,
                    "source_license_status": "open_data_reusable",
                    "claim_supported": True,
                    "claim_support_confidence": 0.91,
                    "text": "建議補件並補強簽章資料。",
                }
            ],
            data_governance_state={
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
        )

        self.assertTrue(gate_meta["run_meta"]["all_passed"])
        self.assertFalse(gate_meta["run_meta"]["human_review_required"])
        self.assertIn("gates", gate_meta["run_meta"])
        self.assertEqual(gate_meta["run_meta"]["gates"][0]["index"], 1)
        self.assertEqual(gate_meta["run_meta"]["gates"][0]["retry_count"], 0)
        self.assertEqual(
            {item["gate"] for item in gate_meta["run_meta"]["gate_results"]},
            {
                "schema_valid",
                "citation_exists",
                "source_rank_valid",
                "source_license_valid",
                "claim_supported",
                "red_line_linter",
                "data_governance",
            },
        )

    def test_run_audit_gates_fails_red_line_and_claim(self):
        gate_meta = self.repo.run_audit_gates(
            correction_items=[
                {
                    "law_name": "建築物室內裝修管理辦法",
                    "article": "33",
                    "source_authority_rank": 2,
                    "source_license_status": "unknown",
                    "claim_supported": False,
                    "claim_support_confidence": 0.2,
                    "text": "本案一定可通過。",
                }
            ],
            data_governance_state={
                "consent_record_id": "consent-002",
                "collection_purpose": "pre_submission_check",
                "raw_file_retention_policy": "raw_90d_then_archive",
                "masked_file_retention_policy": "masked_30d_then_delete",
                "raw_file_access_scope": "project_owner_only",
                "pii_detection_status": "completed",
                "pii_masking_status": "done",
                "deletion_request_supported": True,
                "audit_log_enabled": True,
                "vectorization_allowed": False,
            },
        )

        self.assertFalse(gate_meta["run_meta"]["all_passed"])
        self.assertTrue(gate_meta["run_meta"]["human_review_required"])
        gate_status = {item["gate"]: item["status"] for item in gate_meta["run_meta"]["gate_results"]}
        self.assertEqual(gate_status["source_license_valid"], "failed")
        self.assertEqual(gate_status["claim_supported"], "failed")
        self.assertEqual(gate_status["red_line_linter"], "failed")
        self.assertEqual(gate_status["data_governance"], "failed")


if __name__ == "__main__":
    unittest.main()
