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
            article_no="23",
            as_of_date="2026-07-06",
        )
        citation = self.repo.verify_citation(
            law_name="建築物室內裝修管理辦法",
            article_no="23",
            effective_date="2024-01-01",
        )

        self.assertEqual(article["article"], "23")
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
            "https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=D0070148"
        )

        self.assertEqual(policy["source_authority_rank"], 2)
        self.assertEqual(policy["source_license_status"], "open_data_reusable")
        self.assertEqual(policy["source_update_policy"], "adapter_checked")
        self.assertEqual(policy["crawl_policy"], "snapshot_with_checksum")

    def test_compare_source_policies_tracks_license_and_update_differences(self):
        comparisons = self.repo.compare_source_policies()

        self.assertEqual(len(comparisons), 1)
        comparison = comparisons[0]
        self.assertEqual(
            comparison["comparison_id"],
            "moj-vs-ntpc-official-source-policy",
        )
        fields = {item["field"] for item in comparison["differences"]}
        self.assertIn("source_license_status", fields)
        self.assertIn("source_update_policy", fields)
        policies = comparison["source_policy_state"]
        self.assertEqual(
            {policy["source_license_status"] for policy in policies},
            {"open_data_reusable", "official_reference_only"},
        )

    def test_source_policy_acceptance_covers_all_p0_source_classes(self):
        acceptance = self.repo.run_source_policy_acceptance()

        self.assertTrue(acceptance["all_passed"])
        self.assertEqual(acceptance["failures"], [])
        self.assertEqual(acceptance["article_source_count"], 3)
        self.assertEqual(acceptance["source_class_count"], 2)
        self.assertEqual(acceptance["comparison_count"], 1)
        self.assertEqual(len(acceptance["covered_source_classes"]), 2)

    def test_list_jurisdictions_keeps_disabled_stubs_fail_closed(self):
        enabled = self.repo.list_jurisdictions()
        all_entries = self.repo.list_jurisdictions(include_disabled=True)

        self.assertEqual([entry["jurisdiction"]["local"] for entry in enabled], ["ntpc"])
        disabled = [entry for entry in all_entries if not entry["enabled"]]
        self.assertEqual({entry["jurisdiction"]["local"] for entry in disabled}, {"tpe", "tyc"})
        self.assertTrue(all("stub only" in entry["handling"] for entry in disabled))

    def test_jurisdiction_registry_acceptance_verifies_fail_closed_expansion(self):
        acceptance = self.repo.run_jurisdiction_registry_acceptance()

        self.assertTrue(acceptance["all_passed"])
        self.assertEqual(acceptance["failures"], [])
        self.assertEqual(acceptance["registry_count"], 3)
        self.assertEqual(acceptance["enabled_count"], 1)
        self.assertEqual(acceptance["disabled_count"], 2)
        self.assertEqual(acceptance["non_ntpc_count"], 2)

    def test_packaging_acceptance_verifies_standalone_mcp_strategy(self):
        acceptance = self.repo.run_packaging_acceptance()

        self.assertTrue(acceptance["all_passed"])
        self.assertEqual(acceptance["failures"], [])
        self.assertEqual(acceptance["decision"], "standalone_mcp_server_first")
        self.assertTrue(acceptance["codex_config_present"])
        self.assertTrue(acceptance["claude_config_present"])
        self.assertTrue(acceptance["adr_present"])
        self.assertTrue(acceptance["standalone_entrypoint_present"])

    def test_phase_acceptance_covers_all_roadmap_gates(self):
        acceptance = self.repo.run_phase_acceptance()

        self.assertTrue(acceptance["all_passed"])
        self.assertTrue(
            {
                "p0_source_policy",
                "procedure_stage_hitl",
                "g2_fixture_baseline",
                "metadata_extraction",
                "jurisdiction_registry",
                "packaging_strategy",
                "scenario_matrix",
                "split_data_layout",
                "source_adapters",
                "two_stage_flow",
            }.issubset(set(acceptance["gates"]))
        )
        self.assertTrue(all(acceptance["gates"].values()))
        self.assertEqual(
            acceptance["details"]["g2_fixture_baseline"]["atomic_item_count"],
            84,
        )
        self.assertEqual(
            acceptance["details"]["metadata_extraction"]["agent_input_policy"],
            "metadata_only_no_raw_drawing_or_document_content",
        )

    def test_scenario_matrix_acceptance_covers_mvp_categories(self):
        acceptance = self.repo.run_scenario_matrix_acceptance()

        self.assertTrue(acceptance["all_passed"])
        self.assertEqual(acceptance["failures"], [])
        self.assertEqual(
            set(acceptance["mvp_categories"]),
            {
                "procedure",
                "fire_equipment",
                "fire_compartment",
                "material",
                "completion_packet",
                "response_draft",
            },
        )
        self.assertEqual(set(acceptance["missing_mvp_categories"]), set())
        self.assertGreaterEqual(acceptance["query_count"], 30)
        self.assertTrue(
            all(count >= 5 for count in acceptance["mvp_query_counts"].values())
        )
        self.assertEqual(acceptance["missing_tools"], [])
        self.assertEqual(acceptance["missing_source_packs"], [])
        self.assertTrue(all(result["passed"] for result in acceptance["scenario_results"]))

    def test_split_data_layout_exposes_source_units_and_registries(self):
        acceptance = self.repo.run_data_layout_acceptance()

        self.assertTrue(acceptance["all_passed"])
        self.assertEqual(acceptance["failures"], [])
        self.assertEqual(acceptance["source_pack_count"], 5)
        self.assertEqual(
            set(acceptance["registry_files"]),
            {"jurisdictions.json", "procedure_stages.json", "domain_tags.json"},
        )
        self.assertEqual(
            set(acceptance["fixture_files"]),
            {"tw_scenario_queries.json", "ntpc_synthetic_cases.json"},
        )
        self.assertGreaterEqual(acceptance["source_unit_count"], 10)

    def test_source_adapters_normalize_source_units(self):
        units = self.repo.list_source_units()

        self.assertGreaterEqual(len(units), 10)
        adapter_ids = {unit["source_adapter_id"] for unit in units}
        self.assertTrue(
            {
                "tw-moj-law-adapter",
                "abri-material-reference-adapter",
                "ntpc-official-portal",
                "ntpc-eservice-reference",
            }.issubset(adapter_ids)
        )
        for unit in units:
            self.assertRegex(unit["checksum"], r"^[0-9a-f]{64}$")
            self.assertIn("domain_tags", unit)
            self.assertTrue(unit["source_url"])

    def test_scenario_tools_fail_closed_for_professional_domains(self):
        scenario = self.repo.resolve_tw_scenario(
            jurisdiction={"central": "TW", "local": "ntpc"},
            case_type="室內裝修",
            procedure_stage="變更使用併室內裝修竣工查驗",
            change_of_use_flag=True,
            fire_equipment_change_flag=True,
            material_evidence_status="missing",
        )
        fire = self.repo.check_fire_equipment_routing(
            text="本案調整灑水頭與火警探測器位置。",
            fire_equipment_change_flag=True,
        )
        compartment = self.repo.check_fire_compartment_evidence(
            atomic_items=[{"item_id": "c1", "text": "風管穿越防火牆處請補防火填塞說明"}]
        )
        material = self.repo.check_material_evidence(
            material_records=[
                {
                    "name": "耐燃一級天花板",
                    "location": "A-101",
                    "certificate_no": "",
                }
            ]
        )
        packet = self.repo.build_ntpc_submission_packet("竣工查驗", "ntpc")
        fallback = self.repo.plan_web_search_fallback("新北某地方公告查無", "ntpc")

        self.assertIn("tw-central-fire-equipment", scenario["source_pack_ids"])
        self.assertTrue(scenario["human_review_required"])
        self.assertEqual(
            fire["routing_status"],
            "requires_fire_authority_document_evidence",
        )
        self.assertTrue(fire["professional_confirmation_required"])
        self.assertTrue(compartment["human_review_required"])
        self.assertEqual(material["authenticity_judgment"], "not_adjudicated")
        self.assertIn("材料證明文件", packet["checklist_labels"])
        self.assertEqual(fallback["answer_policy"], "fallback_plan_only")

    def test_two_stage_contractor_flow_builds_response_without_assurance_claims(self):
        analysis = self.repo.run_tw_corrections_analysis(
            text=(
                "發文機關：新北市政府工務局\n"
                "主旨：室內裝修竣工查驗補正通知\n"
                "說明一：請補竣工圖說、材料證明文件及消防安全設備相關文件。\n"
                "說明二：風管穿越防火牆處請補防火填塞說明。"
            ),
            files=[
                {"filename": "A101_竣工圖說.pdf", "file_type": "drawing_file"},
                {"filename": "M001_材料表.pdf", "file_type": "drawing_file"},
            ],
            procedure_stage="竣工查驗",
            as_of_date="2026-07-06",
        )
        response = self.repo.run_tw_corrections_response(
            analysis_artifacts=analysis["artifacts"],
            answers=[
                {
                    "question_key": "review_auto-001",
                    "answer_text": "專業人員確認將補材料證明文件。",
                }
            ],
        )

        self.assertEqual(analysis["stage"], "analysis")
        self.assertIn("document_parsed.json", analysis["artifacts"])
        self.assertIn("atomic_correction_items.json", analysis["artifacts"])
        self.assertIn("client_questions.json", analysis["artifacts"])
        self.assertEqual(response["stage"], "response")
        self.assertIn("response_draft.md", response["artifacts"])
        self.assertIn("professional_review_packet.md", response["artifacts"])
        draft = response["artifacts"]["response_draft.md"]
        self.assertNotIn("已合規", draft)
        self.assertNotIn("保證通過", draft)
        self.assertNotIn("無違法", draft)

    def test_resolve_procedure_requirements_is_stage_specific(self):
        drawing_review = self.repo.resolve_procedure_requirements("圖說審核", "ntpc")
        completion_review = self.repo.resolve_procedure_requirements("竣工查驗", "ntpc")

        self.assertIn("室內裝修圖說", drawing_review["required_documents"])
        self.assertIn("竣工圖說", completion_review["required_documents"])
        self.assertNotEqual(
            drawing_review["required_documents"],
            completion_review["required_documents"],
        )

    def test_resolve_procedure_stage_confidence_routes_ambiguous_text_to_hitl(self):
        confident = self.repo.resolve_procedure_stage_confidence(
            text="本案申請圖說審核，請補室內裝修圖說與簽章責任文件。",
            jurisdiction="ntpc",
        )
        ambiguous = self.repo.resolve_procedure_stage_confidence(
            text="文件同時提到圖說審核與竣工查驗，需確認程序。",
            jurisdiction="ntpc",
        )

        self.assertEqual(confident["procedure_stage"], "圖說審核")
        self.assertGreaterEqual(confident["confidence"], 0.8)
        self.assertFalse(confident["human_review_required"])
        self.assertTrue(ambiguous["human_review_required"])
        self.assertEqual(ambiguous["reason"], "ambiguous_or_low_confidence")

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

    def test_fixture_baseline_reports_g2_complete_when_targets_are_met(self):
        status = self.repo.get_fixture_baseline_status()

        self.assertEqual(status["fixture_set_id"], "g2-synthetic-deidentified-ntpc-v0")
        self.assertEqual(status["target_case_count"], 12)
        self.assertEqual(status["target_atomic_item_count"], 80)
        self.assertEqual(status["case_count"], 12)
        self.assertEqual(status["atomic_item_count"], 84)
        self.assertFalse(status["raw_files_committed"])
        self.assertFalse(status["invalid_cases"])
        self.assertFalse(status["invalid_items"])
        self.assertTrue(status["g2_complete"])
        self.assertEqual(status["status"], "complete")

    def test_fixture_pipeline_acceptance_runs_all_g2_cases_through_gates(self):
        acceptance = self.repo.run_fixture_pipeline_acceptance()

        self.assertEqual(acceptance["fixture_set_id"], "g2-synthetic-deidentified-ntpc-v0")
        self.assertEqual(acceptance["case_count"], 12)
        self.assertEqual(acceptance["atomic_item_count"], 84)
        self.assertEqual(acceptance["snapshot_count"], 12)
        self.assertGreaterEqual(acceptance["sheet_manifest_count"], 12)
        self.assertEqual(acceptance["failed_cases"], [])
        self.assertEqual(acceptance["gate_failures"], [])
        self.assertTrue(acceptance["all_cases_passed"])
        self.assertTrue(all(case["audit_status"] == "passed" for case in acceptance["case_results"]))

    def test_extract_file_metadata_never_allows_raw_drawing_content_for_agent(self):
        metadata = self.repo.extract_file_metadata(
            files=[
                {"filename": "review-letter.pdf", "file_type": "document_file"},
                {"filename": "drawing-set.pdf", "file_type": "drawing_file"},
                {"filename": "notes.txt", "file_type": "other"},
            ]
        )

        self.assertEqual(
            metadata["agent_input_policy"],
            "metadata_only_no_raw_drawing_or_document_content",
        )
        self.assertTrue(metadata["human_review_required"])
        self.assertTrue(all(item["metadata_only"] for item in metadata["files"]))
        self.assertFalse(any(item["raw_content_allowed_for_agent"] for item in metadata["files"]))
        drawing = metadata["files"][1]
        self.assertTrue(drawing["requires_masking"])

    def test_parse_masked_document_and_normalize_atomic_items(self):
        parsed = self.repo.parse_masked_document(
            text=(
                "發文機關：新北市政府工務局\n"
                "發文日期：115年7月6日\n"
                "發文字號：REDACTED-001\n"
                "主旨：室內裝修圖說審核補正通知\n"
                "說明一：請補申請書、建築物權利證明文件。\n"
                "說明二：請補室內裝修圖說與專業人員簽章確認。\n"
            ),
            jurisdiction="ntpc",
        )
        normalized = self.repo.normalize_atomic_correction_items(parsed)

        self.assertEqual(parsed["agency"], "新北市政府工務局")
        self.assertEqual(parsed["document_no"], "REDACTED-001")
        self.assertEqual(parsed["procedure_stage_signal"]["procedure_stage"], "圖說審核")
        self.assertFalse(parsed["procedure_stage_signal"]["human_review_required"])
        self.assertGreaterEqual(normalized["item_count"], 4)
        self.assertTrue(all(item["source_span"] for item in normalized["atomic_correction_items"]))
        self.assertIn(
            "需人工認定",
            {item["adjudication"] for item in normalized["atomic_correction_items"]},
        )

    def test_build_sheet_manifest_and_hitl_confirmation_packet(self):
        manifest = self.repo.build_sheet_manifest(
            files=[
                {"filename": "A001_室內裝修圖說.pdf", "file_type": "drawing_file"},
                {"filename": "A002_材料表.pdf", "file_type": "drawing_file"},
                {"filename": "letter.masked.txt", "file_type": "masked_file"},
            ]
        )
        packet = self.repo.build_hitl_confirmation_packet(
            procedure_stage_signal={
                "procedure_stage": None,
                "confidence": 0.5,
                "human_review_required": True,
                "reason": "ambiguous_or_low_confidence",
            },
            atomic_items=[
                {
                    "item_id": "auto-001",
                    "source_span": "說明二：簽章確認",
                    "adjudication": "需人工認定",
                }
            ],
        )

        self.assertEqual(manifest["sheet_count"], 2)
        self.assertEqual(manifest["sheet_manifest"][1]["sheet_type"], "材料表")
        self.assertFalse(any(sheet["raw_content_allowed_for_agent"] for sheet in manifest["sheet_manifest"]))
        self.assertTrue(packet["human_review_required"])
        self.assertEqual(packet["question_count"], 2)
        self.assertEqual(packet["client_questions"][0]["question_key"], "confirm_procedure_stage")

    def test_apply_hitl_confirmations_finalizes_stage_and_manual_items(self):
        result = self.repo.apply_hitl_confirmations(
            procedure_stage_signal={
                "procedure_stage": None,
                "confidence": 0.5,
                "human_review_required": True,
                "reason": "ambiguous_or_low_confidence",
            },
            atomic_items=[
                {
                    "item_id": "auto-001",
                    "source_span": "說明二：簽章確認",
                    "adjudication": "需人工認定",
                }
            ],
            answers=[
                {
                    "question_key": "confirm_procedure_stage",
                    "selected_option": "圖說審核",
                },
                {
                    "question_key": "review_auto-001",
                    "answer_text": "專業人員已確認需補簽章責任文件。",
                },
            ],
        )

        self.assertEqual(result["confirmation_status"], "complete")
        self.assertFalse(result["human_review_required"])
        self.assertEqual(result["procedure_stage_signal"]["procedure_stage"], "圖說審核")
        self.assertEqual(result["procedure_stage_signal"]["confidence"], 1.0)
        self.assertTrue(result["procedure_stage_signal"]["confirmed_by_human"])
        self.assertEqual(result["atomic_correction_items"][0]["human_review_status"], "confirmed")
        self.assertEqual(result["atomic_correction_items"][0]["adjudication"], "人工確認完成")
        self.assertEqual(result["unanswered_questions"], [])
        self.assertEqual(result["unknown_answers"], [])
        self.assertEqual(result["invalid_answers"], [])

    def test_apply_hitl_confirmations_fails_closed_for_missing_or_unknown_answers(self):
        result = self.repo.apply_hitl_confirmations(
            procedure_stage_signal={
                "procedure_stage": None,
                "confidence": 0.5,
                "human_review_required": True,
                "reason": "ambiguous_or_low_confidence",
            },
            atomic_items=[
                {
                    "item_id": "auto-001",
                    "source_span": "說明二：簽章確認",
                    "adjudication": "需人工認定",
                }
            ],
            answers=[
                {
                    "question_key": "unknown_key",
                    "answer_text": "unexpected",
                }
            ],
        )

        self.assertEqual(result["confirmation_status"], "incomplete")
        self.assertTrue(result["human_review_required"])
        self.assertIn("confirm_procedure_stage", result["unanswered_questions"])
        self.assertIn("review_auto-001", result["unanswered_questions"])
        self.assertEqual(result["unknown_answers"], ["unknown_key"])
        self.assertTrue(result["procedure_stage_signal"]["human_review_required"])

    def test_run_audit_gates_passes_with_compliant_items(self):
        gate_meta = self.repo.run_audit_gates(
            correction_items=[
                {
                    "law_name": "建築物室內裝修管理辦法",
                    "article": "23",
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
                    "article": "23",
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
