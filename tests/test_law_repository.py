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


if __name__ == "__main__":
    unittest.main()
