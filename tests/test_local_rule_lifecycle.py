import copy
import unittest

from tw_law_mcp.local_rule_lifecycle import (
    augment_phase_acceptance,
    load_local_rule_records,
    run_local_rule_lifecycle_acceptance,
    select_local_rule_version,
    validate_local_rule_record,
)


class LocalRuleLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.records = load_local_rule_records()
        self.record = self.records[0]

    def test_ntpc_record_separates_legal_and_processing_dates(self):
        self.assertEqual(self.record["promulgated_at"], "2011-04-25")
        self.assertIsNone(self.record["effective_from"])
        self.assertIsNone(self.record["amended_at"])
        self.assertNotEqual(self.record["retrieved_at"][:10], self.record["promulgated_at"])
        self.assertEqual(validate_local_rule_record(self.record), [])

    def test_historical_selection_fails_closed_without_effective_from(self):
        result = select_local_rule_version(
            self.records,
            jurisdiction="ntpc",
            official_identifier="C0170020",
            as_of_date="2020-01-01",
        )
        self.assertFalse(result["exists"])
        self.assertTrue(result["human_review_required"])
        self.assertEqual(result["status"], "unknown_effective_from")

    def test_current_selection_resolves_single_active_record(self):
        result = select_local_rule_version(
            self.records,
            jurisdiction="ntpc",
            official_identifier="C0170020",
        )
        self.assertTrue(result["exists"])
        self.assertFalse(result["human_review_required"])
        self.assertEqual(result["status"], "current_active")

    def test_pending_reverification_blocks_current_selection(self):
        changed = copy.deepcopy(self.records)
        changed[0]["legal_status"] = "pending_reverification"
        result = select_local_rule_version(
            changed,
            jurisdiction="ntpc",
            official_identifier="C0170020",
        )
        self.assertFalse(result["exists"])
        self.assertEqual(result["status"], "pending_reverification")

    def test_abolished_record_is_not_selected_as_current(self):
        changed = copy.deepcopy(self.records)
        changed[0]["legal_status"] = "abolished"
        changed[0]["effective_from"] = "2011-04-25"
        changed[0]["effective_to"] = "2020-12-31"
        result = select_local_rule_version(
            changed,
            jurisdiction="ntpc",
            official_identifier="C0170020",
        )
        self.assertFalse(result["exists"])
        self.assertEqual(result["status"], "no_active_version")

    def test_overlapping_historical_versions_fail_closed(self):
        changed = copy.deepcopy(self.records)
        first = changed[0]
        first["effective_from"] = "2011-04-25"
        first["effective_to"] = "2020-12-31"
        first["legal_status"] = "superseded"
        second = copy.deepcopy(first)
        second["source_id"] = "ntpc-interior-review-rule-v2"
        second["legal_status"] = "active"
        second["effective_from"] = "2020-01-01"
        second["effective_to"] = None
        changed.append(second)
        result = select_local_rule_version(
            changed,
            jurisdiction="ntpc",
            official_identifier="C0170020",
            as_of_date="2020-06-01",
        )
        self.assertFalse(result["exists"])
        self.assertTrue(result["human_review_required"])
        self.assertEqual(result["status"], "overlapping_versions")

    def test_malformed_record_date_fails_closed_without_raising(self):
        changed = copy.deepcopy(self.records)
        changed[0]["effective_from"] = "not-a-date"
        result = select_local_rule_version(
            changed,
            jurisdiction="ntpc",
            official_identifier="C0170020",
            as_of_date="2020-06-01",
        )
        self.assertFalse(result["exists"])
        self.assertTrue(result["human_review_required"])
        self.assertEqual(result["status"], "invalid_record_date")
        self.assertTrue(any("effective_from" in item for item in result["candidates"]))

    def test_normalized_requirement_hash_is_enforced(self):
        changed = copy.deepcopy(self.record)
        changed["requirements"][0]["normalized_facts"]["building_transcript_max_age_months"] = 12
        failures = validate_local_rule_record(changed)
        self.assertTrue(any("normalized_content_sha256 mismatch" in item for item in failures))

    def test_invalid_normalized_requirement_blocks_current_selection(self):
        changed = copy.deepcopy(self.records)
        changed[0]["requirements"][0]["normalized_facts"][
            "building_transcript_max_age_months"
        ] = 12
        result = select_local_rule_version(
            changed,
            jurisdiction="ntpc",
            official_identifier="C0170020",
        )
        self.assertFalse(result["exists"])
        self.assertTrue(result["human_review_required"])
        self.assertEqual(result["status"], "invalid_lifecycle_record")
        self.assertEqual(result["candidates"], ["ntpc-interior-review-rule"])

    def test_acceptance_covers_ntpc_points_7_to_11(self):
        acceptance = run_local_rule_lifecycle_acceptance()
        self.assertTrue(acceptance["all_passed"])
        self.assertEqual(acceptance["failures"], [])
        self.assertEqual(acceptance["record_count"], 1)
        self.assertEqual(acceptance["normalized_requirement_count"], 5)

    def test_aggregate_helper_adds_lifecycle_gate(self):
        result = augment_phase_acceptance(
            {"all_passed": True, "gates": {"existing": True}, "details": {}}
        )
        self.assertTrue(result["all_passed"])
        self.assertTrue(result["gates"]["existing"])
        self.assertTrue(result["gates"]["local_rule_lifecycle"])
        self.assertIn("local_rule_lifecycle", result["details"])


if __name__ == "__main__":
    unittest.main()
