# TASK STATE: cc-crossbeam-tw full phase completion

## Objective

Complete the downstream roadmap:

- P0 corpus official source authorization and update-policy comparison.
- Formal `procedure_stage` confidence scoring and HITL confirmation loop.
- Fixture baseline: at least 12 de-identified cases and at least 80 atomic correction items (G2).
- Drawing/application metadata extraction.
- Jurisdiction registry beyond New Taipei.
- Packaging decision across Codex plugin, Claude Code plugin, and standalone MCP server.

## Lane

L2 feature with L5 long-task overlay.

## Current State

- Repository currently contains a deterministic `tw-law-mcp` prototype.
- `p0_law_corpus.json` has a small P0 fixture corpus, not a verified official corpus.
- `data_governance_state` gate exists, but there is no raw/masked intake pipeline.
- No real de-identified fixture set exists in the repository.
- No frontend/backend app has been ported into this repository.

## Working Strategy

1. Finish Phase 1.5 foundation before agent or web-app porting.
2. Keep raw drawings out of Codex/agent prompts.
3. Add contracts and deterministic checks before adding host-specific packaging.
4. Treat G2 as incomplete until 12 de-identified cases and 80 atomic items are actually present and verifiable.
5. For the Taiwan scenario matrix slice, add documentation and a repeatable acceptance gate before adding broader tool behavior.

## Progress

- [x] Audit current repo against requested end state.
- [x] Decide next executable slice: Phase 1.5 governed pipeline foundation.
- [x] Add source policy comparison data and repository accessors.
- [x] Add procedure stage confidence resolver and HITL routing metadata.
- [x] Add fixture manifest contract for G2 tracking.
- [x] Add synthetic de-identified G2 baseline: 12 cases and 84 atomic correction items.
- [x] Add metadata extraction contract for documents/drawings.
- [x] Add jurisdiction registry stubs beyond New Taipei.
- [x] Add packaging strategy ADR.
- [x] Run tests and record evidence: `python3 -m unittest discover -s tests` passed, 18 tests.
- [x] Add deterministic masked-document parser, atomic normalizer, sheet manifest builder, and HITL confirmation packet builders.
- [x] Expose Phase 2 artifact builders as MCP tools.
- [x] Add repeatable G2 fixture mini-pipeline acceptance across snapshot, sheet manifest, HITL packet, and audit gates.
- [x] Add fail-closed HITL confirmation application for procedure-stage and manual-review correction questions.
- [x] Add repeatable P0 source-policy acceptance for official-source evidence and comparison coverage.
- [x] Add repeatable jurisdiction registry acceptance for enabled coverage and disabled fail-closed stubs.
- [x] Add repeatable packaging acceptance for standalone MCP strategy and thin Codex/Claude wrappers.
- [x] Add aggregate Phase acceptance gate covering all explicit roadmap requirements.
- [ ] Add Taiwan scenario feature matrix documentation.
- [ ] Add scenario matrix fixture and acceptance gate.
- [ ] Expose scenario matrix acceptance through script, aggregate phase gate, and MCP tool list.

## Current Evidence

- `compare_source_policies` exposes rank/license/update/crawl differences for P0 source classes.
- `run_source_policy_acceptance` verifies all P0 article sources have policy evidence and all official source classes are covered by comparisons.
- P0 corpus source URL correction: `建築物室內裝修管理辦法` now uses MOJ `D0070148` and article 23 for application drawing documents.
- `resolve_procedure_stage_confidence` returns confidence and routes ambiguous/low-confidence input to HITL.
- `get_fixture_baseline_status` reports G2 complete for the synthetic de-identified baseline: 12 cases and 84 atomic items.
- `extract_file_metadata` returns metadata-only agent policy and never allows raw drawing/document content.
- `list_jurisdictions` exposes New Taipei as enabled and Taipei/Taoyuan as disabled fail-closed stubs.
- `run_jurisdiction_registry_acceptance` verifies the enabled New Taipei registry has law packs/stages and non-New-Taipei entries fail closed.
- `run_packaging_acceptance` verifies `.codex/config.toml`, `.mcp.json`, the stdio entrypoint, and ADR-0001 preserve standalone MCP-first packaging.
- `run_phase_acceptance` aggregates P0 source policy, procedure/HITL, G2 fixture, metadata extraction, jurisdiction registry, and packaging strategy gates.
- `parse_masked_document`, `normalize_atomic_correction_items`, `build_sheet_manifest`, and `build_hitl_confirmation_packet` create Phase 2 contract artifacts from masked text and metadata only.
- `apply_hitl_confirmations` applies answered `client_questions` back into `procedure_stage_signal` and atomic correction items, while unknown/missing/invalid answers remain incomplete and require human review.
- `run_fixture_pipeline_acceptance` reports all 12 synthetic cases and 84 atomic correction items pass deterministic snapshot, sheet manifest, HITL packet, and audit-gate acceptance.
- Latest verification: `python3 -m unittest discover -s tests` passed, 27 tests.
- Latest aggregate Phase acceptance smoke: `python3 scripts/run_phase_acceptance.py` passed with all six gates true.
- Latest source policy acceptance smoke: `python3 scripts/run_source_policy_acceptance.py` passed with `all_passed=true`, 3 article sources, and 2 source classes.
- Latest jurisdiction registry acceptance smoke: `python3 scripts/run_jurisdiction_registry_acceptance.py` passed with `all_passed=true`, 1 enabled jurisdiction, and 2 disabled jurisdictions.
- Latest packaging acceptance smoke: `python3 scripts/run_packaging_acceptance.py` passed with `all_passed=true` and `decision=standalone_mcp_server_first`.
- Latest fixture pipeline smoke: `python3 scripts/run_fixture_pipeline.py` passed with `all_cases_passed=true`, 12 cases, and 84 atomic items.
- Current branch for scenario matrix work: `codex/tw-scenario-matrix`.

## Blockers / External Inputs

- Production G2 still requires replacing or supplementing synthetic cases with approved real de-identified New Taipei cases.
- Official source licensing comparison may require live source review before final production claims.
