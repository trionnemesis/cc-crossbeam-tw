# tw-law-mcp Phase 1 Plan

## Recommendation

Build `tw-law-mcp` as the reusable domain boundary first. Keep Codex and Claude Code integration as thin MCP configuration wrappers. Do not duplicate legal corpus, citation, or gate logic in host-specific plugins.

## Phase 1.5 Recommendation

Do not port the original `cc-crossbeam` web upload path yet. Add a governed pipeline foundation first: official-source policy comparison, `procedure_stage` confidence scoring, G2 fixture manifest tracking, metadata extraction contracts, jurisdiction registry stubs, and packaging ADR. This keeps raw design drawings out of agent prompts while making the later web integration executable.

### Option A: Port the original web app now

- Faster visual demo.
- Reuses Next.js, Cloud Run, Vercel Sandbox, and Supabase patterns.
- Raises raw drawing/PDF exposure risk before masking and fixture contracts exist.

### Option B: Finish governed domain boundary first

- Slower visible demo.
- Produces deterministic, testable contracts for law sources, procedure routing, fixtures, metadata extraction, and packaging.
- Allows later frontend/orchestrator work to use masked artifacts instead of raw drawings.

**Recommendation: Option B** — The current repository has only the MCP boundary and fixture corpus. The next lowest-risk step is to finish the governed contracts that every later phase depends on.

## Phase 1 Scope

- Add a deterministic P0 fixture corpus for New Taipei interior renovation review.
- Implement repository APIs for law pack listing, law search, article lookup, citation verification, source policy lookup, and procedure requirement lookup.
- Implement a stdio JSON-RPC MCP server exposing those APIs as tools.
- Add Codex and Claude Code MCP configuration files.
- Add phase-aware versioned law snapshots (`law_snapshot`) for Taiwan formal flow.
- Add deterministic helpers for claim-support fail-closed filtering and illegal-construction reference detection.
- Export formal gate execution metadata (`run_meta.gates`) with per-gate status/interception/retry fields.
- Align governance check input with v0.3 `data_governance_state` contract.

## Phase 1.5 Scope

- Add `source_policy_comparisons` for official-source authorization and update-policy differences.
- Add `procedure_stage` confidence scoring and HITL routing metadata.
- Add a fixture manifest contract for G2 tracking without committing raw client drawings.
- Add document/drawing metadata extraction contracts.
- Add jurisdiction registry entries beyond New Taipei as disabled stubs.
- Add ADR for Codex plugin / Claude Code plugin / standalone MCP packaging.

## Verification

- `python3 -m unittest discover -s tests`
- Stdio smoke test through `python3 -m tw_law_mcp.server`

## Phase 1.5 Verification

- `python3 -m unittest discover -s tests`
- Source policy comparison returns rank/license/update/crawl distinctions for every P0 source.
- Low-confidence or ambiguous `procedure_stage` requires HITL.
- Fixture manifest reports G2 incomplete until `case_count >= 12` and `atomic_item_count >= 80`.
- Disabled jurisdiction stubs fail closed for active procedures.

## Phase 2 Scenario Matrix Scope

Add a Taiwan scenario feature matrix before porting frontend/backend work. The first implementation slice should be documentation plus a deterministic acceptance gate, not a full corpus ingestion pipeline.

### Option A: Port scenario tools directly

- Faster MCP surface growth.
- Risks adding behavior before scenario coverage, source packs, artifacts, and gates are traceable.

### Option B: Add matrix fixture and acceptance first

- Slower visible tool growth.
- Produces a stable contract for later tools: scenario category, corpus packs, tool boundary, artifact contract, gate, and fixture query.
- Keeps future `resolve_tw_scenario` and domain-specific checks tied to a repeatable acceptance report.

**Recommendation: Option B** — The pasted plan identifies the feature matrix as the next executable index. The smallest correct slice is to document the matrix, add scenario fixtures, and add a repeatable `run_scenario_matrix_acceptance` gate before expanding tool behavior.

### Phase 2.0 Scope

- Add `docs/tw-scenario-feature-matrix.md`.
- Add `fixtures/tw_scenario_queries.json`.
- Add `run_scenario_matrix_acceptance` with per-scenario corpus/tool/artifact/gate/fixture checks.
- Include the scenario matrix gate in `run_phase_acceptance`.

### Phase 2.0 Verification

- Scenario matrix test fails before implementation.
- Scenario matrix test passes after implementation.
- `python3 scripts/run_scenario_matrix_acceptance.py` reports `all_passed=true`.
- `python3 scripts/run_phase_acceptance.py` includes `scenario_matrix=true`.
- `python3 -m unittest discover -s tests` passes.

## Phase 2.1-2.6 Scope: Complete Uploaded Plan Through Step 6

The uploaded plan's six implementation steps are now treated as one L2 feature sequence, but each step must remain independently testable. This phase must not redefine completion around the existing matrix skeleton.

### Step 2: Split corpus data directory

- Create `tw_law_mcp/data/sources/` packs:
  - `tw-central-interior-core.json`
  - `tw-central-fire-equipment.json`
  - `tw-fire-compartment-and-egress.json`
  - `tw-material-evidence.json`
  - `ntpc-interior-procedure.json`
- Create `tw_law_mcp/data/registries/`:
  - `jurisdictions.json`
  - `procedure_stages.json`
  - `domain_tags.json`
- Create `tw_law_mcp/data/fixtures/`:
  - `tw_scenario_queries.json`
  - `ntpc_synthetic_cases.json`
- Keep legacy `p0_law_corpus.json` readable during migration.

### Step 3: Source adapter contracts

- Add deterministic local adapter outputs for MOJ, ABRI/CPAMI reference records, NTPC law portal, and NTPC e-service references.
- Normalize every record into `source_unit` with authority, license, crawl policy, checksum, jurisdiction, case type, procedure stage, and domain tags.
- No live web fetch is required in this phase; adapter output is source-bound metadata and fixture text only.

### Step 4: Scenario MCP tools

- Implement:
  - `resolve_tw_scenario`
  - `check_fire_equipment_routing`
  - `check_fire_compartment_evidence`
  - `check_material_evidence`
  - `build_ntpc_submission_packet`
  - `plan_web_search_fallback`
- Tools must fail closed for professional judgment, material authenticity, fire design, legal compliance, and corpus misses.

### Step 5: Evaluation hardening

- `run_scenario_matrix_acceptance` must verify actual corpus pack files, actual MCP tool handlers, artifact contracts, gates, source-unit coverage, and fixture query counts.
- MVP categories must each have at least 5 scenario queries.

### Step 6: Two-stage contractor flow

- Add deterministic two-stage flow skeleton:
  - Stage 1 analysis: masked document + metadata -> parsed document, atomic items, scenario routing, packet, gates, client questions.
  - Stage 2 response: analysis artifacts + human answers -> response draft, professional review packet, correction summary, gate metadata.
- The flow must not use California ADU prompts, compliance assurance language, or web search as authority.

### Phase 2.1-2.6 Verification

- RED tests fail before implementation for missing split data, missing scenario tools, weak matrix acceptance, and missing two-stage flow.
- Targeted tests pass after implementation.
- `python3 scripts/run_scenario_matrix_acceptance.py` reports `all_passed=true` and at least 5 queries per MVP category.
- `python3 scripts/run_phase_acceptance.py` includes scenario matrix and two-stage flow gates.
- `python3 -m unittest discover -s tests` passes.

## Deferred

- Full law corpus ingestion.
- Full Codex and Claude Code plugin packaging.
- Raw drawing upload and full web app integration.
- BC-7 illegal construction adjudication.
