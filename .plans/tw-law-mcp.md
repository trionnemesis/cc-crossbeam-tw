# tw-law-mcp Phase 1 Plan

## Recommendation

Build `tw-law-mcp` as the reusable domain boundary first. Keep Codex and Claude Code integration as thin MCP configuration wrappers. Do not duplicate legal corpus, citation, or gate logic in host-specific plugins.

## Phase 1 Scope

- Add a deterministic P0 fixture corpus for New Taipei interior renovation review.
- Implement repository APIs for law pack listing, law search, article lookup, citation verification, source policy lookup, and procedure requirement lookup.
- Implement a stdio JSON-RPC MCP server exposing those APIs as tools.
- Add Codex and Claude Code MCP configuration files.

## Verification

- `python3 -m unittest discover -s tests`
- Stdio smoke test through `python3 -m tw_law_mcp.server`

## Deferred

- Full law corpus ingestion.
- LLM-backed `check_claim_support`.
- Document extraction and illegal construction evidence detection.
- Codex and Claude Code plugin packaging.
