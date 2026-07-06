# ADR-0001: tw-law-mcp packaging strategy

## Status

Accepted for Phase 1.5.

## Context

The roadmap requires evaluating Codex plugin, Claude Code plugin, and standalone MCP server packaging. The project currently exposes `tw-law-mcp` as a stdio JSON-RPC MCP subset with deterministic law lookup, source policy, audit gates, procedure routing, fixture tracking, and metadata-only file contracts.

Raw design drawings and application documents may contain personal data, project addresses, title blocks, and proprietary layout information. Packaging must preserve the governed boundary: host-specific wrappers may call the MCP tools, but legal corpus, citation verification, gate logic, procedure confidence, and metadata-only intake rules must stay in one shared implementation.

## Options

### Option A: Codex plugin first

- Native for Codex users.
- Can bundle skills and MCP configuration.
- Risk: host-specific behavior may drift from Claude Code and standalone deployments.
- Risk: encourages treating Codex as the primary runtime before raw/masked data boundaries are proven.

### Option B: Claude Code plugin first

- Closest to the original `cc-crossbeam` implementation lineage.
- Can map naturally to Claude Code skills and sandbox orchestration.
- Risk: makes Taiwan domain logic look Claude-specific, even though the law boundary should be host-neutral.

### Option C: Standalone MCP server first

- Keeps corpus, source policy, citation, gates, procedure confidence, fixture baseline, and metadata extraction in one deterministic boundary.
- Codex and Claude Code integrations stay thin wrappers.
- Easier to smoke test through stdio without raw drawing upload.
- Later web app integration can call the same MCP boundary from Cloud Run or sandbox orchestration.

## Decision

Use **Option C: standalone MCP server first**.

Codex plugin and Claude Code plugin packaging are deferred until the standalone MCP contract is stable. Host-specific packages may include configuration, skills, and UX affordances, but must not duplicate domain logic.

## Consequences

- `tw-law-mcp` remains the source of truth for law and auditability behavior.
- Codex and Claude Code wrappers must call the same tools and receive the same fail-closed results.
- Web upload, raw drawing handling, OCR, and sandbox lifecycle remain deferred until metadata-only and raw/masked contracts are implemented and tested.
- Any future plugin package must preserve the rule that raw drawing/document content is not passed to an agent prompt unless a separate approved governance policy explicitly allows it.

## Acceptance

- `python3 -m unittest discover -s tests` passes.
- MCP tool list includes the governed Phase 1.5 tools.
- `get_fixture_baseline_status` remains incomplete until the real G2 fixture targets are satisfied.
- Plugin work cannot be marked complete by adding host configuration alone; it must preserve the standalone MCP behavior.

