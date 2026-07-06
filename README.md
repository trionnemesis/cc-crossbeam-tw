# cc-crossbeam-tw

Taiwan/New Taipei interior renovation auditability MCP prototype.

This repository implements the first slice of `tw-law-mcp`: a deterministic, source-bound law snapshot interface for agent tools. It is not a legal compliance engine and must not be used to claim that a case is compliant, illegal, or guaranteed to pass review.

## Current Scope

- MVP jurisdiction: `{central: "TW", local: "ntpc"}`
- MVP case type: `室內裝修`
- Transport: stdio JSON-RPC MCP subset
- Corpus: minimal P0 fixture data for contract and host smoke testing

## Tools

- `list_law_packs`
- `search_law`
- `get_article`
- `verify_citation`
- `get_source_policy`
- `resolve_procedure_requirements`

Deferred: full corpus ingestion, `check_claim_support`, document extraction, illegal-construction evidence detection, and plugin packaging.

## Run

```bash
python3 scripts/tw_law_mcp_stdio.py
```

Codex project MCP config is in `.codex/config.toml`.

Claude Code project MCP config is in `.mcp.json`.

## Test

```bash
python3 -m unittest discover -s tests
```
