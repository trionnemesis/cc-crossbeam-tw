from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

from .repository import load_default_repository


JSON = dict[str, Any]


TOOL_SCHEMAS: list[JSON] = [
    {
        "name": "list_law_packs",
        "description": "List enabled Taiwan/New Taipei law packs for a jurisdiction, case type, and procedure stage.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jurisdiction": {"type": "object"},
                "case_type": {"type": "string"},
                "procedure_stage": {"type": "string"},
            },
            "required": ["jurisdiction", "case_type", "procedure_stage"],
        },
    },
    {
        "name": "build_law_snapshot",
        "description": "Build a versioned law snapshot for a run context and return source-bound entries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jurisdiction": {"type": "object"},
                "case_type": {"type": "string"},
                "procedure_stage": {"type": "string"},
                "as_of_date": {"type": "string"},
                "as_of_date_basis": {"type": "string"},
                "user_supplied_date": {"type": "string"},
            },
            "required": ["jurisdiction", "case_type", "procedure_stage", "as_of_date"],
        },
    },
    {
        "name": "search_law",
        "description": "Search the deterministic P0 law snapshot. Results include rank, license, source URL, and checksum.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "hierarchy": {"type": "string"},
                "authority": {"type": "string"},
                "as_of_date": {"type": "string"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_article",
        "description": "Get one article from the P0 law snapshot by law_id and article number.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "law_id": {"type": "string"},
                "article_no": {"type": "string"},
                "as_of_date": {"type": "string"},
            },
            "required": ["law_id", "article_no"],
        },
    },
    {
        "name": "verify_citation",
        "description": "Verify whether a citation exists in the P0 snapshot. This is deterministic citation existence, not legal assurance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "law_name": {"type": "string"},
                "article_no": {"type": "string"},
                "effective_date": {"type": "string"},
            },
            "required": ["law_name", "article_no"],
        },
    },
    {
        "name": "check_claim_support",
        "description": "Check whether a claim is sufficiently supported by article text for fail-closed filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "article_text": {"type": "string"},
                "claim": {"type": "string"},
                "context": {"type": "string"},
            },
            "required": ["article_text", "claim"],
        },
    },
    {
        "name": "get_local_rule",
        "description": "Get structured local-law metadata (jurisdiction + rule name + documents + policy).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jurisdiction": {"type": "string"},
                "rule_name": {"type": "string"},
                "as_of_date": {"type": "string"},
            },
            "required": ["jurisdiction", "rule_name"],
        },
    },
    {
        "name": "detect_illegal_construction_reference",
        "description": "Detect whether files or text only imply illegal-construction indicators for manual routing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "text": {"type": "string"},
            },
            "required": ["files"],
        },
    },
    {
        "name": "get_source_policy",
        "description": "Return authority rank, license status, update policy, and crawl policy for a source URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"source_url": {"type": "string"}},
            "required": ["source_url"],
        },
    },
    {
        "name": "compare_source_policies",
        "description": "Return official-source authorization and update-policy differences for P0 sources.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_source_policy_acceptance",
        "description": "Verify P0 article sources have complete official-source policy evidence and comparison coverage.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "list_jurisdictions",
        "description": "List enabled jurisdiction registry entries, optionally including disabled stubs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_disabled": {"type": "boolean"},
            },
        },
    },
    {
        "name": "run_jurisdiction_registry_acceptance",
        "description": "Verify jurisdiction registry entries are enabled or fail-closed with law-pack coverage.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_packaging_acceptance",
        "description": "Verify Codex and Claude Code wrappers preserve standalone MCP server packaging strategy.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_phase_acceptance",
        "description": "Run aggregate acceptance for all roadmap Phase gates.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "resolve_procedure_requirements",
        "description": "Return stage-specific New Taipei interior renovation procedure requirements.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "stage": {"type": "string"},
                "jurisdiction": {"type": "string"},
            },
            "required": ["stage", "jurisdiction"],
        },
    },
    {
        "name": "resolve_procedure_stage_confidence",
        "description": "Score procedure_stage confidence from document text and file metadata; low confidence routes to HITL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "jurisdiction": {"type": "string"},
            },
        },
    },
    {
        "name": "get_fixture_baseline_status",
        "description": "Report whether the de-identified fixture baseline satisfies G2.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_fixture_pipeline_acceptance",
        "description": "Run the synthetic G2 fixture baseline through snapshot, sheet, HITL, and audit-gate acceptance.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "extract_file_metadata",
        "description": "Extract metadata-only file contract fields without allowing raw drawing/document content into agent input.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
            "required": ["files"],
        },
    },
    {
        "name": "parse_masked_document",
        "description": "Parse masked Taiwan official-document text into document_parsed fields and procedure-stage signal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "jurisdiction": {"type": "string"},
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "normalize_atomic_correction_items",
        "description": "Normalize parsed document sections into atomic correction items with source spans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_parsed": {"type": "object"},
                "law_name": {"type": "string"},
                "article": {"type": "string"},
            },
            "required": ["document_parsed"],
        },
    },
    {
        "name": "build_sheet_manifest",
        "description": "Build sheet_manifest metadata from drawing/source snapshot filenames without reading raw pixels.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
            "required": ["files"],
        },
    },
    {
        "name": "build_hitl_confirmation_packet",
        "description": "Build client_questions for low-confidence procedure stage and manual-review correction items.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "procedure_stage_signal": {"type": "object"},
                "atomic_items": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
            "required": ["procedure_stage_signal", "atomic_items"],
        },
    },
    {
        "name": "apply_hitl_confirmations",
        "description": "Apply human answers to procedure-stage and correction-item HITL questions with fail-closed validation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "procedure_stage_signal": {"type": "object"},
                "atomic_items": {
                    "type": "array",
                    "items": {"type": "object"},
                },
                "answers": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
            "required": ["procedure_stage_signal", "atomic_items", "answers"],
        },
    },
    {
        "name": "run_audit_gates",
        "description": "Run deterministic audit gates (schema/citation/source/claim/redline/governance).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "correction_items": {
                    "type": "array",
                    "items": {"type": "object"},
                },
                "data_governance_state": {"type": "object"},
            },
            "required": ["correction_items"],
        },
    },
]


class TwLawMcpServer:
    def __init__(self):
        self.repo = load_default_repository()
        self.handlers: dict[str, Callable[..., Any]] = {
            "list_law_packs": self.repo.list_law_packs,
            "build_law_snapshot": self.repo.build_law_snapshot,
            "search_law": self.repo.search_law,
            "get_article": self.repo.get_article,
            "verify_citation": self.repo.verify_citation,
            "check_claim_support": self.repo.check_claim_support,
            "get_local_rule": self.repo.get_local_rule,
            "detect_illegal_construction_reference": self.repo.detect_illegal_construction_reference,
            "get_source_policy": self.repo.get_source_policy,
            "compare_source_policies": self.repo.compare_source_policies,
            "run_source_policy_acceptance": self.repo.run_source_policy_acceptance,
            "list_jurisdictions": self.repo.list_jurisdictions,
            "run_jurisdiction_registry_acceptance": self.repo.run_jurisdiction_registry_acceptance,
            "run_packaging_acceptance": self.repo.run_packaging_acceptance,
            "run_phase_acceptance": self.repo.run_phase_acceptance,
            "resolve_procedure_requirements": self.repo.resolve_procedure_requirements,
            "resolve_procedure_stage_confidence": self.repo.resolve_procedure_stage_confidence,
            "get_fixture_baseline_status": self.repo.get_fixture_baseline_status,
            "run_fixture_pipeline_acceptance": self.repo.run_fixture_pipeline_acceptance,
            "extract_file_metadata": self.repo.extract_file_metadata,
            "parse_masked_document": self.repo.parse_masked_document,
            "normalize_atomic_correction_items": self.repo.normalize_atomic_correction_items,
            "build_sheet_manifest": self.repo.build_sheet_manifest,
            "build_hitl_confirmation_packet": self.repo.build_hitl_confirmation_packet,
            "apply_hitl_confirmations": self.repo.apply_hitl_confirmations,
            "run_audit_gates": self.repo.run_audit_gates,
        }

    def handle(self, request: JSON) -> JSON | None:
        method = request.get("method")
        request_id = request.get("id")
        if request_id is None:
            return None
        try:
            if method == "initialize":
                return self._result(request_id, self._initialize())
            if method == "tools/list":
                return self._result(request_id, {"tools": TOOL_SCHEMAS})
            if method == "tools/call":
                return self._result(request_id, self._call_tool(request.get("params", {})))
            return self._error(request_id, -32601, f"unknown method: {method}")
        except Exception as exc:
            return self._error(request_id, -32603, str(exc))

    def _initialize(self) -> JSON:
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": "tw-law-mcp",
                "version": "0.3.0",
            },
            "instructions": (
                "Use these tools for Taiwan/New Taipei interior renovation auditability tasks. "
                "They verify source-bound citation and procedure metadata only; do not treat "
                "results as legal assurance or professional certification."
            ),
        }

    def _call_tool(self, params: JSON) -> JSON:
        name = params.get("name")
        arguments = params.get("arguments", {})
        handler = self.handlers.get(name)
        if handler is None:
            raise ValueError(f"unknown tool: {name}")
        result = handler(**arguments)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, ensure_ascii=False, sort_keys=True),
                }
            ],
            "isError": False,
        }

    def _result(self, request_id: Any, result: JSON) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _error(self, request_id: Any, code: int, message: str) -> JSON:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def main() -> None:
    server = TwLawMcpServer()
    for line in sys.stdin:
        if not line.strip():
            continue
        response = server.handle(json.loads(line))
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
