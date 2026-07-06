from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DATA_PATH = Path(__file__).with_name("data") / "p0_law_corpus.json"
REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_BASELINE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "g2_baseline.json"
SCENARIO_QUERIES_PATH = REPO_ROOT / "fixtures" / "tw_scenario_queries.json"
CODEX_MCP_CONFIG_PATH = REPO_ROOT / ".codex" / "config.toml"
CLAUDE_MCP_CONFIG_PATH = REPO_ROOT / ".mcp.json"
PACKAGING_ADR_PATH = REPO_ROOT / "docs" / "ADR-0001-packaging-strategy.md"


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_terms(query: str) -> list[str]:
    normalized = query.replace("/", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return [term.lower() for term in normalized.split() if term]


def _first_marker_value(line: str, markers: tuple[str, ...]) -> str | None:
    for marker in markers:
        if marker in line:
            return line.split(marker, 1)[1].strip(" ：:")
    return None


@dataclass(frozen=True)
class LawRepository:
    data: dict[str, Any]

    def list_law_packs(
        self,
        jurisdiction: dict[str, str],
        case_type: str,
        procedure_stage: str,
    ) -> list[dict[str, Any]]:
        packs = []
        for pack in self.data["law_packs"]:
            if pack["jurisdiction"] != jurisdiction:
                continue
            if pack["case_type"] != case_type:
                continue
            if procedure_stage not in pack["procedure_stages"]:
                continue
            packs.append(dict(pack))
        return packs

    def build_law_snapshot(
        self,
        jurisdiction: dict[str, str],
        case_type: str,
        procedure_stage: str,
        as_of_date: str,
        as_of_date_basis: str = "run_date",
        user_supplied_date: str | None = None,
    ) -> dict[str, Any]:
        selected_packs = self.list_law_packs(
            jurisdiction=jurisdiction,
            case_type=case_type,
            procedure_stage=procedure_stage,
        )
        law_snapshot_id = self._snapshot_id(
            jurisdiction=jurisdiction,
            case_type=case_type,
            procedure_stage=procedure_stage,
            as_of_date=as_of_date,
        )
        entries = []
        for article in self._pack_articles(selected_packs):
            policy = self.get_source_policy(article["source_url"])
            entries.append(
                {
                    "law_id": article["law_id"],
                    "law_name": article["law_name"],
                    "article": article["article"],
                    "paragraph": article["paragraph"],
                    "item": article["item"],
                    "effective_date": article["effective_date"],
                    "amendment_date": article["amendment_date"],
                    "fetched_at": datetime.now(timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                    "source_url": article["source_url"],
                    "source_authority_rank": article["source_authority_rank"],
                    "source_license_status": article["source_license_status"],
                    "source_update_policy": policy["source_update_policy"],
                    "source_adapter_id": article.get("source_adapter_id", "tw-law-mcp"),
                    "checksum": _checksum(article["text"]),
                }
            )

        return {
            "law_snapshot_id": law_snapshot_id,
            "as_of_date": as_of_date,
            "as_of_date_basis": self._as_of_basis(as_of_date_basis, user_supplied_date),
            "entries": entries,
            "source_policy_state": [
                self.get_source_policy(entry["source_url"]) for entry in self._dedupe_by_url(entries)
            ],
        }

    def search_law(
        self,
        query: str,
        hierarchy: str | None = None,
        authority: str | None = None,
        as_of_date: str | None = None,
    ) -> list[dict[str, Any]]:
        terms = _normalize_terms(query)
        results = []
        for article in self.data["articles"]:
            if hierarchy and article["hierarchy"] != hierarchy:
                continue
            if authority and article["authority"] != authority:
                continue
            article_text = article["text"].lower()
            article_name = article["law_name"].lower()
            score = sum(
                article_text.count(term) + article_name.count(term)
                for term in terms
            )
            if score <= 0:
                continue
            results.append(self._public_article(article, score=score, as_of_date=as_of_date))
        return sorted(
            results,
            key=lambda item: (-item["score"], item["source_authority_rank"], item["law_name"]),
        )

    def get_article(
        self,
        law_id: str,
        article_no: str,
        as_of_date: str | None = None,
    ) -> dict[str, Any]:
        for article in self.data["articles"]:
            if article["law_id"] == law_id and article["article"] == article_no:
                return self._public_article(article, score=None, as_of_date=as_of_date)
        return {
            "exists": False,
            "law_id": law_id,
            "article": article_no,
            "as_of_date": as_of_date,
            "diff": "not_found",
        }

    def _public_article(
        self,
        article: dict[str, Any],
        score: int | None,
        as_of_date: str | None,
    ) -> dict[str, Any]:
        public = dict(article)
        public["checksum"] = _checksum(article["text"])
        public["as_of_date"] = as_of_date
        if score is not None:
            public["score"] = score
        return public

    def run_audit_gates(
        self,
        correction_items: list[dict[str, Any]],
        data_governance_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        gate_results = [
            self._gate_schema_valid(correction_items),
            self._gate_citation_exists(correction_items),
            self._gate_source_rank(correction_items),
            self._gate_source_license(correction_items),
            self._gate_claim_support(correction_items),
            self._gate_red_line(correction_items),
            self._gate_data_governance(data_governance_state),
        ]
        all_passed = all(gate["status"] == "passed" for gate in gate_results)
        downgraded_items = [item for gate in gate_results for item in gate.get("downgraded_items", [])]
        unique_downgraded = list(dict.fromkeys(downgraded_items))
        return {
            "run_meta": {
                "gates": [
                    {**gate, "index": index, "retry_count": 0, "intercepted": gate["status"] == "failed"}
                    for index, gate in enumerate(gate_results, start=1)
                ],
                "gate_results": gate_results,
                "all_passed": all_passed,
                "downgraded_items": unique_downgraded,
                "human_review_required": not all_passed,
                "status": "passed" if all_passed else "failed",
                "retry_count": 0,
            }
        }

    def verify_citation(
        self,
        law_name: str,
        article_no: str,
        effective_date: str | None = None,
    ) -> dict[str, Any]:
        for article in self.data["articles"]:
            if article["law_name"] == law_name and article["article"] == article_no:
                effective_matches = (
                    effective_date is None or effective_date == article["effective_date"]
                )
                return {
                    "exists": True,
                    "canonical_name": article["law_name"],
                    "version": {
                        "effective_date": article["effective_date"],
                        "amendment_date": article["amendment_date"],
                    },
                    "rank": article["source_authority_rank"],
                    "diff": "match" if effective_matches else "effective_date_mismatch",
                }
        return {
            "exists": False,
            "canonical_name": None,
            "version": None,
            "rank": None,
            "diff": "not_found",
        }

    def check_claim_support(
        self,
        article_text: str,
        claim: str,
        context: str | None = None,
    ) -> dict[str, Any]:
        normalized_claim = _normalize_terms(claim)
        if not normalized_claim:
            return {
                "supported": False,
                "confidence": 0.0,
                "rationale": "claim 為空，無法進行文字驗證。",
                "unsupported_reason": "claim is empty",
            }

        haystack = _normalize_terms(f"{article_text}\n{context or ''}")
        if not haystack:
            return {
                "supported": False,
                "confidence": 0.0,
                "rationale": "未提供可比對的條文文本。",
                "unsupported_reason": "missing article text",
            }

        haystack_set = set(haystack)
        matched = sorted({term for term in normalized_claim if term in haystack_set})
        confidence = min(0.99, len(matched) / len(normalized_claim))
        supported = confidence >= 0.6
        unsupported_reason = "" if supported else "claim 支持不足，需降級人工確認"
        return {
            "supported": supported,
            "confidence": round(confidence, 3),
            "rationale": (
                "條文關鍵詞匹配比率判定。"
                f" matched={len(matched)}/{len(normalized_claim)}."
            ),
            "unsupported_reason": unsupported_reason,
        }

    def get_local_rule(
        self,
        jurisdiction: str,
        rule_name: str,
        as_of_date: str | None = None,
    ) -> dict[str, Any]:
        normalized_jurisdiction = jurisdiction.lower()
        for rule in self.data.get("local_rules", []):
            if rule["jurisdiction"] != normalized_jurisdiction:
                continue
            if rule["rule_name"] != rule_name:
                continue
            return {
                "jurisdiction": normalized_jurisdiction,
                "exists": True,
                "as_of_date": as_of_date,
                "source_url": rule["source_url"],
                "law_id": rule["law_id"],
                "law_name": rule["rule_name"],
                "procedure_stages": rule["procedure_stages"],
                "required_documents": rule["required_documents"],
                "effective_date": rule["effective_date"],
                "amendment_date": rule["amendment_date"],
                "source_policy": self.get_source_policy(rule["source_url"]),
            }
        return {
            "jurisdiction": normalized_jurisdiction,
            "rule_name": rule_name,
            "as_of_date": as_of_date,
            "exists": False,
            "required_documents": [],
            "handling": "未在 registry 找到正式在地規則，需人工確認。",
        }

    def detect_illegal_construction_reference(
        self,
        files: list[str] | None,
        text: str | None = None,
    ) -> dict[str, Any]:
        files = files or []
        haystack = " ".join(files + ([text] if text else []))
        haystack_lower = haystack.lower()
        evidence_map = {
            "違建項目簽證表": ["違建項目簽證表", "違建項目簽證"],
            "違建相片": ["違建相片", "違建照片", "illeg"],
            "圖說斜線標示": ["斜線標示", "斜線", "違建範圍標示", "違建範圍"],
            "公文文字提及": ["違建", "違章建築", "違章"],
            "其他附件": ["附件", "附件清單", "違建相關附件", "附件資料"],
        }

        evidence_types = []
        source_span = None
        for name, markers in evidence_map.items():
            for marker in markers:
                idx = haystack_lower.find(marker)
                if idx >= 0:
                    evidence_types.append(name)
                    if source_span is None and text is not None:
                        source_span = text[max(0, idx - 30) : idx + len(marker) + 30]
                    break

        return {
            "present": len(evidence_types) > 0,
            "evidence_type": evidence_types,
            "source_span": source_span,
            "required_attachment_detected": any(
                item in evidence_types for item in {"違建項目簽證表", "違建相片", "其他附件"}
            ),
            "handling": "僅標記文件存在與需人工確認，不進行違建認定",
        }

    def get_source_policy(self, source_url: str) -> dict[str, Any]:
        for policy in self.data["source_policies"]:
            if policy["source_url"] == source_url:
                return dict(policy)
        return {
            "source_url": source_url,
            "source_authority_rank": 5,
            "source_license_status": "unknown",
            "source_update_policy": "unknown",
            "crawl_policy": "manual_review_required",
        }

    def compare_source_policies(self) -> list[dict[str, Any]]:
        comparisons = []
        for comparison in self.data.get("source_policy_comparisons", []):
            enriched = dict(comparison)
            enriched["source_policy_state"] = [
                self.get_source_policy(source_url) for source_url in comparison["sources"]
            ]
            comparisons.append(enriched)
        return comparisons

    def run_source_policy_acceptance(self) -> dict[str, Any]:
        article_source_urls = sorted({article["source_url"] for article in self.data["articles"]})
        policies = {policy["source_url"]: dict(policy) for policy in self.data["source_policies"]}
        comparisons = self.compare_source_policies()
        failures = []

        missing_policy_urls = [url for url in article_source_urls if url not in policies]
        if missing_policy_urls:
            failures.append(
                {
                    "gate": "all_article_sources_have_policy",
                    "reason": "missing_source_policy",
                    "details": missing_policy_urls,
                }
            )

        required_policy_fields = {
            "source_authority_rank",
            "source_license_status",
            "source_update_policy",
            "crawl_policy",
            "verified_law_name",
            "verified_at",
            "update_policy_evidence",
            "license_evidence",
        }
        incomplete_policies = []
        for source_url, policy in policies.items():
            missing = sorted(field for field in required_policy_fields if not policy.get(field))
            if missing:
                incomplete_policies.append({"source_url": source_url, "missing": missing})
        if incomplete_policies:
            failures.append(
                {
                    "gate": "source_policy_evidence_complete",
                    "reason": "missing_required_policy_evidence",
                    "details": incomplete_policies,
                }
            )

        covered_classes = set()
        for comparison in comparisons:
            fields = {difference.get("field") for difference in comparison.get("differences", [])}
            if not {"source_license_status", "source_update_policy"}.issubset(fields):
                failures.append(
                    {
                        "gate": "comparison_covers_required_differences",
                        "reason": "missing_license_or_update_policy_difference",
                        "details": {"comparison_id": comparison.get("comparison_id")},
                    }
                )
            for source_url in comparison.get("sources", []):
                policy = policies.get(source_url, self.get_source_policy(source_url))
                covered_classes.add(self._source_policy_class(source_url, policy))

        article_classes = {
            self._source_policy_class(source_url, policies[source_url])
            for source_url in article_source_urls
            if source_url in policies
        }
        missing_comparison_classes = sorted(article_classes - covered_classes)
        if missing_comparison_classes:
            failures.append(
                {
                    "gate": "official_source_classes_compared",
                    "reason": "source_class_not_covered_by_comparison",
                    "details": missing_comparison_classes,
                }
            )

        return {
            "article_source_count": len(article_source_urls),
            "source_policy_count": len(policies),
            "source_class_count": len(article_classes),
            "comparison_count": len(comparisons),
            "covered_source_classes": sorted(covered_classes),
            "all_passed": not failures,
            "failures": failures,
        }

    def list_jurisdictions(self, include_disabled: bool = False) -> list[dict[str, Any]]:
        jurisdictions = []
        for entry in self.data.get("jurisdiction_registry", []):
            if not include_disabled and not entry.get("enabled", False):
                continue
            jurisdictions.append(dict(entry))
        return jurisdictions

    def run_jurisdiction_registry_acceptance(self) -> dict[str, Any]:
        entries = self.data.get("jurisdiction_registry", [])
        law_pack_ids = {pack["law_pack_id"] for pack in self.data.get("law_packs", [])}
        failures = []
        enabled = [entry for entry in entries if entry.get("enabled")]
        disabled = [entry for entry in entries if not entry.get("enabled")]

        if not enabled:
            failures.append(
                {
                    "gate": "enabled_jurisdiction_present",
                    "reason": "no_enabled_jurisdiction",
                    "details": [],
                }
            )
        if not any(entry.get("jurisdiction", {}).get("local") != "ntpc" for entry in entries):
            failures.append(
                {
                    "gate": "non_ntpc_registry_entries_present",
                    "reason": "missing_non_ntpc_entries",
                    "details": [],
                }
            )

        enabled_failures = []
        for entry in enabled:
            missing_pack_ids = [
                pack_id for pack_id in entry.get("law_pack_ids", []) if pack_id not in law_pack_ids
            ]
            if missing_pack_ids or not entry.get("supported_procedure_stages"):
                enabled_failures.append(
                    {
                        "jurisdiction": entry.get("jurisdiction"),
                        "missing_pack_ids": missing_pack_ids,
                        "supported_procedure_stages": entry.get("supported_procedure_stages", []),
                    }
                )
        if enabled_failures:
            failures.append(
                {
                    "gate": "enabled_jurisdictions_have_law_packs_and_stages",
                    "reason": "enabled_registry_entry_incomplete",
                    "details": enabled_failures,
                }
            )

        disabled_failures = []
        for entry in disabled:
            if entry.get("law_pack_ids") or entry.get("supported_procedure_stages") or "fail closed" not in entry.get("handling", ""):
                disabled_failures.append(
                    {
                        "jurisdiction": entry.get("jurisdiction"),
                        "law_pack_ids": entry.get("law_pack_ids", []),
                        "supported_procedure_stages": entry.get("supported_procedure_stages", []),
                        "handling": entry.get("handling"),
                    }
                )
        if disabled_failures:
            failures.append(
                {
                    "gate": "disabled_jurisdictions_fail_closed",
                    "reason": "disabled_registry_entry_not_fail_closed",
                    "details": disabled_failures,
                }
            )

        return {
            "registry_count": len(entries),
            "enabled_count": len(enabled),
            "disabled_count": len(disabled),
            "non_ntpc_count": sum(
                1 for entry in entries if entry.get("jurisdiction", {}).get("local") != "ntpc"
            ),
            "all_passed": not failures,
            "failures": failures,
        }

    def run_packaging_acceptance(self) -> dict[str, Any]:
        failures = []
        codex_config = self._load_codex_mcp_config()
        claude_config = self._load_claude_mcp_config()
        adr_text = PACKAGING_ADR_PATH.read_text(encoding="utf-8") if PACKAGING_ADR_PATH.exists() else ""

        codex_server = codex_config.get("mcp_servers", {}).get("tw_law_mcp", {})
        codex_ok = (
            codex_server.get("command") == "python3"
            and codex_server.get("args") == ["scripts/tw_law_mcp_stdio.py"]
            and codex_server.get("enabled") is True
        )
        if not codex_ok:
            failures.append(
                {
                    "gate": "codex_mcp_config_points_to_standalone_server",
                    "reason": "codex_config_invalid",
                    "details": codex_server,
                }
            )

        claude_server = claude_config.get("mcpServers", {}).get("tw-law-mcp", {})
        claude_ok = (
            claude_server.get("command") == "python3"
            and claude_server.get("args") == ["${CLAUDE_PROJECT_DIR}/scripts/tw_law_mcp_stdio.py"]
        )
        if not claude_ok:
            failures.append(
                {
                    "gate": "claude_mcp_config_points_to_standalone_server",
                    "reason": "claude_config_invalid",
                    "details": claude_server,
                }
            )

        required_adr_markers = [
            "Accepted for Phase 1.5.",
            "Option C: standalone MCP server first",
            "Codex plugin and Claude Code plugin packaging are deferred",
            "must not duplicate domain logic",
        ]
        missing_markers = [marker for marker in required_adr_markers if marker not in adr_text]
        if missing_markers:
            failures.append(
                {
                    "gate": "packaging_adr_records_decision",
                    "reason": "missing_adr_markers",
                    "details": missing_markers,
                }
            )

        server_exists = (REPO_ROOT / "scripts" / "tw_law_mcp_stdio.py").exists()
        if not server_exists:
            failures.append(
                {
                    "gate": "standalone_mcp_entrypoint_exists",
                    "reason": "missing_stdio_entrypoint",
                    "details": "scripts/tw_law_mcp_stdio.py",
                }
            )

        return {
            "decision": "standalone_mcp_server_first",
            "codex_config_present": CODEX_MCP_CONFIG_PATH.exists(),
            "claude_config_present": CLAUDE_MCP_CONFIG_PATH.exists(),
            "adr_present": PACKAGING_ADR_PATH.exists(),
            "standalone_entrypoint_present": server_exists,
            "all_passed": not failures,
            "failures": failures,
        }

    def run_phase_acceptance(self) -> dict[str, Any]:
        source_policy = self.run_source_policy_acceptance()
        fixture_pipeline = self.run_fixture_pipeline_acceptance()
        jurisdiction_registry = self.run_jurisdiction_registry_acceptance()
        packaging = self.run_packaging_acceptance()
        scenario_matrix = self.run_scenario_matrix_acceptance()
        procedure_hitl = self._run_procedure_hitl_acceptance()
        metadata_extraction = self._run_metadata_extraction_acceptance()
        gates = {
            "p0_source_policy": source_policy["all_passed"],
            "procedure_stage_hitl": procedure_hitl["all_passed"],
            "g2_fixture_baseline": fixture_pipeline["all_cases_passed"],
            "metadata_extraction": metadata_extraction["all_passed"],
            "jurisdiction_registry": jurisdiction_registry["all_passed"],
            "packaging_strategy": packaging["all_passed"],
            "scenario_matrix": scenario_matrix["all_passed"],
        }
        return {
            "all_passed": all(gates.values()),
            "gates": gates,
            "details": {
                "p0_source_policy": source_policy,
                "procedure_stage_hitl": procedure_hitl,
                "g2_fixture_baseline": {
                    "fixture_set_id": fixture_pipeline["fixture_set_id"],
                    "case_count": fixture_pipeline["case_count"],
                    "atomic_item_count": fixture_pipeline["atomic_item_count"],
                    "all_cases_passed": fixture_pipeline["all_cases_passed"],
                    "failed_cases": fixture_pipeline["failed_cases"],
                    "gate_failures": fixture_pipeline["gate_failures"],
                },
                "metadata_extraction": metadata_extraction,
                "jurisdiction_registry": jurisdiction_registry,
                "packaging_strategy": packaging,
                "scenario_matrix": scenario_matrix,
            },
        }

    def run_scenario_matrix_acceptance(self) -> dict[str, Any]:
        matrix = self._load_scenario_queries()
        queries = matrix.get("queries", [])
        mvp_categories = matrix.get("mvp_categories", [])
        seen_categories = sorted(
            {query.get("category") for query in queries if query.get("category")}
        )
        missing_mvp_categories = sorted(set(mvp_categories) - set(seen_categories))
        failures = []
        scenario_results = []
        required_fields = {
            "scenario_id",
            "category",
            "query",
            "expected_corpus_packs",
            "expected_tool",
            "expected_artifact",
            "expected_gate",
            "expected_output_type",
            "human_review_required",
            "prohibited_outputs",
        }

        if not queries:
            failures.append(
                {
                    "gate": "scenario_fixture_exists",
                    "reason": "missing_queries",
                    "details": str(SCENARIO_QUERIES_PATH),
                }
            )

        for category in missing_mvp_categories:
            failures.append(
                {
                    "gate": "mvp_category_coverage",
                    "reason": "missing_mvp_category",
                    "details": category,
                }
            )

        for query in queries:
            scenario_id = query.get("scenario_id", "<missing>")
            scenario_failures = []
            missing_fields = sorted(
                field
                for field in required_fields
                if self._missing_scenario_value(query.get(field))
            )
            if missing_fields:
                scenario_failures.append(
                    {
                        "gate": "scenario_contract_fields",
                        "reason": "missing_fields",
                        "details": missing_fields,
                    }
                )

            corpus_packs = query.get("expected_corpus_packs")
            if not isinstance(corpus_packs, list) or not corpus_packs:
                scenario_failures.append(
                    {
                        "gate": "source_pack_contract",
                        "reason": "missing_expected_corpus_packs",
                        "details": corpus_packs,
                    }
                )

            prohibited_outputs = query.get("prohibited_outputs")
            if not isinstance(prohibited_outputs, list) or not prohibited_outputs:
                scenario_failures.append(
                    {
                        "gate": "prohibited_output_policy",
                        "reason": "missing_prohibited_outputs",
                        "details": prohibited_outputs,
                    }
                )

            if query.get("risk_requires_hitl") and query.get("human_review_required") is not True:
                scenario_failures.append(
                    {
                        "gate": "risk_hitl_policy",
                        "reason": "risk_without_hitl",
                        "details": query.get("category"),
                    }
                )

            if (
                query.get("category") == "web_fallback"
                and query.get("expected_output_type") != "web_search_fallback_plan"
            ):
                scenario_failures.append(
                    {
                        "gate": "fallback_policy",
                        "reason": "fallback_must_return_plan_only",
                        "details": query.get("expected_output_type"),
                    }
                )

            scenario_results.append(
                {
                    "scenario_id": scenario_id,
                    "category": query.get("category"),
                    "expected_tool": query.get("expected_tool"),
                    "expected_artifact": query.get("expected_artifact"),
                    "expected_gate": query.get("expected_gate"),
                    "expected_corpus_packs": query.get("expected_corpus_packs", []),
                    "human_review_required": query.get("human_review_required"),
                    "passed": not scenario_failures,
                    "failures": scenario_failures,
                }
            )
            failures.extend(
                {"scenario_id": scenario_id, **failure}
                for failure in scenario_failures
            )

        return {
            "matrix_id": matrix.get("matrix_id"),
            "all_passed": not failures,
            "query_count": len(queries),
            "mvp_categories": mvp_categories,
            "categories": seen_categories,
            "missing_mvp_categories": missing_mvp_categories,
            "scenario_results": scenario_results,
            "failures": failures,
        }

    def resolve_procedure_stage_confidence(
        self,
        text: str | None = None,
        files: list[str] | None = None,
        jurisdiction: str = "ntpc",
    ) -> dict[str, Any]:
        candidates = self.data.get("procedure_requirements", {})
        normalized_jurisdiction = jurisdiction.lower()
        haystack = " ".join((files or []) + ([text] if text else []))
        scores = []
        for key, requirement in candidates.items():
            key_jurisdiction, stage = key.split(":", 1)
            if key_jurisdiction != normalized_jurisdiction:
                continue
            markers = [stage] + requirement.get("required_documents", [])
            matched = [marker for marker in markers if marker and marker in haystack]
            if matched:
                scores.append(
                    {
                        "procedure_stage": stage,
                        "score": len(matched),
                        "matched_markers": matched,
                    }
                )

        scores = sorted(scores, key=lambda item: (-item["score"], item["procedure_stage"]))
        if not scores:
            return {
                "procedure_stage": None,
                "confidence": 0.0,
                "human_review_required": True,
                "reason": "no_stage_markers_detected",
                "candidates": [],
            }

        top = scores[0]
        second_score = scores[1]["score"] if len(scores) > 1 else 0
        confidence = 0.9 if top["score"] >= 2 and top["score"] > second_score else 0.5
        return {
            "procedure_stage": top["procedure_stage"],
            "confidence": confidence,
            "human_review_required": confidence < 0.8,
            "reason": "stage_markers_detected" if confidence >= 0.8 else "ambiguous_or_low_confidence",
            "candidates": scores,
        }

    def get_fixture_baseline_status(self) -> dict[str, Any]:
        baseline = self._load_fixture_baseline()
        cases = baseline.get("cases", [])
        valid_cases = []
        invalid_cases = []
        invalid_items = []
        raw_committed = []

        required_item_fields = {
            "item_id",
            "source_span",
            "text",
            "law_name",
            "article",
            "adjudication",
        }
        allowed_adjudications = {"符合要件跡象", "缺失待補", "需人工認定"}
        for case in cases:
            fixture_id = case.get("fixture_id", "<missing>")
            items = case.get("atomic_correction_items", [])
            case_valid = (
                case.get("deidentified") is True
                and case.get("raw_files_committed") is False
                and isinstance(items, list)
                and bool(items)
            )
            if case.get("raw_files_committed"):
                raw_committed.append(fixture_id)
            for item in items:
                missing = sorted(required_item_fields - set(item))
                bad_adjudication = item.get("adjudication") not in allowed_adjudications
                if missing or bad_adjudication:
                    invalid_items.append(
                        {
                            "fixture_id": fixture_id,
                            "item_id": item.get("item_id"),
                            "missing": missing,
                            "bad_adjudication": bad_adjudication,
                        }
                    )
            if case_valid:
                valid_cases.append(case)
            else:
                invalid_cases.append(fixture_id)

        atomic_item_count = sum(len(case.get("atomic_correction_items", [])) for case in valid_cases)
        target_case_count = int(baseline.get("target_case_count", 12))
        target_atomic_item_count = int(baseline.get("target_atomic_item_count", 80))
        complete = (
            len(valid_cases) >= target_case_count
            and atomic_item_count >= target_atomic_item_count
            and not raw_committed
            and not invalid_cases
            and not invalid_items
        )
        return {
            "fixture_set_id": baseline.get("fixture_set_id"),
            "case_count": len(valid_cases),
            "atomic_item_count": atomic_item_count,
            "target_case_count": target_case_count,
            "target_atomic_item_count": target_atomic_item_count,
            "raw_files_committed": raw_committed,
            "invalid_cases": invalid_cases,
            "invalid_items": invalid_items,
            "g2_complete": complete,
            "status": "complete" if complete else "incomplete",
        }

    def run_fixture_pipeline_acceptance(self) -> dict[str, Any]:
        baseline_status = self.get_fixture_baseline_status()
        baseline = self._load_fixture_baseline()
        cases = baseline.get("cases", [])
        case_results = []
        failed_cases = []
        gate_failures = []
        snapshot_count = 0
        sheet_manifest_count = 0
        hitl_question_count = 0
        atomic_item_count = 0

        for case in cases:
            fixture_id = case.get("fixture_id", "<missing>")
            jurisdiction = case.get("jurisdiction", {"central": "TW", "local": "ntpc"})
            case_type = case.get("case_type", "室內裝修")
            procedure_stage = case.get("procedure_stage")
            snapshot = self.build_law_snapshot(
                jurisdiction=jurisdiction,
                case_type=case_type,
                procedure_stage=procedure_stage,
                as_of_date=case.get("as_of_date", "2026-07-06"),
            )
            sheet_manifest = self.build_sheet_manifest(case.get("file_metadata", []))
            procedure_stage_signal = {
                "procedure_stage": procedure_stage,
                "confidence": 0.9,
                "human_review_required": False,
                "reason": "fixture_label",
            }
            correction_items = [
                self._acceptance_gate_item(item)
                for item in case.get("atomic_correction_items", [])
            ]
            hitl_packet = self.build_hitl_confirmation_packet(
                procedure_stage_signal=procedure_stage_signal,
                atomic_items=correction_items,
            )
            audit_result = self.run_audit_gates(
                correction_items=correction_items,
                data_governance_state=self._fixture_data_governance_state(
                    fixture_id=fixture_id,
                    baseline_id=baseline.get("fixture_set_id", "unknown"),
                ),
            )
            all_gates_passed = audit_result["run_meta"]["all_passed"]
            if not all_gates_passed:
                failed_cases.append(fixture_id)
                gate_failures.extend(
                    {
                        "fixture_id": fixture_id,
                        "gate": gate["gate"],
                        "reason": gate["reason"],
                    }
                    for gate in audit_result["run_meta"]["gate_results"]
                    if gate["status"] != "passed"
                )

            snapshot_count += int(bool(snapshot.get("entries")))
            sheet_manifest_count += sheet_manifest["sheet_count"]
            hitl_question_count += hitl_packet["question_count"]
            atomic_item_count += len(correction_items)
            case_results.append(
                {
                    "fixture_id": fixture_id,
                    "procedure_stage": procedure_stage,
                    "law_snapshot_id": snapshot["law_snapshot_id"],
                    "snapshot_entry_count": len(snapshot["entries"]),
                    "sheet_count": sheet_manifest["sheet_count"],
                    "atomic_item_count": len(correction_items),
                    "hitl_question_count": hitl_packet["question_count"],
                    "audit_status": audit_result["run_meta"]["status"],
                }
            )

        all_cases_passed = (
            baseline_status["g2_complete"]
            and len(case_results) == baseline_status["case_count"]
            and atomic_item_count == baseline_status["atomic_item_count"]
            and not failed_cases
        )
        return {
            "fixture_set_id": baseline.get("fixture_set_id"),
            "case_count": len(case_results),
            "atomic_item_count": atomic_item_count,
            "snapshot_count": snapshot_count,
            "sheet_manifest_count": sheet_manifest_count,
            "hitl_question_count": hitl_question_count,
            "baseline_status": baseline_status["status"],
            "all_cases_passed": all_cases_passed,
            "failed_cases": failed_cases,
            "gate_failures": gate_failures,
            "case_results": case_results,
        }

    def _load_fixture_baseline(self) -> dict[str, Any]:
        if FIXTURE_BASELINE_PATH.exists():
            with FIXTURE_BASELINE_PATH.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        return self.data.get(
            "fixture_baseline",
            {"target_case_count": 12, "target_atomic_item_count": 80, "cases": []},
        )

    def _load_scenario_queries(self) -> dict[str, Any]:
        if SCENARIO_QUERIES_PATH.exists():
            with SCENARIO_QUERIES_PATH.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        return {
            "matrix_id": "missing",
            "mvp_categories": [],
            "queries": [],
        }

    @staticmethod
    def _missing_scenario_value(value: Any) -> bool:
        return value is None or value == "" or value == []

    def _acceptance_gate_item(self, item: dict[str, Any]) -> dict[str, Any]:
        article_meta = self._find_article(item.get("law_name"), item.get("article"))
        gate_item = dict(item)
        gate_item["source_authority_rank"] = article_meta.get("source_authority_rank", 5)
        gate_item["source_license_status"] = article_meta.get(
            "source_license_status",
            "unknown",
        )
        gate_item["claim_supported"] = True
        gate_item["claim_support_confidence"] = 0.9
        return gate_item

    def _fixture_data_governance_state(self, fixture_id: str, baseline_id: str) -> dict[str, Any]:
        return {
            "consent_record_id": f"{baseline_id}:{fixture_id}",
            "collection_purpose": "g2_fixture_acceptance",
            "raw_file_retention_policy": "no_raw_files_committed",
            "masked_file_retention_policy": "masked_fixture_retained_for_tests",
            "raw_file_access_scope": "none",
            "pii_detection_status": "synthetic_deidentified",
            "pii_masking_status": "done",
            "deletion_request_supported": True,
            "audit_log_enabled": True,
            "vectorization_allowed": True,
        }

    def _find_article(self, law_name: str | None, article_no: str | None) -> dict[str, Any]:
        for article in self.data["articles"]:
            if article["law_name"] == law_name and article["article"] == article_no:
                return article
        return {}

    @staticmethod
    def _load_codex_mcp_config() -> dict[str, Any]:
        if not CODEX_MCP_CONFIG_PATH.exists():
            return {}
        with CODEX_MCP_CONFIG_PATH.open("rb") as handle:
            return tomllib.load(handle)

    @staticmethod
    def _load_claude_mcp_config() -> dict[str, Any]:
        if not CLAUDE_MCP_CONFIG_PATH.exists():
            return {}
        with CLAUDE_MCP_CONFIG_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _run_procedure_hitl_acceptance(self) -> dict[str, Any]:
        confident = self.resolve_procedure_stage_confidence(
            text="本案申請圖說審核，請補室內裝修圖說與簽章責任文件。",
            jurisdiction="ntpc",
        )
        ambiguous = self.resolve_procedure_stage_confidence(
            text="文件同時提到圖說審核與竣工查驗，需確認程序。",
            jurisdiction="ntpc",
        )
        packet = self.build_hitl_confirmation_packet(
            procedure_stage_signal=ambiguous,
            atomic_items=[
                {
                    "item_id": "phase-001",
                    "source_span": "說明二：簽章確認",
                    "adjudication": "需人工認定",
                }
            ],
        )
        confirmation = self.apply_hitl_confirmations(
            procedure_stage_signal=ambiguous,
            atomic_items=[
                {
                    "item_id": "phase-001",
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
                    "question_key": "review_phase-001",
                    "answer_text": "專業人員已確認需補簽章責任文件。",
                },
            ],
        )
        checks = {
            "confident_stage_does_not_require_hitl": confident["human_review_required"] is False,
            "ambiguous_stage_requires_hitl": ambiguous["human_review_required"] is True,
            "packet_contains_questions": packet["question_count"] >= 2,
            "confirmation_completes_loop": confirmation["confirmation_status"] == "complete",
        }
        return {
            "all_passed": all(checks.values()),
            "checks": checks,
            "confident_stage": confident,
            "ambiguous_stage": ambiguous,
            "question_count": packet["question_count"],
            "confirmation_status": confirmation["confirmation_status"],
        }

    def _run_metadata_extraction_acceptance(self) -> dict[str, Any]:
        metadata = self.extract_file_metadata(
            files=[
                {"filename": "application.masked.txt", "file_type": "masked_file"},
                {"filename": "A001_室內裝修圖說.pdf", "file_type": "drawing_file"},
                {"filename": "A002_材料表.pdf", "file_type": "drawing_file"},
            ]
        )
        manifest = self.build_sheet_manifest(
            files=[
                {"filename": "A001_室內裝修圖說.pdf", "file_type": "drawing_file"},
                {"filename": "A002_材料表.pdf", "file_type": "drawing_file"},
            ]
        )
        checks = {
            "metadata_only": all(item["metadata_only"] for item in metadata["files"]),
            "raw_content_never_allowed": not any(
                item["raw_content_allowed_for_agent"] for item in metadata["files"]
            ),
            "drawing_requires_masking": any(
                item["file_type"] == "drawing_file" and item["requires_masking"]
                for item in metadata["files"]
            ),
            "sheet_manifest_created": manifest["sheet_count"] == 2,
        }
        return {
            "all_passed": all(checks.values()),
            "checks": checks,
            "agent_input_policy": metadata["agent_input_policy"],
            "sheet_count": manifest["sheet_count"],
        }

    @staticmethod
    def _source_policy_class(source_url: str, policy: dict[str, Any]) -> str:
        host = urlparse(source_url).netloc.lower()
        signature = (
            policy.get("source_authority_rank"),
            policy.get("source_license_status"),
            policy.get("source_update_policy"),
            policy.get("crawl_policy"),
        )
        return f"{host}:{signature}"

    def parse_masked_document(
        self,
        text: str,
        jurisdiction: str = "ntpc",
        files: list[str] | None = None,
    ) -> dict[str, Any]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        parsed = {
            "agency": None,
            "document_date": None,
            "document_no": None,
            "subject": None,
            "sections": {
                "主旨": [],
                "說明": [],
                "辦法": [],
                "附件": [],
            },
            "source_spans": [],
            "pii_masking_status": "assumed_masked_input",
        }
        current_section = None
        for index, line in enumerate(lines, start=1):
            agency = _first_marker_value(line, ("發文機關：", "機關："))
            date = _first_marker_value(line, ("發文日期：", "日期："))
            doc_no = _first_marker_value(line, ("發文字號：", "字號："))
            subject = _first_marker_value(line, ("主旨：",))
            if agency:
                parsed["agency"] = agency
                continue
            if date:
                parsed["document_date"] = date
                continue
            if doc_no:
                parsed["document_no"] = doc_no
                continue
            if subject is not None:
                parsed["subject"] = subject
                current_section = "主旨"
                if subject:
                    parsed["sections"]["主旨"].append(subject)
                continue
            if line.startswith("說明"):
                current_section = "說明"
            elif line.startswith("辦法"):
                current_section = "辦法"
            elif line.startswith("附件"):
                current_section = "附件"

            if current_section in parsed["sections"]:
                parsed["sections"][current_section].append(line)
                parsed["source_spans"].append(
                    {
                        "line": index,
                        "section": current_section,
                        "text": line,
                    }
                )

        stage_signal = self.resolve_procedure_stage_confidence(
            text=text,
            files=files,
            jurisdiction=jurisdiction,
        )
        parsed["procedure_stage_signal"] = stage_signal
        parsed["human_review_required"] = stage_signal["human_review_required"]
        return parsed

    def normalize_atomic_correction_items(
        self,
        document_parsed: dict[str, Any],
        law_name: str = "建築物室內裝修管理辦法",
        article: str = "23",
    ) -> dict[str, Any]:
        correction_lines = []
        for section in ("說明", "辦法", "附件"):
            correction_lines.extend(document_parsed.get("sections", {}).get(section, []))
        if not correction_lines and document_parsed.get("subject"):
            correction_lines.append(document_parsed["subject"])

        items = []
        for index, line in enumerate(correction_lines, start=1):
            parts = [
                part.strip(" ；;。")
                for part in line.replace("、", "；").replace("，", "；").replace("與", "；").split("；")
                if part.strip(" ；;。")
            ]
            for part in parts:
                if not self._looks_like_correction(part):
                    continue
                item_index = len(items) + 1
                items.append(
                    {
                        "item_id": f"auto-{item_index:03d}",
                        "source_span": line,
                        "text": part,
                        "law_name": law_name,
                        "article": article,
                        "source_authority_rank": 2,
                        "source_license_status": "open_data_reusable",
                        "claim_supported": False,
                        "claim_support_confidence": 0.0,
                        "adjudication": "需人工認定" if "確認" in part or "簽章" in part else "缺失待補",
                    }
                )

        return {
            "atomic_correction_items": items,
            "item_count": len(items),
            "human_review_required": bool(items),
        }

    def build_sheet_manifest(self, files: list[dict[str, Any]]) -> dict[str, Any]:
        metadata = self.extract_file_metadata(files)["files"]
        sheets = []
        for index, item in enumerate(metadata, start=1):
            filename = item["filename"]
            stem = Path(filename).stem
            sheet_type = self._infer_sheet_type(filename)
            if item["file_type"] not in {"drawing_file", "source_snapshot"}:
                continue
            sheets.append(
                {
                    "sheet_id": f"S{index:03d}",
                    "filename": filename,
                    "sheet_no": stem,
                    "sheet_type": sheet_type,
                    "metadata_only": True,
                    "raw_content_allowed_for_agent": False,
                }
            )
        return {
            "sheet_manifest": sheets,
            "sheet_count": len(sheets),
            "agent_input_policy": "sheet_metadata_only_no_raw_pixels",
        }

    def build_hitl_confirmation_packet(
        self,
        procedure_stage_signal: dict[str, Any],
        atomic_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        questions = []
        if procedure_stage_signal.get("human_review_required"):
            questions.append(
                {
                    "question_key": "confirm_procedure_stage",
                    "question_type": "single_choice",
                    "prompt": "請確認本案程序階段。",
                    "options": [
                        "圖說審核",
                        "竣工查驗",
                        "變更使用併室內裝修竣工查驗",
                        "簡易室內裝修",
                    ],
                    "reason": procedure_stage_signal.get("reason"),
                }
            )
        for item in atomic_items:
            if item.get("adjudication") == "需人工認定":
                questions.append(
                    {
                        "question_key": f"review_{item['item_id']}",
                        "question_type": "free_text",
                        "prompt": "請專業人員確認此補正項處理方式。",
                        "source_span": item.get("source_span"),
                    }
                )
        return {
            "client_questions": questions,
            "question_count": len(questions),
            "human_review_required": bool(questions),
        }

    def apply_hitl_confirmations(
        self,
        procedure_stage_signal: dict[str, Any],
        atomic_items: list[dict[str, Any]],
        answers: list[dict[str, Any]],
    ) -> dict[str, Any]:
        packet = self.build_hitl_confirmation_packet(
            procedure_stage_signal=procedure_stage_signal,
            atomic_items=atomic_items,
        )
        questions = {question["question_key"]: question for question in packet["client_questions"]}
        answer_map = {
            str(answer.get("question_key")): answer
            for answer in answers
            if answer.get("question_key") is not None
        }
        unknown_answers = sorted(key for key in answer_map if key not in questions)
        unanswered_questions = sorted(key for key in questions if key not in answer_map)
        invalid_answers = []

        finalized_stage = dict(procedure_stage_signal)
        if "confirm_procedure_stage" in questions and "confirm_procedure_stage" in answer_map:
            answer_value = self._answer_value(answer_map["confirm_procedure_stage"])
            options = questions["confirm_procedure_stage"].get("options", [])
            if answer_value in options:
                finalized_stage.update(
                    {
                        "procedure_stage": answer_value,
                        "confidence": 1.0,
                        "human_review_required": False,
                        "reason": "human_confirmed",
                        "confirmed_by_human": True,
                    }
                )
            else:
                invalid_answers.append(
                    {
                        "question_key": "confirm_procedure_stage",
                        "reason": "answer_not_in_options",
                        "answer": answer_value,
                    }
                )

        finalized_items = []
        for item in atomic_items:
            finalized = dict(item)
            question_key = f"review_{item.get('item_id')}"
            if question_key in questions and question_key in answer_map:
                answer_value = self._answer_value(answer_map[question_key])
                if answer_value:
                    finalized["human_review_answer"] = answer_value
                    finalized["human_review_status"] = "confirmed"
                    finalized["adjudication"] = "人工確認完成"
                else:
                    invalid_answers.append(
                        {
                            "question_key": question_key,
                            "reason": "empty_answer",
                            "answer": answer_value,
                        }
                    )
            finalized_items.append(finalized)

        human_review_required = bool(unanswered_questions or unknown_answers or invalid_answers)
        if human_review_required and questions.get("confirm_procedure_stage"):
            finalized_stage["human_review_required"] = True
        return {
            "procedure_stage_signal": finalized_stage,
            "atomic_correction_items": finalized_items,
            "confirmation_status": "complete" if not human_review_required else "incomplete",
            "human_review_required": human_review_required,
            "unanswered_questions": unanswered_questions,
            "unknown_answers": unknown_answers,
            "invalid_answers": invalid_answers,
            "confirmation_log": [
                {
                    "question_key": key,
                    "applied": key in questions and key not in unanswered_questions,
                }
                for key in sorted(answer_map)
            ],
        }

    @staticmethod
    def extract_file_metadata(files: list[dict[str, Any]]) -> dict[str, Any]:
        metadata = []
        allowed_types = {
            "document_file",
            "drawing_file",
            "ocr_text",
            "masked_file",
            "source_snapshot",
        }
        for file_info in files:
            file_type = file_info.get("file_type")
            filename = str(file_info.get("filename", ""))
            extension = Path(filename).suffix.lower().lstrip(".")
            metadata.append(
                {
                    "filename": filename,
                    "file_type": file_type,
                    "extension": extension,
                    "allowed_file_type": file_type in allowed_types,
                    "raw_content_allowed_for_agent": False,
                    "requires_masking": file_type in {"document_file", "drawing_file"},
                    "metadata_only": True,
                }
            )
        return {
            "files": metadata,
            "agent_input_policy": "metadata_only_no_raw_drawing_or_document_content",
            "human_review_required": any(not item["allowed_file_type"] for item in metadata),
        }

    @staticmethod
    def _answer_value(answer: dict[str, Any]) -> str:
        value = answer.get("answer")
        if value is None:
            value = answer.get("answer_text")
        if value is None:
            value = answer.get("selected_option")
        return str(value or "").strip()

    @staticmethod
    def _looks_like_correction(text: str) -> bool:
        markers = ("補", "缺", "確認", "檢附", "圖說", "簽章", "材料", "權利")
        return any(marker in text for marker in markers)

    @staticmethod
    def _infer_sheet_type(filename: str) -> str:
        if "竣工" in filename:
            return "竣工圖說"
        if "材料" in filename:
            return "材料表"
        if "現況" in filename:
            return "現況圖"
        if "簡易" in filename:
            return "簡易圖說"
        return "室內裝修圖說"

    def resolve_procedure_requirements(
        self,
        stage: str,
        jurisdiction: str,
    ) -> dict[str, Any]:
        normalized_jurisdiction = jurisdiction.lower()
        return dict(
            self.data["procedure_requirements"].get(
                f"{normalized_jurisdiction}:{stage}",
                {
                    "jurisdiction": normalized_jurisdiction,
                    "procedure_stage": stage,
                    "supported": False,
                    "required_documents": [],
                    "human_review_required": True,
                    "handling": "未定義程序模板，需人工確認。",
                },
            )
        )

    @staticmethod
    def _as_of_basis(as_of_date_basis: str, user_supplied_date: str | None) -> list[str]:
        normalized_basis = as_of_date_basis or "run_date"
        if normalized_basis not in {"document_issue_date", "run_date", "user_supplied_date"}:
            normalized_basis = "run_date"
        basis = [normalized_basis, "run_date"]
        if user_supplied_date:
            basis.append("user_supplied_date")
        return list(dict.fromkeys(basis))

    @staticmethod
    def _snapshot_id(
        jurisdiction: dict[str, str],
        case_type: str,
        procedure_stage: str,
        as_of_date: str,
    ) -> str:
        canonical = json.dumps(
            {
                "jurisdiction": jurisdiction,
                "case_type": case_type,
                "procedure_stage": procedure_stage,
                "as_of_date": as_of_date,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]

    def _pack_articles(self, packs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        law_names = {name for pack in packs for name in pack["laws"]}
        return [article for article in self.data["articles"] if article["law_name"] in law_names]

    @staticmethod
    def _dedupe_by_url(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen_urls: set[str] = set()
        unique_entries = []
        for entry in entries:
            source_url = entry["source_url"]
            if source_url in seen_urls:
                continue
            seen_urls.add(source_url)
            unique_entries.append(entry)
        return unique_entries

    @staticmethod
    def _gate_schema_valid(correction_items: list[dict[str, Any]]) -> dict[str, Any]:
        required_fields = {"law_name", "article", "source_authority_rank", "source_license_status"}
        failing = []
        for idx, item in enumerate(correction_items):
            missing = sorted(required_fields - set(item.keys()))
            if missing:
                failing.append(idx)
        if failing:
            return {
                "gate": "schema_valid",
                "status": "failed",
                "reason": "missing_required_fields",
                "downgraded_items": failing,
                "details": [
                    {"index": idx, "missing": sorted(required_fields - set(correction_items[idx].keys()))}
                    for idx in failing
                ],
            }
        return {
            "gate": "schema_valid",
            "status": "passed",
            "reason": "all_items_have_required_fields",
            "downgraded_items": [],
        }

    @staticmethod
    def _gate_citation_exists(correction_items: list[dict[str, Any]]) -> dict[str, Any]:
        failing = []
        for idx, item in enumerate(correction_items):
            if not isinstance(item.get("law_name"), str) or not isinstance(item.get("article"), str):
                failing.append(idx)
        if not failing:
            return {
                "gate": "citation_exists",
                "status": "passed",
                "reason": "all_items_have_citation_fields",
                "downgraded_items": [],
            }
        return {
            "gate": "citation_exists",
            "status": "failed",
            "reason": "citation_fields_missing_or_invalid",
            "downgraded_items": failing,
            "details": [{"index": idx} for idx in failing],
        }

    @staticmethod
    def _gate_source_rank(correction_items: list[dict[str, Any]]) -> dict[str, Any]:
        failing = []
        for idx, item in enumerate(correction_items):
            rank = item.get("source_authority_rank")
            if not isinstance(rank, int) or not (1 <= rank <= 5):
                failing.append(idx)
        if not failing:
            return {
                "gate": "source_rank_valid",
                "status": "passed",
                "reason": "all_items_have_valid_authority_rank",
                "downgraded_items": [],
            }
        return {
            "gate": "source_rank_valid",
            "status": "failed",
            "reason": "invalid_authority_rank",
            "downgraded_items": failing,
            "details": [{"index": idx, "rank": correction_items[idx].get("source_authority_rank")} for idx in failing],
        }

    @staticmethod
    def _gate_source_license(correction_items: list[dict[str, Any]]) -> dict[str, Any]:
        blocked_statuses = {"restricted", "permission_required", "unknown"}
        failing = []
        for idx, item in enumerate(correction_items):
            license_status = item.get("source_license_status")
            if license_status in blocked_statuses:
                failing.append(idx)
        if not failing:
            return {
                "gate": "source_license_valid",
                "status": "passed",
                "reason": "all_items_have_accepted_license_status",
                "downgraded_items": [],
            }
        return {
            "gate": "source_license_valid",
            "status": "failed",
            "reason": "license_not_acceptable",
            "downgraded_items": failing,
            "details": [
                {"index": idx, "source_license_status": correction_items[idx].get("source_license_status")}
                for idx in failing
            ],
        }

    @staticmethod
    def _gate_claim_support(correction_items: list[dict[str, Any]]) -> dict[str, Any]:
        failing = []
        for idx, item in enumerate(correction_items):
            if item.get("claim_supported") is False:
                failing.append(idx)
        if not failing:
            return {
                "gate": "claim_supported",
                "status": "passed",
                "reason": "all_claims_have_support_or_not_applicable",
                "downgraded_items": [],
            }
        return {
            "gate": "claim_supported",
            "status": "failed",
            "reason": "low_confidence_or_unsupported_claim",
            "downgraded_items": failing,
            "details": [{"index": idx, "confidence": correction_items[idx].get("claim_support_confidence")} for idx in failing],
        }

    @staticmethod
    def _gate_red_line(correction_items: list[dict[str, Any]]) -> dict[str, Any]:
        forbidden = {"本案合規", "本案違法", "保證通過", "一定通過", "一定可通過", "一定不違規", "保證合法"}
        failing = []
        for idx, item in enumerate(correction_items):
            source_text = item.get("text", "")
            if any(token in source_text for token in forbidden):
                failing.append(idx)
        if not failing:
            return {
                "gate": "red_line_linter",
                "status": "passed",
                "reason": "no_forbidden_assertions_detected",
                "downgraded_items": [],
            }
        return {
            "gate": "red_line_linter",
            "status": "failed",
            "reason": "forbidden_assertions_detected",
            "downgraded_items": failing,
            "details": [
                {"index": idx}
                for idx in failing
            ],
        }

    @staticmethod
    def _gate_data_governance(data_governance_state: dict[str, Any] | None) -> dict[str, Any]:
        required = {
            "collection_purpose",
            "raw_file_retention_policy",
            "masked_file_retention_policy",
            "raw_file_access_scope",
            "pii_detection_status",
            "pii_masking_status",
            "deletion_request_supported",
            "audit_log_enabled",
            "vectorization_allowed",
        }
        consent_keys = {"user_consent_record_id", "consent_record_id"}
        if not data_governance_state:
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "missing_data_governance_state",
                "downgraded_items": ["all"],
                "details": [{"missing": sorted(required | consent_keys)}],
            }
        if not set(data_governance_state) & consent_keys:
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "missing_data_governance_fields",
                "downgraded_items": ["all"],
                "details": [{"missing": ["consent_record_id or user_consent_record_id"]}],
            }
        missing = sorted(required - set(data_governance_state.keys()))
        if missing:
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "missing_data_governance_fields",
                "downgraded_items": ["all"],
                "details": [{"missing": missing}],
            }
        if not isinstance(data_governance_state.get("vectorization_allowed"), bool):
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "invalid_data_governance_vectorization_flag",
                "downgraded_items": ["all"],
                "details": [
                    {"vectorization_allowed": data_governance_state.get("vectorization_allowed")}
                ],
            }
        if not data_governance_state.get("vectorization_allowed"):
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "vectorization_not_allowed_by_governance_policy",
                "downgraded_items": ["all"],
                "details": [
                    {
                        "vectorization_allowed": data_governance_state.get("vectorization_allowed"),
                        "pii_masking_status": data_governance_state.get("pii_masking_status"),
                    }
                ],
            }
        if data_governance_state.get("pii_masking_status") != "done":
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "pii_masking_incomplete",
                "downgraded_items": ["all"],
                "details": [{"pii_masking_status": data_governance_state.get("pii_masking_status")}],
            }
        if not isinstance(data_governance_state.get("pii_detection_status"), str):
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "pii_detection_status_missing_or_invalid",
                "downgraded_items": ["all"],
                "details": [{"pii_detection_status": data_governance_state.get("pii_detection_status")}],
            }
        if not isinstance(data_governance_state.get("deletion_request_supported"), bool):
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "deletion_request_support_flag_invalid",
                "downgraded_items": ["all"],
                "details": [
                    {
                        "deletion_request_supported": data_governance_state.get(
                            "deletion_request_supported"
                        )
                    }
                ],
            }
        if not isinstance(data_governance_state.get("audit_log_enabled"), bool):
            return {
                "gate": "data_governance",
                "status": "failed",
                "reason": "audit_log_flag_invalid",
                "downgraded_items": ["all"],
                "details": [{"audit_log_enabled": data_governance_state.get("audit_log_enabled")}],
            }
        return {
            "gate": "data_governance",
            "status": "passed",
            "reason": "data_governance_fields_complete",
            "downgraded_items": [],
        }


def load_default_repository(path: Path = DATA_PATH) -> LawRepository:
    with path.open("r", encoding="utf-8") as handle:
        return LawRepository(json.load(handle))
