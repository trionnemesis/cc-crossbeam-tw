from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATA_PATH = Path(__file__).with_name("data") / "p0_law_corpus.json"


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_terms(query: str) -> list[str]:
    normalized = query.replace("/", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return [term.lower() for term in normalized.split() if term]


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
