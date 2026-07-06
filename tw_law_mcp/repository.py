from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DATA_PATH = Path(__file__).with_name("data") / "p0_law_corpus.json"


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_terms(query: str) -> list[str]:
    return [term for term in query.replace("/", " ").split() if term]


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
            score = sum(
                article["text"].count(term) + article["law_name"].count(term)
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
        return dict(
            self.data["procedure_requirements"].get(
                f"{jurisdiction}:{stage}",
                {
                    "jurisdiction": jurisdiction,
                    "procedure_stage": stage,
                    "supported": False,
                    "required_documents": [],
                    "human_review_required": True,
                },
            )
        )

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


def load_default_repository(path: Path = DATA_PATH) -> LawRepository:
    with path.open("r", encoding="utf-8") as handle:
        return LawRepository(json.load(handle))
