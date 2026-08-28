from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).with_name("data") / "local_rules"
ALLOWED_LEGAL_STATUSES = {"active", "abolished", "superseded", "pending_reverification"}
ALLOWED_REPRESENTATIONS = {"source_snapshot", "normalized_requirement", "discovery_reference"}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_iso_date(value: str | None, field: str, failures: list[str], source_id: str) -> date | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        failures.append(f"{source_id}: {field} must be an ISO date string or null")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        failures.append(f"{source_id}: {field} is not YYYY-MM-DD")
        return None


def _safe_iso_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def load_local_rule_records(data_dir: Path = DATA_DIR) -> list[dict[str, Any]]:
    if not data_dir.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(data_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "records" in payload:
            batch = payload["records"]
        else:
            batch = [payload]
        if not isinstance(batch, list):
            raise ValueError(f"{path}: records must be a list")
        for record in batch:
            if not isinstance(record, dict):
                raise ValueError(f"{path}: each record must be an object")
            records.append(record)
    return records


def validate_local_rule_record(record: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    source_id = str(record.get("source_id") or "<missing-source-id>")

    required = (
        "source_id",
        "jurisdiction",
        "official_identifier",
        "source_url",
        "source_kind",
        "representation",
        "legal_status",
        "promulgated_at",
        "effective_from",
        "effective_to",
        "amended_at",
        "retrieved_at",
        "verified_at",
        "source_license_status",
    )
    for field in required:
        if field not in record:
            failures.append(f"{source_id}: missing {field}")

    if record.get("legal_status") not in ALLOWED_LEGAL_STATUSES:
        failures.append(f"{source_id}: invalid legal_status")
    if record.get("representation") not in ALLOWED_REPRESENTATIONS:
        failures.append(f"{source_id}: invalid representation")
    if record.get("source_kind") != "local_rule":
        failures.append(f"{source_id}: source_kind must be local_rule")

    jurisdiction = record.get("jurisdiction")
    if not isinstance(jurisdiction, dict) or not jurisdiction.get("local"):
        failures.append(f"{source_id}: jurisdiction.local is required")

    for field in ("promulgated_at", "effective_from", "effective_to", "amended_at"):
        _parse_iso_date(record.get(field), field, failures, source_id)

    effective_from = _safe_iso_date(record.get("effective_from"))
    effective_to = _safe_iso_date(record.get("effective_to"))
    if effective_from and effective_to and effective_to < effective_from:
        failures.append(f"{source_id}: effective_to precedes effective_from")

    retrieved_at = record.get("retrieved_at")
    verified_at = record.get("verified_at")
    if not isinstance(retrieved_at, str) or "T" not in retrieved_at:
        failures.append(f"{source_id}: retrieved_at must be an ISO datetime")
    if not isinstance(verified_at, str) or "T" not in verified_at:
        failures.append(f"{source_id}: verified_at must be an ISO datetime")

    retrieved_date = retrieved_at.split("T", 1)[0] if isinstance(retrieved_at, str) else None
    verified_date = verified_at.split("T", 1)[0] if isinstance(verified_at, str) else None
    for field in ("promulgated_at", "effective_from", "amended_at"):
        value = record.get(field)
        basis = record.get(f"{field}_basis")
        if value and value in {retrieved_date, verified_date} and basis in {None, "retrieved_at", "verified_at"}:
            failures.append(f"{source_id}: {field} may not be inferred from retrieval/verification time")

    representation = record.get("representation")
    requirements = record.get("requirements", [])
    if representation == "normalized_requirement":
        if not isinstance(requirements, list) or not requirements:
            failures.append(f"{source_id}: normalized_requirement requires requirements")
        for index, requirement in enumerate(requirements):
            prefix = f"{source_id}: requirement[{index}]"
            if not isinstance(requirement, dict):
                failures.append(f"{prefix} must be an object")
                continue
            locator = requirement.get("source_locator")
            if not isinstance(locator, dict) or not locator.get("point"):
                failures.append(f"{prefix} missing source_locator.point")
            normalized = requirement.get("normalized_facts")
            if not isinstance(normalized, dict) or not normalized:
                failures.append(f"{prefix} missing normalized_facts")
            expected_hash = _canonical_sha256(normalized) if isinstance(normalized, dict) else None
            if requirement.get("normalized_content_sha256") != expected_hash:
                failures.append(f"{prefix} normalized_content_sha256 mismatch")
            if requirement.get("verification_status") != "normalized_verified":
                failures.append(f"{prefix} must be normalized_verified")
            if requirement.get("source_text_sha256") is not None:
                failures.append(f"{prefix} source_text_sha256 must stay null unless an exact source snapshot is retained")

    if representation == "source_snapshot":
        if not record.get("source_text_sha256"):
            failures.append(f"{source_id}: source_snapshot requires source_text_sha256")

    if record.get("legal_status") in {"abolished", "superseded"} and not record.get("effective_to"):
        failures.append(f"{source_id}: inactive rule requires effective_to")

    return failures


@dataclass(frozen=True)
class VersionSelection:
    exists: bool
    status: str
    human_review_required: bool
    record: dict[str, Any] | None = None
    candidates: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "exists": self.exists,
            "status": self.status,
            "human_review_required": self.human_review_required,
            "record": self.record,
            "candidates": list(self.candidates),
        }


def select_local_rule_version(
    records: list[dict[str, Any]],
    *,
    jurisdiction: str,
    official_identifier: str,
    as_of_date: str | None = None,
) -> dict[str, Any]:
    matches = [
        record
        for record in records
        if isinstance(record.get("jurisdiction"), dict)
        and record["jurisdiction"].get("local") == jurisdiction
        and record.get("official_identifier") == official_identifier
    ]
    if not matches:
        return VersionSelection(False, "not_found", True).as_dict()

    if any(record.get("legal_status") == "pending_reverification" for record in matches):
        ids = tuple(str(record.get("source_id")) for record in matches)
        return VersionSelection(False, "pending_reverification", True, candidates=ids).as_dict()

    active = [record for record in matches if record.get("legal_status") == "active"]
    if as_of_date is None:
        if len(active) == 1:
            return VersionSelection(True, "current_active", False, record=active[0]).as_dict()
        status = "ambiguous_active_versions" if active else "no_active_version"
        return VersionSelection(False, status, True, candidates=tuple(str(r.get("source_id")) for r in active)).as_dict()

    try:
        target = date.fromisoformat(as_of_date)
    except (TypeError, ValueError):
        return VersionSelection(False, "invalid_as_of_date", True).as_dict()

    malformed_records: list[str] = []
    for record in matches:
        for field in ("effective_from", "effective_to"):
            raw = record.get(field)
            if raw in (None, ""):
                continue
            if _safe_iso_date(raw) is None:
                malformed_records.append(f"{record.get('source_id')}:{field}")
    if malformed_records:
        return VersionSelection(
            False,
            "invalid_record_date",
            True,
            candidates=tuple(sorted(malformed_records)),
        ).as_dict()

    unknown_effective = [record for record in active if not record.get("effective_from")]
    if unknown_effective:
        return VersionSelection(
            False,
            "unknown_effective_from",
            True,
            candidates=tuple(str(record.get("source_id")) for record in unknown_effective),
        ).as_dict()

    candidates: list[dict[str, Any]] = []
    for record in matches:
        if record.get("legal_status") not in {"active", "abolished", "superseded"}:
            continue
        start = _safe_iso_date(record.get("effective_from"))
        if start is None:
            continue
        end = _safe_iso_date(record.get("effective_to"))
        if start <= target and (end is None or target <= end):
            candidates.append(record)

    if len(candidates) == 1:
        return VersionSelection(True, "effective_version", False, record=candidates[0]).as_dict()
    if len(candidates) > 1:
        return VersionSelection(
            False,
            "overlapping_versions",
            True,
            candidates=tuple(str(record.get("source_id")) for record in candidates),
        ).as_dict()
    return VersionSelection(False, "no_effective_version", True).as_dict()


def run_local_rule_lifecycle_acceptance(data_dir: Path = DATA_DIR) -> dict[str, Any]:
    records = load_local_rule_records(data_dir)
    failures: list[str] = []
    for record in records:
        failures.extend(validate_local_rule_record(record))

    identifiers: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        jurisdiction = record.get("jurisdiction") or {}
        key = (str(jurisdiction.get("local")), str(record.get("official_identifier")))
        identifiers.setdefault(key, []).append(record)

    for (jurisdiction, official_identifier), group in identifiers.items():
        active = [record for record in group if record.get("legal_status") == "active"]
        if len(active) > 1:
            failures.append(f"{jurisdiction}:{official_identifier}: multiple active versions")

    ntpc_current = select_local_rule_version(
        records,
        jurisdiction="ntpc",
        official_identifier="C0170020",
    )
    if not ntpc_current["exists"]:
        failures.append("ntpc:C0170020: current active version must resolve")

    ntpc_historical = select_local_rule_version(
        records,
        jurisdiction="ntpc",
        official_identifier="C0170020",
        as_of_date="2020-01-01",
    )
    if ntpc_historical["status"] != "unknown_effective_from" or not ntpc_historical["human_review_required"]:
        failures.append("ntpc:C0170020: historical query must fail closed while effective_from is unknown")

    return {
        "all_passed": not failures,
        "failures": failures,
        "record_count": len(records),
        "jurisdiction_count": len({(r.get("jurisdiction") or {}).get("local") for r in records}),
        "active_record_count": sum(r.get("legal_status") == "active" for r in records),
        "normalized_requirement_count": sum(
            len(r.get("requirements", [])) for r in records if r.get("representation") == "normalized_requirement"
        ),
        "current_ntpc_selection": ntpc_current,
        "historical_ntpc_selection": ntpc_historical,
    }


def augment_phase_acceptance(base_result: dict[str, Any]) -> dict[str, Any]:
    """Add local-rule lifecycle acceptance to an aggregate phase result.

    CLI and MCP both call this helper so transport choice cannot bypass the lifecycle gate.
    """
    lifecycle = run_local_rule_lifecycle_acceptance()
    result = dict(base_result)
    gates = dict(base_result.get("gates", {}))
    details = dict(base_result.get("details", {}))
    gates["local_rule_lifecycle"] = lifecycle["all_passed"]
    details["local_rule_lifecycle"] = lifecycle
    result["gates"] = gates
    result["details"] = details
    result["all_passed"] = bool(base_result.get("all_passed")) and lifecycle["all_passed"]
    return result
