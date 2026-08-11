from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from tw_law_mcp.repository import load_default_repository

from .codex_provider import CodexCliProvider
from .config import WorkerConfig
from .database import WorkerDatabase
from .masking import mask_sensitive_text


SAFE_PROCESSING_ERRORS = {
    "MALWARE_DETECTED",
    "UNSUPPORTED_MEDIA_TYPE",
    "NO_EXTRACTABLE_TEXT",
    "RESIDUAL_PII_BLOCKED",
}


def _safe_error_code(error: Exception) -> str:
    value = str(error)
    return value if value in SAFE_PROCESSING_ERRORS else "PROCESSING_FAILED"


def _extract_text(path: Path, media_type: str) -> str:
    if media_type == "text/plain":
        return path.read_text(encoding="utf-8")
    raise RuntimeError("UNSUPPORTED_MEDIA_TYPE")


def _question_rows(result: dict[str, Any]) -> list[dict[str, str]]:
    artifacts = result.get("artifacts", {})
    packet = artifacts.get("client_questions.json", {})
    questions = packet.get("client_questions") or packet.get("questions") or []
    rows: list[dict[str, str]] = []
    for index, question in enumerate(questions):
        if not isinstance(question, dict):
            continue
        key = str(question.get("question_key") or question.get("key") or f"question-{index + 1}")
        prompt = str(question.get("prompt") or question.get("question") or "需要人工確認")
        rows.append({"key": key[:120], "prompt": prompt[:2000]})
    return rows


def _data_governance_state(row: dict[str, Any]) -> dict[str, Any] | None:
    raw = row.get("data_governance_json")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stored = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(stored, dict):
        return None
    return {
        **stored,
        "pii_detection_status": "completed",
        "pii_masking_status": "done",
    }


def _data_governance_passed(result: dict[str, Any]) -> bool:
    run_meta = result.get("artifacts", {}).get("run_meta.json", {})
    gates = run_meta.get("gate_results") or run_meta.get("gates") or []
    return any(
        isinstance(gate, dict)
        and gate.get("gate") == "data_governance"
        and gate.get("status") == "passed"
        for gate in gates
    )


def process_upload(
    config: WorkerConfig,
    upload_id: str,
    *,
    codex_provider: CodexCliProvider | None = None,
) -> None:
    database = WorkerDatabase(config.database_path)
    row = database.get_upload(upload_id)
    if not row or row["state"] != "uploaded":
        raise RuntimeError("upload is not ready for processing")
    raw_path = Path(row["quarantine_path"]).resolve(strict=True)
    if config.quarantine_root.resolve(strict=True) not in raw_path.parents:
        raise RuntimeError("quarantine path escaped its trusted root")

    try:
        database.transition(upload_id, "uploaded", "scanning")
        data = raw_path.read_bytes()
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
            raise RuntimeError("MALWARE_DETECTED")
        database.transition(upload_id, "scanning", "clean")
        text = _extract_text(raw_path, row["expected_media_type"])
        database.transition(upload_id, "clean", "masking")
        masking = mask_sensitive_text(text)
        if not masking.text.strip():
            raise RuntimeError("NO_EXTRACTABLE_TEXT")

        sanitized_path = config.sanitized_root / f"{upload_id}.masked.txt"
        with sanitized_path.open("x", encoding="utf-8") as handle:
            os.chmod(sanitized_path, 0o600)
            handle.write(masking.text)
        sanitized_sha = hashlib.sha256(masking.text.encode("utf-8")).hexdigest()

        repository = load_default_repository()
        governance_state = _data_governance_state(row)
        deterministic = repository.run_tw_corrections_analysis(
            text=masking.text,
            files=[{"filename": "masked-document.txt", "file_type": "document_file"}],
            jurisdiction="ntpc",
            data_governance_state=governance_state,
        )
        deterministic_json = json.dumps(deterministic, ensure_ascii=False, sort_keys=True)
        model_result: dict[str, Any] | None = None
        model_status = "disabled"
        if config.codex_enabled and _data_governance_passed(deterministic):
            provider = codex_provider or CodexCliProvider(
                timeout_seconds=config.model_timeout_seconds
            )
            model = provider.analyze(masking.text, deterministic)
            model_result = {
                "summary": model.summary,
                "risk_flags": model.risk_flags,
                "human_review_required": model.human_review_required,
            }
            model_status = "completed"
        elif config.codex_enabled:
            model_status = "blocked_by_data_governance"

        now = int(time.time())
        run_id = str(uuid.uuid4())
        artifact_id = str(uuid.uuid4())
        questions = _question_rows(deterministic)
        with database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO artifact "
                "(id, case_id, upload_id, kind, storage_path, sha256, metadata_json, created_at) "
                "VALUES (?, ?, ?, 'masked_text', ?, ?, ?, ?)",
                (
                    artifact_id,
                    row["case_id"],
                    upload_id,
                    str(sanitized_path),
                    sanitized_sha,
                    json.dumps({"mask_counts": masking.counts}, sort_keys=True),
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO analysis_run "
                "(id, case_id, upload_id, status, deterministic_result_json, model_result_json, "
                "model_status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    row["case_id"],
                    upload_id,
                    "awaiting_review",
                    deterministic_json,
                    json.dumps(model_result, ensure_ascii=False) if model_result else None,
                    model_status,
                    now,
                    now,
                ),
            )
            for question in questions:
                connection.execute(
                    "INSERT INTO hitl_question "
                    "(id, case_id, analysis_run_id, question_key, prompt, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                    (
                        str(uuid.uuid4()),
                        row["case_id"],
                        run_id,
                        question["key"],
                        question["prompt"],
                        now,
                    ),
                )
            connection.execute(
                "UPDATE upload_record SET state = 'sanitized', sanitized_path = ?, updated_at = ? "
                "WHERE id = ? AND state = 'masking'",
                (str(sanitized_path), now, upload_id),
            )
            connection.execute(
                "UPDATE case_record SET status = 'awaiting_review', updated_at = ? WHERE id = ?",
                (now, row["case_id"]),
            )
            connection.execute(
                "INSERT INTO audit_event "
                "(id, case_id, actor_user_id, action, entity_type, entity_id, metadata_json, created_at) "
                "VALUES (?, ?, NULL, 'upload.sanitized', 'upload', ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    row["case_id"],
                    upload_id,
                    json.dumps(
                        {
                            "artifact_kind": "masked_text",
                            "mask_total": masking.total,
                            "model_status": model_status,
                            "data_governance_status": (
                                "passed" if _data_governance_passed(deterministic) else "failed"
                            ),
                            "consent_record_id": (
                                governance_state.get("consent_record_id")
                                if governance_state
                                else None
                            ),
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            connection.commit()
        if not questions:
            process_review(config, run_id)
    except Exception as error:
        database.reject_upload(upload_id, _safe_error_code(error))
        raise


def process_review(config: WorkerConfig, analysis_run_id: str) -> None:
    database = WorkerDatabase(config.database_path)
    with database.connect() as connection:
        run = connection.execute(
            "SELECT * FROM analysis_run WHERE id = ?", (analysis_run_id,)
        ).fetchone()
        if not run or run["status"] != "awaiting_review":
            raise RuntimeError("analysis run is not awaiting review")
        questions = connection.execute(
            "SELECT question_key, answer, status, answered_by_user_id FROM hitl_question "
            "WHERE analysis_run_id = ? ORDER BY created_at",
            (analysis_run_id,),
        ).fetchall()
    if any(row["status"] != "answered" or not row["answer"] for row in questions):
        raise RuntimeError("review answers are incomplete")
    if any(not row["answered_by_user_id"] for row in questions):
        raise RuntimeError("review answers are missing an authenticated approver")

    deterministic = json.loads(run["deterministic_result_json"])
    answers = [
        {"question_key": row["question_key"], "answer_text": row["answer"], "is_answered": True}
        for row in questions
    ]
    repository = load_default_repository()
    # The artifacts come from this worker's private database, so the run identity can
    # be restored; each answer is then bound to the session user who actually gave it.
    artifacts = deterministic.get("artifacts", {})
    run_id = repository.restore_analysis_run(artifacts)
    if run_id:
        for row, answer in zip(questions, answers):
            repository.record_hitl_approval(
                run_id=run_id,
                question_key=row["question_key"],
                approved_by=row["answered_by_user_id"],
                answer=answer,
                analysis_artifacts=artifacts,
            )
    response = repository.run_tw_corrections_response(artifacts, answers, run_id=run_id)
    response_json = json.dumps(response, ensure_ascii=False, sort_keys=True)
    now = int(time.time())
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        changed = connection.execute(
            "UPDATE analysis_run SET status = 'completed', response_result_json = ?, updated_at = ? "
            "WHERE id = ? AND status = 'awaiting_review'",
            (response_json, now, analysis_run_id),
        ).rowcount
        if changed != 1:
            connection.rollback()
            raise RuntimeError("review state changed concurrently")
        connection.execute(
            "UPDATE case_record SET status = 'completed', updated_at = ? WHERE id = ?",
            (now, run["case_id"]),
        )
        connection.execute(
            "INSERT INTO audit_event "
            "(id, case_id, actor_user_id, action, entity_type, entity_id, metadata_json, created_at) "
            "VALUES (?, ?, NULL, 'review.completed', 'analysis_run', ?, '{}', ?)",
            (str(uuid.uuid4()), run["case_id"], analysis_run_id, now),
        )
        connection.commit()
