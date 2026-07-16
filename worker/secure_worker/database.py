from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class WorkerDatabase:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
        finally:
            connection.close()

    def validate_schema(self) -> None:
        required = {
            "upload_record",
            "artifact",
            "analysis_run",
            "hitl_question",
            "case_record",
            "audit_event",
        }
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        present = {row["name"] for row in rows}
        missing = sorted(required - present)
        if missing:
            raise RuntimeError(f"worker database schema is incomplete: {', '.join(missing)}")

    def claim_upload(
        self,
        *,
        token_hash: str,
        upload_id: str,
        content_length: int,
        media_type: str,
        content_sha256: str,
    ) -> dict[str, Any] | None:
        now = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM upload_record WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                connection.rollback()
                return None
            checks = (
                row["id"] == upload_id,
                row["state"] == "pending",
                row["token_expires_at"] > now,
                row["expected_size"] == content_length,
                row["max_size"] >= content_length,
                row["expected_media_type"] == media_type,
                row["expected_sha256"] == content_sha256,
            )
            if not all(checks):
                connection.rollback()
                return None
            changed = connection.execute(
                "UPDATE upload_record SET state = 'uploading', updated_at = ? "
                "WHERE id = ? AND state = 'pending'",
                (now, upload_id),
            ).rowcount
            if changed != 1:
                connection.rollback()
                return None
            connection.commit()
            return dict(row)

    def mark_uploaded(self, upload_id: str, quarantine_path: Path) -> None:
        now = int(time.time())
        with self.connect() as connection:
            changed = connection.execute(
                "UPDATE upload_record SET state = 'uploaded', quarantine_path = ?, "
                "uploaded_at = ?, updated_at = ? WHERE id = ? AND state = 'uploading'",
                (str(quarantine_path), now, now, upload_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("invalid upload state transition")
            connection.commit()

    def reject_upload(self, upload_id: str, error_code: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE upload_record SET state = 'rejected', error_code = ?, updated_at = ? "
                "WHERE id = ? AND state IN ('uploading', 'uploaded', 'scanning', 'clean', 'masking')",
                (error_code, int(time.time()), upload_id),
            )
            connection.commit()

    def get_upload(self, upload_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM upload_record WHERE id = ?", (upload_id,)
            ).fetchone()
        return dict(row) if row else None

    def transition(self, upload_id: str, expected: str, target: str) -> None:
        with self.connect() as connection:
            changed = connection.execute(
                "UPDATE upload_record SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                (target, int(time.time()), upload_id, expected),
            ).rowcount
            if changed != 1:
                raise RuntimeError(f"invalid upload state transition: {expected} -> {target}")
            connection.commit()
