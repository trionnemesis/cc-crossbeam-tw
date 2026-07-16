from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from worker.secure_worker.codex_provider import CodexAnalysis, CodexCliProvider
from worker.secure_worker.config import WorkerConfig
from worker.secure_worker.masking import find_sensitive_classes, mask_sensitive_text
from worker.secure_worker.processing import process_review, process_upload
from worker.secure_worker.upload import UploadRejected, accept_upload, bytes_stream


SCHEMA = """
CREATE TABLE case_record (id TEXT PRIMARY KEY, status TEXT, updated_at INTEGER);
CREATE TABLE upload_record (
 id TEXT PRIMARY KEY, case_id TEXT, uploader_user_id TEXT, object_key TEXT,
 display_label TEXT, expected_size INTEGER, max_size INTEGER, expected_media_type TEXT,
 expected_sha256 TEXT, token_hash TEXT UNIQUE, token_expires_at INTEGER, state TEXT,
 quarantine_path TEXT, sanitized_path TEXT, error_code TEXT, created_at INTEGER,
 updated_at INTEGER, uploaded_at INTEGER
);
CREATE TABLE artifact (
 id TEXT PRIMARY KEY, case_id TEXT, upload_id TEXT, kind TEXT, storage_path TEXT,
 sha256 TEXT, metadata_json TEXT, created_at INTEGER
);
CREATE TABLE analysis_run (
 id TEXT PRIMARY KEY, case_id TEXT, upload_id TEXT, status TEXT,
 deterministic_result_json TEXT, model_result_json TEXT, response_result_json TEXT, model_status TEXT,
 created_at INTEGER, updated_at INTEGER
);
CREATE TABLE hitl_question (
 id TEXT PRIMARY KEY, case_id TEXT, analysis_run_id TEXT, question_key TEXT,
 prompt TEXT, status TEXT, answer TEXT, answered_by_user_id TEXT,
 created_at INTEGER, answered_at INTEGER, UNIQUE(analysis_run_id, question_key)
);
CREATE TABLE audit_event (
 id TEXT PRIMARY KEY, case_id TEXT, actor_user_id TEXT, action TEXT,
 entity_type TEXT, entity_id TEXT, metadata_json TEXT, created_at INTEGER
);
"""


class SecureWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.database_path = root / "worker.sqlite"
        self.quarantine = root / "quarantine"
        self.sanitized = root / "sanitized"
        self.quarantine.mkdir(mode=0o700)
        self.sanitized.mkdir(mode=0o700)
        self.config = WorkerConfig(
            database_path=self.database_path,
            quarantine_root=self.quarantine,
            sanitized_root=self.sanitized,
            allowed_origin="http://127.0.0.1:3000",
            codex_enabled=False,
        )
        connection = sqlite3.connect(self.database_path)
        connection.executescript(SCHEMA)
        connection.execute(
            "INSERT INTO case_record (id, status, updated_at) VALUES ('case-1', 'awaiting_upload', 0)"
        )
        connection.commit()
        connection.close()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _intent(self, upload_id: str, token: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        connection = sqlite3.connect(self.database_path)
        connection.execute(
            "INSERT INTO upload_record "
            "(id, case_id, uploader_user_id, object_key, display_label, expected_size, max_size, "
            "expected_media_type, expected_sha256, token_hash, token_expires_at, state, "
            "created_at, updated_at) VALUES (?, 'case-1', 'user-1', ?, '測試文件', ?, ?, "
            "'text/plain', ?, ?, 4102444800, 'pending', 0, 0)",
            (
                upload_id,
                f"case-1/{upload_id}",
                len(data),
                self.config.max_upload_bytes,
                digest,
                hashlib.sha256(token.encode()).hexdigest(),
            ),
        )
        connection.commit()
        connection.close()
        return digest

    def test_masking_removes_common_taiwan_identifiers(self) -> None:
        raw = (
            "申請人王小明，身分證 A123456789，email owner@example.com，電話 0912-345-678，"
            "統編12345678，護照號碼AB123456，地號板橋區文化段123地號，"
            "地址板橋區文化路一段123號，案件編號NTPC-12345。"
        )
        result = mask_sensitive_text(raw)
        self.assertGreaterEqual(result.total, 9)
        self.assertEqual(find_sensitive_classes(result.text), [])
        for canary in [
            "王小明",
            "A123456789",
            "owner@example.com",
            "0912-345-678",
            "12345678",
            "AB123456",
            "文化段123地號",
            "文化路一段123號",
            "NTPC-12345",
        ]:
            self.assertNotIn(canary, result.text)

    def test_model_receives_only_masked_payload_from_real_upload_path(self) -> None:
        upload_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        token = "m" * 43
        raw = (
            "業主王小明，統編12345678，護照號碼AB123456，"
            "地號板橋區文化段123地號，地址板橋區文化路一段1號。"
        ).encode()
        digest = self._intent(upload_id, token, raw)
        accept_upload(
            self.config,
            token=token,
            upload_id=upload_id,
            media_type="text/plain",
            content_length=len(raw),
            content_sha256=digest,
            stream=bytes_stream(raw),
        )

        class SpyProvider:
            received = ""

            def analyze(self, masked_text, _context):  # type: ignore[no-untyped-def]
                self.received = masked_text
                return CodexAnalysis("已遮罩", [], True)

        provider = SpyProvider()
        process_upload(replace(self.config, codex_enabled=True), upload_id, codex_provider=provider)  # type: ignore[arg-type]
        self.assertGreater(provider.received.count("[MASKED_"), 0)
        for canary in ["王小明", "12345678", "AB123456", "文化段123地號", "文化路一段1號"]:
            self.assertNotIn(canary, provider.received)

    def test_single_user_worker_accepts_https_origin_but_stays_on_loopback(self) -> None:
        with patch("worker.secure_worker.config.REPO_ROOT", Path(self.temp.name)):
            with patch("worker.secure_worker.config.RUNTIME_ROOT", Path(self.temp.name) / ".runtime"):
                config = WorkerConfig.from_environment(
                    {
                        "APP_MODE": "single-user",
                        "APP_ORIGIN": "https://secure.example.com",
                        "WORKER_BIND_HOST": "127.0.0.1",
                        "DATABASE_PATH": ".runtime/secure-web.sqlite",
                        "QUARANTINE_ROOT": ".runtime/quarantine",
                        "SANITIZED_ROOT": ".runtime/sanitized",
                    }
                )
        self.assertEqual(config.allowed_origin, "https://secure.example.com")
        self.assertEqual(config.bind_host, "127.0.0.1")

    def test_upload_is_single_use_and_processes_only_masked_text(self) -> None:
        upload_id = "11111111-1111-4111-8111-111111111111"
        token = "a" * 43
        raw = "補正通知 A123456789 owner@example.com 新北市板橋區文化路一段123號".encode()
        digest = self._intent(upload_id, token, raw)
        accepted = accept_upload(
            self.config,
            token=token,
            upload_id=upload_id,
            media_type="text/plain",
            content_length=len(raw),
            content_sha256=digest,
            stream=bytes_stream(raw),
        )
        self.assertTrue(accepted.exists())
        with self.assertRaises(UploadRejected):
            accept_upload(
                self.config,
                token=token,
                upload_id=upload_id,
                media_type="text/plain",
                content_length=len(raw),
                content_sha256=digest,
                stream=bytes_stream(raw),
            )

        process_upload(self.config, upload_id)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        upload = connection.execute(
            "SELECT state, sanitized_path FROM upload_record WHERE id = ?", (upload_id,)
        ).fetchone()
        run = connection.execute(
            "SELECT deterministic_result_json, model_status FROM analysis_run WHERE upload_id = ?",
            (upload_id,),
        ).fetchone()
        connection.close()
        self.assertEqual(upload["state"], "sanitized")
        self.assertEqual(run["model_status"], "disabled")
        sanitized = Path(upload["sanitized_path"]).read_text()
        combined = sanitized + run["deterministic_result_json"]
        for canary in ["A123456789", "owner@example.com", "文化路一段123號"]:
            self.assertNotIn(canary, combined)

    def test_upload_rejects_checksum_mismatch(self) -> None:
        upload_id = "22222222-2222-4222-8222-222222222222"
        token = "b" * 43
        raw = b"safe text"
        self._intent(upload_id, token, raw)
        with self.assertRaises(UploadRejected):
            accept_upload(
                self.config,
                token=token,
                upload_id=upload_id,
                media_type="text/plain",
                content_length=len(raw),
                content_sha256="0" * 64,
                stream=bytes_stream(raw),
            )

    def test_review_requires_all_answers_and_builds_response(self) -> None:
        upload_id = "33333333-3333-4333-8333-333333333333"
        token = "c" * 43
        raw = "補正通知，程序階段需確認。".encode()
        digest = self._intent(upload_id, token, raw)
        accept_upload(
            self.config,
            token=token,
            upload_id=upload_id,
            media_type="text/plain",
            content_length=len(raw),
            content_sha256=digest,
            stream=bytes_stream(raw),
        )
        process_upload(self.config, upload_id)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        run = connection.execute(
            "SELECT id FROM analysis_run WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        with self.assertRaises(RuntimeError):
            process_review(self.config, run["id"])
        connection.execute(
            "UPDATE hitl_question SET status = 'answered', answer = '圖說審核' "
            "WHERE analysis_run_id = ?",
            (run["id"],),
        )
        connection.commit()
        connection.close()
        process_review(self.config, run["id"])
        connection = sqlite3.connect(self.database_path)
        completed = connection.execute(
            "SELECT status, response_result_json FROM analysis_run WHERE id = ?", (run["id"],)
        ).fetchone()
        connection.close()
        self.assertEqual(completed[0], "completed")
        self.assertIn("response_draft.md", completed[1])

    def test_upload_without_questions_completes_response_automatically(self) -> None:
        upload_id = "44444444-4444-4444-8444-444444444444"
        token = "d" * 43
        raw = "本案辦理圖說審核，請補申請書。".encode()
        digest = self._intent(upload_id, token, raw)
        accept_upload(
            self.config,
            token=token,
            upload_id=upload_id,
            media_type="text/plain",
            content_length=len(raw),
            content_sha256=digest,
            stream=bytes_stream(raw),
        )
        process_upload(self.config, upload_id)
        connection = sqlite3.connect(self.database_path)
        run = connection.execute(
            "SELECT status, response_result_json FROM analysis_run WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        question_count = connection.execute(
            "SELECT count(*) FROM hitl_question WHERE analysis_run_id = "
            "(SELECT id FROM analysis_run WHERE upload_id = ?)",
            (upload_id,),
        ).fetchone()[0]
        connection.close()
        self.assertEqual(question_count, 0)
        self.assertEqual(run[0], "completed")
        self.assertIn("response_draft.md", run[1])

    def test_codex_provider_is_isolated_and_does_not_inherit_secrets(self) -> None:
        provider = CodexCliProvider(timeout_seconds=5)
        observed: dict[str, object] = {}

        def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
            observed["command"] = command
            observed["environment"] = kwargs["env"]
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text(
                json.dumps(
                    {
                        "summary": "需人工確認",
                        "risk_flags": ["法源需核對"],
                        "human_review_required": True,
                    }
                )
            )
            return type("Completed", (), {"returncode": 0})()

        with patch.dict("os.environ", {"HOME": "/tmp/home", "PATH": "/bin", "DATABASE_URL": "secret"}, clear=True):
            with patch("subprocess.run", side_effect=fake_run):
                result = provider.analyze("[MASKED_TAIWAN_ID] 補正通知", {"artifact_names": []})
        self.assertTrue(result.human_review_required)
        command = observed["command"]
        self.assertIn("--ephemeral", command)
        self.assertIn("read-only", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("shell_tool", command)
        self.assertNotIn("DATABASE_URL", observed["environment"])


if __name__ == "__main__":
    unittest.main()
