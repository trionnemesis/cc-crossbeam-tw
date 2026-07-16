from __future__ import annotations

import hashlib
import hmac
import io
import os
import uuid
from pathlib import Path
from typing import BinaryIO

from .config import WorkerConfig
from .database import WorkerDatabase


class UploadRejected(Exception):
    pass


def _media_matches(media_type: str, prefix: bytes) -> bool:
    if media_type == "application/pdf":
        return prefix.startswith(b"%PDF-")
    if media_type == "image/png":
        return prefix.startswith(b"\x89PNG\r\n\x1a\n")
    if media_type == "image/jpeg":
        return prefix.startswith(b"\xff\xd8\xff")
    if media_type == "text/plain":
        return b"\x00" not in prefix
    return False


def accept_upload(
    config: WorkerConfig,
    *,
    token: str,
    upload_id: str,
    media_type: str,
    content_length: int,
    content_sha256: str,
    stream: BinaryIO,
) -> Path:
    try:
        uuid.UUID(upload_id)
    except ValueError as error:
        raise UploadRejected("invalid upload identifier") from error
    if content_length <= 0 or content_length > config.max_upload_bytes:
        raise UploadRejected("invalid content length")
    if len(token) < 32 or len(content_sha256) != 64:
        raise UploadRejected("invalid upload capability")

    token_hash = hashlib.sha256(token.encode("ascii", errors="strict")).hexdigest()
    database = WorkerDatabase(config.database_path)
    row = database.claim_upload(
        token_hash=token_hash,
        upload_id=upload_id,
        content_length=content_length,
        media_type=media_type,
        content_sha256=content_sha256,
    )
    if not row:
        raise UploadRejected("upload capability rejected")

    partial_path = config.quarantine_root / f"{upload_id}.part"
    final_path = config.quarantine_root / f"{upload_id}.raw"
    digest = hashlib.sha256()
    received = 0
    prefix = b""
    try:
        with partial_path.open("xb") as handle:
            os.chmod(partial_path, 0o600)
            while received < content_length:
                chunk = stream.read(min(65_536, content_length - received))
                if not chunk:
                    break
                if not prefix:
                    prefix = chunk[:32]
                received += len(chunk)
                if received > config.max_upload_bytes:
                    raise UploadRejected("upload exceeded size limit")
                digest.update(chunk)
                handle.write(chunk)
        actual_sha = digest.hexdigest()
        if received != content_length or not hmac.compare_digest(actual_sha, content_sha256):
            raise UploadRejected("upload checksum or size mismatch")
        if not _media_matches(media_type, prefix):
            raise UploadRejected("file signature does not match declared media type")
        with partial_path.open("rb") as handle:
            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in handle.read():
                raise UploadRejected("malware test signature detected")
        os.replace(partial_path, final_path)
        os.chmod(final_path, 0o600)
        database.mark_uploaded(upload_id, final_path)
        return final_path
    except Exception:
        partial_path.unlink(missing_ok=True)
        final_path.unlink(missing_ok=True)
        database.reject_upload(upload_id, "UPLOAD_VALIDATION_FAILED")
        raise


def bytes_stream(data: bytes) -> BinaryIO:
    return io.BytesIO(data)
