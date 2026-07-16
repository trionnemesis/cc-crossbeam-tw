from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = REPO_ROOT / ".runtime"


def _private_runtime_path(raw: str, *, directory: bool) -> Path:
    RUNTIME_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(RUNTIME_ROOT, 0o700)
    trusted_root = RUNTIME_ROOT.resolve(strict=True)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    candidate = candidate.resolve(strict=False)
    if candidate != trusted_root and trusted_root not in candidate.parents:
        raise ValueError("worker paths must stay inside the private runtime directory")
    if directory:
        candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(candidate, 0o700)
        return candidate.resolve(strict=True)
    if candidate.parent.resolve(strict=True) != trusted_root:
        raise ValueError("database must be a direct child of the private runtime directory")
    return candidate


def _allowed_origin(value: str, mode: str) -> str:
    parsed = urlparse(value)
    if mode == "local":
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("local worker origin must use a loopback host")
    elif mode == "single-user":
        if parsed.scheme != "https":
            raise ValueError("single-user worker origin must use HTTPS")
        if not parsed.hostname:
            raise ValueError("single-user worker origin requires a hostname")
    else:
        raise ValueError("Codex-auth worker is not allowed in production mode")
    return value.rstrip("/")


def _load_or_create_internal_secret() -> str:
    RUNTIME_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_path = RUNTIME_ROOT / "worker-internal-secret"
    try:
        descriptor = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(secrets.token_urlsafe(48))
    os.chmod(secret_path, 0o600)
    return secret_path.read_text(encoding="utf-8").strip()


@dataclass(frozen=True)
class WorkerConfig:
    database_path: Path
    quarantine_root: Path
    sanitized_root: Path
    allowed_origin: str
    bind_host: str = "127.0.0.1"
    bind_port: int = 8787
    max_upload_bytes: int = 25 * 1024 * 1024
    codex_enabled: bool = False
    internal_secret: str = "test-internal-secret"

    @classmethod
    def from_environment(cls, environment: dict[str, str] | None = None) -> "WorkerConfig":
        env = environment if environment is not None else os.environ
        app_mode = env.get("APP_MODE", "local")
        bind_host = env.get("WORKER_BIND_HOST", "127.0.0.1")
        if bind_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("local worker must bind to loopback")
        port = int(env.get("WORKER_BIND_PORT", "8787"))
        if port < 1024 or port > 65535:
            raise ValueError("invalid worker port")
        return cls(
            database_path=_private_runtime_path(
                env.get("DATABASE_PATH", ".runtime/secure-web.sqlite"), directory=False
            ),
            quarantine_root=_private_runtime_path(
                env.get("QUARANTINE_ROOT", ".runtime/quarantine"), directory=True
            ),
            sanitized_root=_private_runtime_path(
                env.get("SANITIZED_ROOT", ".runtime/sanitized"), directory=True
            ),
            allowed_origin=_allowed_origin(
                env.get("APP_ORIGIN", "http://127.0.0.1:3000"), app_mode
            ),
            bind_host=bind_host,
            bind_port=port,
            codex_enabled=env.get("CODEX_WORKER_ENABLED", "false").lower() == "true",
            internal_secret=_load_or_create_internal_secret(),
        )
