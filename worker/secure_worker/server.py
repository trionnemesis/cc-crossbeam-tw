from __future__ import annotations

import hmac
import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import WorkerConfig
from .database import WorkerDatabase
from .processing import process_review, process_upload
from .upload import UploadRejected, accept_upload


class SecureWorkerHandler(BaseHTTPRequestHandler):
    server_version = "CrossbeamSecureWorker/0.1"
    config: WorkerConfig

    def log_message(self, _format: str, *_args: object) -> None:
        # Request paths contain bearer upload capabilities and must never be logged.
        return

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        origin = self.headers.get("origin")
        if origin == self.config.allowed_origin:
            self.send_header("access-control-allow-origin", origin)
            self.send_header("vary", "origin")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/health":
            self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            return
        self._json(HTTPStatus.OK, {"status": "ok", "storage": "private-local"})

    def do_OPTIONS(self) -> None:  # noqa: N802
        origin = self.headers.get("origin")
        if origin != self.config.allowed_origin:
            self._json(HTTPStatus.FORBIDDEN, {"error": "ORIGIN_REJECTED"})
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("access-control-allow-origin", origin)
        self.send_header("access-control-allow-methods", "PUT, OPTIONS")
        self.send_header(
            "access-control-allow-headers",
            "content-type, x-content-sha256, x-upload-id",
        )
        self.send_header("access-control-max-age", "600")
        self.send_header("vary", "origin")
        self.end_headers()

    def do_PUT(self) -> None:  # noqa: N802
        origin = self.headers.get("origin")
        if origin != self.config.allowed_origin:
            self._json(HTTPStatus.FORBIDDEN, {"error": "ORIGIN_REJECTED"})
            return
        path = urlparse(self.path).path
        if not path.startswith("/upload/"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            return
        token = path.removeprefix("/upload/")
        upload_id = self.headers.get("x-upload-id", "")
        media_type = self.headers.get("content-type", "").split(";", 1)[0]
        content_sha256 = self.headers.get("x-content-sha256", "")
        try:
            content_length = int(self.headers.get("content-length", "0"))
            accept_upload(
                self.config,
                token=token,
                upload_id=upload_id,
                media_type=media_type,
                content_length=content_length,
                content_sha256=content_sha256,
                stream=self.rfile,
            )
        except (ValueError, UploadRejected):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "UPLOAD_REJECTED"})
            return

        threading.Thread(
            target=_process_without_leaking_errors,
            args=(self.config, upload_id),
            daemon=True,
        ).start()
        self._json(HTTPStatus.CREATED, {"uploadId": upload_id, "state": "uploaded"})

    def do_POST(self) -> None:  # noqa: N802
        if self.headers.get("origin"):
            self._json(HTTPStatus.FORBIDDEN, {"error": "SERVER_REQUEST_REQUIRED"})
            return
        provided = self.headers.get("x-worker-internal-secret", "")
        if not hmac.compare_digest(provided, self.config.internal_secret):
            self._json(HTTPStatus.FORBIDDEN, {"error": "INTERNAL_AUTH_REJECTED"})
            return
        path = urlparse(self.path).path
        if not path.startswith("/review/"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            return
        run_id = path.removeprefix("/review/")
        try:
            process_review(self.config, run_id)
        except Exception:
            self._json(HTTPStatus.CONFLICT, {"error": "REVIEW_NOT_READY"})
            return
        self._json(HTTPStatus.OK, {"analysisRunId": run_id, "state": "completed"})


def _process_without_leaking_errors(config: WorkerConfig, upload_id: str) -> None:
    try:
        process_upload(config, upload_id)
    except Exception:
        # The state and a bounded error code are stored in the private database.
        return


def create_server(config: WorkerConfig) -> ThreadingHTTPServer:
    WorkerDatabase(config.database_path).validate_schema()
    handler = type("BoundSecureWorkerHandler", (SecureWorkerHandler,), {"config": config})
    return ThreadingHTTPServer((config.bind_host, config.bind_port), handler)


def main() -> None:
    config = WorkerConfig.from_environment()
    server = create_server(config)
    print(
        json.dumps(
            {"status": "ready", "address": f"http://{config.bind_host}:{config.bind_port}"}
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
