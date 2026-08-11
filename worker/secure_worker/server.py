from __future__ import annotations

import hmac
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from .config import WorkerConfig
from .database import WorkerDatabase
from .processing import process_review, process_upload
from .upload import UploadRejected, accept_upload


OVERLOADED_BODY = b'{"error":"WORKER_OVERLOADED"}'


class ProcessingPool:
    """Bounded execution for background document processing.

    ``max_workers`` caps concurrent work and ``max_pending`` caps everything the
    worker has promised to do, so an upload burst is refused at the door instead
    of accumulating threads and Codex subprocesses.
    """

    def __init__(self, *, max_workers: int, max_pending: int):
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="secure-worker-job"
        )
        self._slots = threading.BoundedSemaphore(max_pending)

    def reserve(self) -> bool:
        """Claim capacity before the request body is read."""
        return self._slots.acquire(blocking=False)

    def release(self) -> None:
        self._slots.release()

    def submit(self, job: Callable[..., None], *args: Any) -> None:
        try:
            self._executor.submit(self._run, job, *args)
        except RuntimeError:
            self.release()
            raise

    def _run(self, job: Callable[..., None], *args: Any) -> None:
        try:
            job(*args)
        finally:
            self.release()

    def shutdown(self, *, wait: bool = False) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=not wait)


def _refuse_overloaded(request: Any) -> None:
    head = (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"content-type: application/json; charset=utf-8\r\n"
        b"content-length: " + str(len(OVERLOADED_BODY)).encode("ascii") + b"\r\n"
        b"retry-after: 5\r\n"
        b"cache-control: no-store\r\n"
        b"connection: close\r\n\r\n"
    )
    try:
        request.sendall(head + OVERLOADED_BODY)
    except OSError:
        # The peer is already gone; the connection is closed by the caller.
        return


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Serves requests with a hard ceiling on concurrent connections."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], handler_class: type, *, max_inflight: int):
        self._inflight = threading.BoundedSemaphore(max_inflight)
        super().__init__(address, handler_class)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._inflight.acquire(blocking=False):
            _refuse_overloaded(request)
            # Bypass this class's shutdown_request so no slot is released.
            super().shutdown_request(request)
            return
        # socketserver calls shutdown_request for us on both the success and the
        # error path, so the slot is released exactly once per accepted request.
        super().process_request(request, client_address)

    def shutdown_request(self, request: Any) -> None:
        try:
            super().shutdown_request(request)
        finally:
            self._inflight.release()


class SecureWorkerHandler(BaseHTTPRequestHandler):
    server_version = "CrossbeamSecureWorker/0.1"
    config: WorkerConfig
    pool: ProcessingPool
    # Bounds how long a slow or stalled peer may hold a connection slot.
    timeout = 30

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

    def _overloaded(self) -> None:
        body = json.dumps({"error": "WORKER_OVERLOADED"}).encode("utf-8")
        self.send_response(HTTPStatus.SERVICE_UNAVAILABLE)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.send_header("retry-after", "5")
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
        # Reserve processing capacity before reading the body, so an overloaded
        # worker never writes a quarantine file it cannot analyze.
        if not self.pool.reserve():
            self._overloaded()
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
            self.pool.release()
            self._json(HTTPStatus.BAD_REQUEST, {"error": "UPLOAD_REJECTED"})
            return
        except BaseException:
            self.pool.release()
            raise

        self.pool.submit(_process_without_leaking_errors, self.config, upload_id)
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
        if not self.pool.reserve():
            self._overloaded()
            return
        run_id = path.removeprefix("/review/")
        try:
            process_review(self.config, run_id)
        except Exception:
            self._json(HTTPStatus.CONFLICT, {"error": "REVIEW_NOT_READY"})
            return
        finally:
            self.pool.release()
        self._json(HTTPStatus.OK, {"analysisRunId": run_id, "state": "completed"})


def _process_without_leaking_errors(config: WorkerConfig, upload_id: str) -> None:
    try:
        process_upload(config, upload_id)
    except Exception:
        # The state and a bounded error code are stored in the private database.
        return


def create_server(config: WorkerConfig) -> BoundedThreadingHTTPServer:
    WorkerDatabase(config.database_path).validate_schema()
    pool = ProcessingPool(
        max_workers=config.max_processing_workers,
        max_pending=config.max_pending_jobs,
    )
    handler = type(
        "BoundSecureWorkerHandler",
        (SecureWorkerHandler,),
        {"config": config, "pool": pool, "timeout": config.request_timeout_seconds},
    )
    server = BoundedThreadingHTTPServer(
        (config.bind_host, config.bind_port),
        handler,
        max_inflight=config.max_inflight_requests,
    )
    server.processing_pool = pool  # type: ignore[attr-defined]
    return server


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
        server.processing_pool.shutdown()  # type: ignore[attr-defined]
        server.server_close()


if __name__ == "__main__":
    main()
