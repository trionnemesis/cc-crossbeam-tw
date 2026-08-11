"""Server-issued run identity and human approval records.

Audit evidence is only worth something if a caller cannot author it. Everything in
this module is minted or computed by the server: run IDs come from the system CSPRNG,
digests are taken over artifacts the server itself produced, and an approval exists
only when :meth:`ProvenanceLedger.record_approval` was called with a human identity
that the caller had already authenticated.

Deliberately *not* exposed as MCP tools: an MCP client is the agent, so letting it
record its own approval would only launder an assertion into evidence.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any


PROVENANCE_ISSUER = "tw-law-mcp-server"

STATUS_VERIFIED = "server_verified"
STATUS_UNKNOWN_RUN = "unknown_run"
STATUS_ARTIFACTS_MODIFIED = "artifacts_modified"
STATUS_UNBOUND = "unbound_run"

CONFIRMATION_APPROVED = "server_approved"
CONFIRMATION_UNAPPROVED = "unapproved"


def canonical_digest(value: Any) -> str:
    """SHA-256 over a canonical JSON encoding, stable across processes."""
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def artifact_digests(artifacts: dict[str, Any]) -> dict[str, str]:
    return {name: canonical_digest(value) for name, value in artifacts.items()}


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    input_digest: str
    artifact_digests: dict[str, str]
    issued_at: float
    origin: str


@dataclass(frozen=True)
class ApprovalRecord:
    run_id: str
    question_key: str
    approved_by: str
    answer_digest: str
    artifact_digest: str
    approved_at: float


class ProvenanceLedger:
    """Immutable-after-issuance run and approval records, bounded in size."""

    def __init__(self, max_runs: int = 512):
        self._lock = threading.Lock()
        self._runs: dict[str, RunRecord] = {}
        self._approvals: dict[str, dict[str, ApprovalRecord]] = {}
        self._max_runs = max_runs

    def mint_run_id(self) -> str:
        """A run ID the caller could not have predicted or chosen."""
        return f"run_{secrets.token_hex(16)}"

    def register_issued_run(
        self, *, run_id: str, input_digest: str, artifacts: dict[str, Any]
    ) -> RunRecord:
        """Record a run the server just produced.

        Separate from minting because the run ID is embedded in ``run_meta.json``
        before the artifacts are digested, so the digests cover it.
        """
        return self._register(
            run_id=run_id,
            input_digest=input_digest,
            digests=artifact_digests(artifacts),
            origin="issued",
        )

    def restore_run(self, *, run_id: str, input_digest: str, artifacts: dict[str, Any]) -> RunRecord:
        """Re-register a run from a trusted private store.

        Only for callers that persisted the server's own artifacts themselves (the
        secure worker's private database). Never reachable from the MCP tool surface,
        because a remote caller replaying its own artifacts would prove nothing.
        """
        return self._register(
            run_id=run_id,
            input_digest=input_digest,
            digests=artifact_digests(artifacts),
            origin="restored",
        )

    def _register(
        self, *, run_id: str, input_digest: str, digests: dict[str, str], origin: str
    ) -> RunRecord:
        record = RunRecord(
            run_id=run_id,
            input_digest=input_digest,
            artifact_digests=digests,
            issued_at=time.time(),
            origin=origin,
        )
        with self._lock:
            existing = self._runs.get(run_id)
            if existing is not None:
                # Issued records never change; a replay returns the original.
                return existing
            self._runs[run_id] = record
            self._evict_locked()
        return record

    def _evict_locked(self) -> None:
        while len(self._runs) > self._max_runs:
            oldest = next(iter(self._runs))
            self._runs.pop(oldest, None)
            self._approvals.pop(oldest, None)

    def get_run(self, run_id: str | None) -> RunRecord | None:
        if not run_id:
            return None
        with self._lock:
            return self._runs.get(run_id)

    def verify_artifacts(self, run_id: str | None, artifacts: dict[str, Any]) -> str:
        """Compare caller-returned artifacts against what the server issued."""
        if not run_id:
            return STATUS_UNBOUND
        record = self.get_run(run_id)
        if record is None:
            return STATUS_UNKNOWN_RUN
        if artifact_digests(artifacts) != record.artifact_digests:
            return STATUS_ARTIFACTS_MODIFIED
        return STATUS_VERIFIED

    def record_approval(
        self,
        *,
        run_id: str,
        question_key: str,
        approved_by: str,
        answer: Any,
        artifacts: dict[str, Any],
    ) -> ApprovalRecord:
        """Bind one human decision to a run, an identity and an artifact digest.

        ``approved_by`` must already be an authenticated identity; this ledger
        records it, it does not establish it.
        """
        if not run_id:
            raise ValueError("approval requires a server-issued run id")
        if not approved_by:
            raise ValueError("approval requires an authenticated human identity")
        if self.get_run(run_id) is None:
            raise ValueError("approval requires a known run")
        record = ApprovalRecord(
            run_id=run_id,
            question_key=question_key,
            approved_by=approved_by,
            answer_digest=canonical_digest(answer),
            artifact_digest=canonical_digest(artifacts),
            approved_at=time.time(),
        )
        with self._lock:
            self._approvals.setdefault(run_id, {})[question_key] = record
        return record

    def approvals_for(self, run_id: str | None) -> dict[str, ApprovalRecord]:
        if not run_id:
            return {}
        with self._lock:
            return dict(self._approvals.get(run_id, {}))
