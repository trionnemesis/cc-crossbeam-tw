"""Reversible, opt-in TXT masking core (``cb.mask.v1``) -- issue #28, PR A.

STATUS: API SKELETON (STDD red phase). Constants, the exception class and the
record layouts are real; every behavioural function and method raises
``NotImplementedError`` on purpose. The specification is
``docs/ADR-0003-reversible-masking.md`` and its executable form is
``tests/test_reversible_masking.py``. The green phase fills the bodies in and
replaces the two placeholder version constants with derived values.

Boundaries (ADR-0003, "What PR A does not do"): RAM only, no persistence, no
endpoint, no MCP tool, no model call, not wired into ``process_upload``, UTF-8
TXT only, standard library only. The legacy ``masking.mask_sensitive_text`` API
is untouched; this module is a separate opt-in API and is not exported from the
package ``__init__``.

Public surface (everything else is private):

* ``mask_document(original, binding, *, retention_deadline=None)`` ->
  ``(SafeMaskedDocument, PrivateManifest)``
* ``check_release_text(text, manifest)`` -- outbound / release scan.
* ``restore_original(masked, manifest, binding)`` -- Mode A (byte-exact,
  in-place) restore; Mode B (template slots) is deferred to PR C.
* ``InMemoryManifestRegistry`` -- RAM stand-in for the PR B vault.

Errors: ``ReversibleMaskingError`` carries a stable code and nothing else;
``residual_pii.ResidualPiiBlocked`` is re-raised unchanged for residual PII.
Neither may carry raw values, ``__cause__`` or ``__context__``.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Iterable, Mapping, Sequence

from .masking import NON_NAME_TERMS, PATTERNS

__all__ = [
    "DETECTOR_VERSION",
    "ENTITY_TYPES",
    "ERROR_CODES",
    "InMemoryManifestRegistry",
    "LABEL_RULES",
    "MAX_DOCUMENT_BYTES",
    "MAX_OCCURRENCES",
    "PARSER_VERSION",
    "POLICY_VERSION",
    "DocumentBinding",
    "Occurrence",
    "PrivateBytes",
    "PrivateManifest",
    "ReversibleMaskingError",
    "SCHEMA_VERSION",
    "SafeMaskedDocument",
    "TOKEN_RE",
    "check_release_text",
    "derive_detector_version",
    "derive_policy_version",
    "mask_document",
    "restore_original",
]

SCHEMA_VERSION = "cb.mask.v1"
PARSER_VERSION = "txt-utf8-strict/1"
RESOLUTION_POLICY_ID = "span-resolution/1"

# Limits are read from the module globals at call time so tests can lower them.
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
MAX_OCCURRENCES = 999_999

NAMESPACE_LENGTH = 28
SEQUENCE_DIGITS = 6
RESERVED_PREFIX = "[[CB"
RESTORE_ORIGINAL_IN_PLACE = "original_in_place"
RESTORE_MASKED_ONLY = "masked_only"

# [[CB1:<TYPE>:<NAMESPACE>:<SEQ>]] -- see ADR-0003 "Token grammar".
TOKEN_RE = re.compile(r"\[\[CB1:([A-Z][A-Z_]{0,31}):([a-z]{28}):([0-9]{6})\]\]")
# Opaque identifiers (binding fields, occurrence/entity ids). Always evaluated
# with ``fullmatch``: a trailing newline must not be accepted.
OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

# Keys must equal the ``masking.PATTERNS`` class names (a test enforces it).
ENTITY_TYPES: Mapping[str, str] = MappingProxyType(
    {
        "name": "PERSON",
        "personal_name": "PERSON",
        "taiwan_id": "NATIONAL_ID",
        "tax_id": "TAX_ID",
        "passport_or_resident_id": "IDENTITY_DOCUMENT",
        "email": "EMAIL",
        "mobile": "PHONE",
        "landline": "PHONE",
        "birth_date": "BIRTH_DATE",
        "parcel_id": "PARCEL_ID",
        "bank_or_case_id": "ACCOUNT_OR_CASE_ID",
        "address": "ADDRESS",
    }
)

# Leading field label that is kept in the output; only the value is masked.
# Each rule is applied anchored at the start of the detector match
# (``rule.match(text, start, end)``). No rule match -> the whole match is the
# value. A rule that would leave an empty value is ignored.
LABEL_RULES: Mapping[str, re.Pattern[str]] = MappingProxyType(
    {
        "name": re.compile(r"(?:申請人|業主|所有權人|聯絡人|姓名|承辦人)\s*(?:為|[:：])?\s*"),
        "tax_id": re.compile(r"(?:營業人統編|統一編號|統編)\s*[:：]?\s*"),
        "passport_or_resident_id": re.compile(r"(?:護照|居留證)(?:號碼|號)?\s*[:：]?\s*"),
        "birth_date": re.compile(
            r"(?:出生年月日|出生日期|出生|生日|D\.?O\.?B\.?)\s*(?:為|[:：])?\s*",
            re.IGNORECASE,
        ),
        "parcel_id": re.compile(r"(?:地號|建號)\s*[:：]?\s*"),
        "bank_or_case_id": re.compile(r"(?:銀行帳號|帳戶號碼|案件編號|申請案號)\s*[:：]?\s*"),
        "address": re.compile(r"[\u3400-\u9fff]{0,6}(?:地址|住址|地點|位置)\s*(?:為|[:：])?\s*"),
    }
)

# Every code a ReversibleMaskingError may carry. ADR-0003 "Error codes" lists
# the same set and a test keeps both in sync. Residual PII is reported with the
# existing ``residual_pii.ResidualPiiBlocked`` ("RESIDUAL_PII_BLOCKED"), which
# is deliberately not part of this set.
ERROR_CODES: frozenset[str] = frozenset(
    {
        "INVALID_INPUT_TYPE",
        "DOCUMENT_TOO_LARGE",
        "INVALID_UTF8",
        "INVALID_BINDING",
        "INVALID_RETENTION_DEADLINE",
        "RESERVED_TOKEN_COLLISION",
        "SPAN_CONFLICT",
        "TOO_MANY_OCCURRENCES",
        "MALFORMED_TOKEN",
        "UNKNOWN_TOKEN",
        "DUPLICATE_TOKEN",
        "MISSING_TOKEN",
        "TOKEN_POSITION_MISMATCH",
        "BINDING_MISMATCH",
        "RESTORE_NOT_PERMITTED",
        "MASKED_DIGEST_MISMATCH",
        "MANIFEST_INVALID",
        "RESTORE_DIGEST_MISMATCH",
        "VERSION_CONTENT_MISMATCH",
        "MAPPING_UNAVAILABLE",
        "LEGACY_MAPPING_UNAVAILABLE",
    }
)

# PLACEHOLDERS. Green phase: derive at import, e.g.
#   DETECTOR_VERSION = derive_detector_version()
#   POLICY_VERSION = derive_policy_version()
# Format: "det-" / "pol-" + 16 lowercase hex characters (ADR-0003 "Versions").
DETECTOR_VERSION = "det-unimplemented"
POLICY_VERSION = "pol-unimplemented"


class ReversibleMaskingError(ValueError):
    """A refusal with a stable code and nothing else.

    ``str(err) == err.code`` and ``err.args == (code,)``. Raise it outside any
    ``except`` block so that ``__cause__`` and ``__context__`` stay ``None``: a
    ``UnicodeDecodeError`` holds the whole raw input in ``.object``.
    """

    code: str

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DocumentBinding:
    """Trusted case / document / immutable-version binding.

    Green phase: ``__post_init__`` validates each field with
    ``OPAQUE_ID_RE.fullmatch`` (a non-``str`` is invalid too) and raises
    ``ReversibleMaskingError("INVALID_BINDING")``.
    """

    case_id: str
    document_id: str
    document_version: str


@dataclass(frozen=True, kw_only=True)
class SafeMaskedDocument:
    """What may cross the trust boundary: no value, no original digest, no offsets."""

    schema_version: str
    manifest_id: str
    binding: DocumentBinding
    masked_text: str
    masked_sha256: str
    mask_counts: Mapping[str, int]
    occurrence_count: int
    parser_version: str
    policy_version: str
    detector_version: str
    status: str = "masked"

    @property
    def masked_bytes(self) -> bytes:
        raise NotImplementedError("SafeMaskedDocument.masked_bytes")

    def outbound_payload(self) -> dict[str, object]:
        """Simulated model allowlist: exactly schema_version, masked_text, mask_counts."""
        raise NotImplementedError("SafeMaskedDocument.outbound_payload")


class PrivateBytes:
    """The exact original bytes of one occurrence; never printed, pickled or iterated."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        self._data = data

    def reveal(self) -> bytes:
        raise NotImplementedError("PrivateBytes.reveal")

    def __len__(self) -> int:
        raise NotImplementedError("PrivateBytes.__len__")

    def __repr__(self) -> str:
        raise NotImplementedError("PrivateBytes.__repr__")

    def __str__(self) -> str:
        raise NotImplementedError("PrivateBytes.__str__")

    def __reduce__(self) -> object:
        raise NotImplementedError("PrivateBytes.__reduce__")


@dataclass(frozen=True, kw_only=True, repr=False)
class Occurrence:
    """One masked span. Offsets are 0-based, end-exclusive UTF-8 BYTE offsets."""

    occurrence_id: str
    token: str
    entity_id: str
    entity_type: str
    detector_class: str
    original_byte_start: int
    original_byte_end: int
    masked_byte_start: int
    masked_byte_end: int
    original_value: PrivateBytes
    segment_id: str = "body"

    def __repr__(self) -> str:
        raise NotImplementedError("Occurrence.__repr__")

    def __str__(self) -> str:
        raise NotImplementedError("Occurrence.__str__")


@dataclass(frozen=True, kw_only=True, repr=False)
class PrivateManifest:
    """Private mapping for one immutable masking run. RAM only in PR A."""

    schema_version: str
    manifest_id: str
    binding: DocumentBinding
    token_namespace: str
    original_sha256: str
    masked_sha256: str
    parser_version: str
    policy_version: str
    detector_version: str
    bom: bool
    occurrences: tuple[Occurrence, ...]
    encoding: str = "utf-8"
    newline_policy: str = "preserve"
    restore_policy: str = RESTORE_ORIGINAL_IN_PLACE
    retention_deadline: float | None = None
    key_id: str | None = None

    def __repr__(self) -> str:
        raise NotImplementedError("PrivateManifest.__repr__")

    def __str__(self) -> str:
        raise NotImplementedError("PrivateManifest.__str__")

    def __reduce__(self) -> object:
        raise NotImplementedError("PrivateManifest.__reduce__")


def derive_detector_version(
    patterns: Sequence[tuple[str, re.Pattern[str]]] = PATTERNS,
    non_name_terms: Iterable[str] = NON_NAME_TERMS,
) -> str:
    """``"det-" + sha256(ordered name/pattern/flags + sorted terms)[:16]``."""
    raise NotImplementedError("derive_detector_version")


def derive_policy_version(
    label_rules: Mapping[str, re.Pattern[str]] = LABEL_RULES,
    entity_types: Mapping[str, str] = ENTITY_TYPES,
    resolution_policy_id: str = RESOLUTION_POLICY_ID,
) -> str:
    """``"pol-" + sha256(label rules + entity map + resolution policy id)[:16]``."""
    raise NotImplementedError("derive_policy_version")


def mask_document(
    original: bytes,
    binding: DocumentBinding,
    *,
    retention_deadline: float | None = None,
) -> tuple[SafeMaskedDocument, PrivateManifest]:
    """Mask one UTF-8 TXT document. Nothing partial is returned on any failure."""
    raise NotImplementedError("mask_document")


def check_release_text(text: str, manifest: PrivateManifest) -> None:
    """Outbound / release scan: only tokens issued by this manifest, rest scanned."""
    raise NotImplementedError("check_release_text")


def restore_original(masked: bytes, manifest: PrivateManifest, binding: DocumentBinding) -> bytes:
    """Mode A: byte-exact in-place restore, bytes returned only after every check."""
    raise NotImplementedError("restore_original")


class InMemoryManifestRegistry:
    """RAM stand-in for the PR B vault; the trusted load path. Never hands out manifests."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock

    def issue(
        self,
        original: bytes,
        binding: DocumentBinding,
        *,
        retention_deadline: float | None = None,
    ) -> SafeMaskedDocument:
        raise NotImplementedError("InMemoryManifestRegistry.issue")

    def restore_original(
        self,
        masked: bytes,
        *,
        manifest_id: str | None,
        binding: DocumentBinding,
    ) -> bytes:
        raise NotImplementedError("InMemoryManifestRegistry.restore_original")

    def discard(self, manifest_id: str) -> None:
        raise NotImplementedError("InMemoryManifestRegistry.discard")
