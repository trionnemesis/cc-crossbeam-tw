"""Reversible, opt-in TXT masking core (``cb.mask.v1``) for issue #28, PR A.

``masking.mask_sensitive_text`` swaps each match for ``[MASKED_<CLASS>]`` and keeps nothing,
so a masked document can never be turned back. This module is the separate, opt-in API for
the cases that must get the original back: it masks one UTF-8 TXT document into unique
per-occurrence tokens and keeps the exact original bytes, with their positions, in a private
manifest. ``restore_original`` then puts them back in place, byte for byte, or refuses.

Everything lives in process memory. It is not wired into ``process_upload`` and has no
endpoint, tool, model path or persistence. ``docs/ADR-0003-reversible-masking.md`` is the
specification and ``tests/test_reversible_masking.py`` is its executable form.

Failures raise ``ReversibleMaskingError`` (a stable code and nothing else) or the existing
``residual_pii.ResidualPiiBlocked``. Neither may carry a raw value, a ``__cause__`` or a
``__context__``, so every refusal is raised outside any ``except`` block.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import string
import threading
import time
import uuid
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Iterable, Mapping, Sequence

from .masking import NON_NAME_TERMS, PATTERNS, _is_masked_class
from .residual_pii import ResidualPiiBlocked, find_residual_sensitive_classes

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
# Names the four span-resolution rules, so POLICY_VERSION changes if they ever do.
RESOLUTION_POLICY_ID = "span-resolution/1"

# Read from the module at call time, so a test (or an operator) can lower them.
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
MAX_OCCURRENCES = 999_999

NAMESPACE_LENGTH = 28
SEQUENCE_DIGITS = 6
RESERVED_PREFIX = "[[CB"
RESTORE_ORIGINAL_IN_PLACE = "original_in_place"
RESTORE_MASKED_ONLY = "masked_only"

# [[CB1:<TYPE>:<NAMESPACE>:<SEQ>]]. The namespace is letters only on purpose: digit runs in a
# hex namespace trip the phone and identity patterns of residual_pii, so valid output would
# fail its own release scan at random (about 3 % of tokens measured).
TOKEN_RE = re.compile(r"\[\[CB1:([A-Z][A-Z_]{0,31}):([a-z]{28}):([0-9]{6})\]\]")
# Binding fields and occurrence/entity ids. Always used with fullmatch: "$" would let a
# trailing newline through.
OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

# Keys must equal the masking.PATTERNS class names (a test enforces it). The type is what a
# token tells a reader; the detector class stays in the private manifest.
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

# Several detectors match a field label together with its value ("申請人：王大明"). The label
# is what the correction rules read, so it stays and only the value is masked. A rule is
# applied anchored at the start of the detector match; no match (or a match that would leave
# no value) means the whole match is the value, which over-masks rather than under-masks.
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

# Every code a ReversibleMaskingError may carry; the ADR lists the same set and a test keeps
# both in sync. Residual PII is reported with the existing ResidualPiiBlocked instead.
ERROR_CODES: frozenset[str] = frozenset(
    {
        # input
        "INVALID_INPUT_TYPE",
        "DOCUMENT_TOO_LARGE",
        "INVALID_UTF8",
        "INVALID_BINDING",
        "INVALID_RETENTION_DEADLINE",
        # masking
        "RESERVED_TOKEN_COLLISION",
        "SPAN_CONFLICT",
        "TOO_MANY_OCCURRENCES",
        # token scan (release scan and restore)
        "MALFORMED_TOKEN",
        "UNKNOWN_TOKEN",
        "DUPLICATE_TOKEN",
        "MISSING_TOKEN",
        "TOKEN_POSITION_MISMATCH",
        # restore
        "BINDING_MISMATCH",
        "RESTORE_NOT_PERMITTED",
        "MASKED_DIGEST_MISMATCH",
        "MANIFEST_INVALID",
        "RESTORE_DIGEST_MISMATCH",
        # registry
        "VERSION_CONTENT_MISMATCH",
        "MAPPING_UNAVAILABLE",
        "LEGACY_MAPPING_UNAVAILABLE",
    }
)

_BOM = b"\xef\xbb\xbf"
# The release scan and the reserved-prefix check look for the same thing: anything that could
# be read as a token, in any case.
_TOKEN_PREFIX_RE = re.compile(re.escape(RESERVED_PREFIX), re.IGNORECASE)
_NAMESPACE_RE = re.compile(r"[a-z]{28}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
# What mask_sensitive_text left behind: an exact marker for one of the PATTERNS classes.
_LEGACY_MARKER_RE = re.compile(
    rb"\[MASKED_(?:" + b"|".join(name.upper().encode("ascii") for name, _ in PATTERNS) + rb")\]"
)


class ReversibleMaskingError(ValueError):
    """A refusal with a stable code and nothing else.

    ``str(err) == err.code`` and ``err.args == (code,)``. Raise it outside any ``except``
    block: a ``UnicodeDecodeError`` holds the whole raw input in ``.object`` and must never
    become ``__context__``.
    """

    code: str

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _is_opaque_id(value: object) -> bool:
    return isinstance(value, str) and OPAQUE_ID_RE.fullmatch(value) is not None


@dataclass(frozen=True)
class DocumentBinding:
    """Trusted case / document / immutable-version binding.

    Only identifier-shaped values are accepted, which keeps free text (and so personal data)
    out of ids that the safe document carries.
    """

    case_id: str
    document_id: str
    document_version: str

    def __post_init__(self) -> None:
        if not all(
            _is_opaque_id(v) for v in (self.case_id, self.document_id, self.document_version)
        ):
            raise ReversibleMaskingError("INVALID_BINDING")


@dataclass(frozen=True, kw_only=True)
class SafeMaskedDocument:
    """What may cross the trust boundary: no value, no original digest, no original offset."""

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
        return self.masked_text.encode("utf-8")

    def outbound_payload(self) -> dict[str, object]:
        """The simulated model allowlist: a fresh dict, so a caller cannot reach back in."""
        return {
            "schema_version": self.schema_version,
            "masked_text": self.masked_text,
            "mask_counts": dict(self.mask_counts),
        }


class PrivateBytes:
    """The exact original bytes of one occurrence; never printed, pickled or iterated."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("PrivateBytes holds bytes")
        # Copy: a caller's bytearray must not be able to change the value afterwards.
        self._data = bytes(data)

    def reveal(self) -> bytes:
        return self._data

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        # Not even the length: a byte count in a log line already narrows down a short value.
        return "PrivateBytes(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> object:
        # Blocks pickle, copy and deepcopy, and so dataclasses.asdict of anything holding one.
        raise TypeError("PrivateBytes cannot be serialized")


@dataclass(frozen=True, kw_only=True, repr=False)
class Occurrence:
    """One masked span. Offsets are 0-based, end-exclusive UTF-8 BYTE offsets.

    Code points and UTF-16 units are never stored: they differ from bytes as soon as a
    document holds Han text, and the restore slices bytes.
    """

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
        return f"Occurrence(occurrence_id={self.occurrence_id!r}, entity_type={self.entity_type!r})"

    __str__ = __repr__


@dataclass(frozen=True, kw_only=True, repr=False)
class PrivateManifest:
    """The private mapping of one immutable masking run. Process memory only in PR A."""

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
        # Id, schema and a count: enough to correlate a log line, nothing that maps to a value.
        return (
            f"PrivateManifest(manifest_id={self.manifest_id!r}, schema={self.schema_version!r}, "
            f"occurrences={len(self.occurrences)})"
        )

    __str__ = __repr__

    def __reduce__(self) -> object:
        raise TypeError("PrivateManifest cannot be serialized")


def _short_digest(parts: Iterable[object]) -> str:
    # One JSON line per part keeps field boundaries unambiguous.
    digest = hashlib.sha256()
    for part in parts:
        digest.update(json.dumps(part, ensure_ascii=True).encode("ascii") + b"\n")
    return digest.hexdigest()[:16]


def derive_detector_version(
    patterns: Sequence[tuple[str, re.Pattern[str]]] = PATTERNS,
    non_name_terms: Iterable[str] = NON_NAME_TERMS,
) -> str:
    """Changes when a pattern's name, text, flags or position, or the vocabulary filter, changes."""
    parts: list[object] = [["detector", 1]]
    parts += [[name, pattern.pattern, int(pattern.flags)] for name, pattern in patterns]
    # Sorted: a frozenset iterates in a hash-seed dependent order.
    parts.append(["non_name_terms", sorted(non_name_terms)])
    return "det-" + _short_digest(parts)


def derive_policy_version(
    label_rules: Mapping[str, re.Pattern[str]] = LABEL_RULES,
    entity_types: Mapping[str, str] = ENTITY_TYPES,
    resolution_policy_id: str = RESOLUTION_POLICY_ID,
) -> str:
    """Changes when a label rule, the entity map or the span-resolution policy changes."""
    parts: list[object] = [["policy", 1]]
    parts += [
        ["label", name, label_rules[name].pattern, int(label_rules[name].flags)]
        for name in sorted(label_rules)
    ]
    parts += [["entity", name, entity_types[name]] for name in sorted(entity_types)]
    parts.append(["resolution", resolution_policy_id])
    return "pol-" + _short_digest(parts)


# A manifest records the versions it was made with, and the registry refuses to reuse a
# binding under different ones: old approvals and tokens must not survive a rule change.
DETECTOR_VERSION = derive_detector_version()
POLICY_VERSION = derive_policy_version()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_equal(left: object, right: object) -> bool:
    if not (isinstance(left, str) and isinstance(right, str)):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _decode_strict(data: bytes) -> str | None:
    # Returns None instead of raising so that the caller refuses outside this except block:
    # the UnicodeDecodeError holds the whole raw input and must not become a context.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _check_retention_deadline(value: object) -> None:
    # NaN compares false with everything, so a NaN deadline would never expire.
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ReversibleMaskingError("INVALID_RETENTION_DEADLINE")


def _value_span(name: str, text: str, start: int, end: int) -> tuple[int, int]:
    """The part of one detector match that is the value: label kept, trailing whitespace kept out."""
    rule = LABEL_RULES.get(name)
    if rule is not None:
        label = rule.match(text, start, end)
        if label is not None and label.end() < end:
            start = label.end()
    # The birth_date pattern ends in \s*, so its match can swallow the line terminator after
    # the date. Masking that would join two lines of the safe document.
    kept = len(text[start:end].rstrip())
    if kept:
        end = start + kept
    return start, end


def _resolve_spans(text: str) -> list[tuple[int, int, str]]:
    """Disjoint value spans as (start, end, detector class), in code points of ``text``.

    Every pattern runs over the same original text, never over replaced text, so every offset
    is an original offset. Identical spans keep the lowest PATTERNS index, a span inside another
    is absorbed by it, and a partial overlap refuses the document: merging would invent a type,
    shrinking would mask less than a detector asked for.
    """
    best: dict[tuple[int, int], tuple[int, str]] = {}
    for priority, (name, pattern) in enumerate(PATTERNS):
        for match in pattern.finditer(text):
            if not _is_masked_class(name, match.group(0)):
                continue
            span = _value_span(name, text, match.start(), match.end())
            if span not in best or priority < best[span][0]:
                best[span] = (priority, name)
    # Longest first at equal starts, so an outer span is seen before anything inside it.
    ordered = sorted(best.items(), key=lambda item: (item[0][0], -item[0][1]))
    kept: list[tuple[int, int, str]] = []
    for (start, end), (_priority, name) in ordered:
        if kept and start < kept[-1][1]:
            if end <= kept[-1][1]:
                continue
            raise ReversibleMaskingError("SPAN_CONFLICT")
        kept.append((start, end, name))
    return kept


def _byte_offsets(text: str, positions: Iterable[int]) -> dict[int, int]:
    """Code-point index -> UTF-8 byte offset, in one linear pass.

    Encoding ``text[:i]`` for every span would be quadratic on a large document.
    """
    offsets: dict[int, int] = {}
    cursor = total = 0
    for position in sorted(set(positions)):
        total += len(text[cursor:position].encode("utf-8"))
        cursor = position
        offsets[position] = total
    return offsets


def _make_token(entity_type: str, namespace: str, sequence: int) -> str:
    return f"[[CB1:{entity_type}:{namespace}:{sequence:0{SEQUENCE_DIGITS}d}]]"


def mask_document(
    original: bytes,
    binding: DocumentBinding,
    *,
    retention_deadline: float | None = None,
) -> tuple[SafeMaskedDocument, PrivateManifest]:
    """Mask one UTF-8 TXT document. Nothing partial is returned on any failure."""
    if not isinstance(original, bytes):
        # No str, bytearray or memoryview: a mutable buffer could change between check and use.
        raise ReversibleMaskingError("INVALID_INPUT_TYPE")
    if not isinstance(binding, DocumentBinding):
        raise ReversibleMaskingError("INVALID_BINDING")
    _check_retention_deadline(retention_deadline)
    # Size before decoding, so an oversized input is reported as oversized.
    if len(original) > MAX_DOCUMENT_BYTES:
        raise ReversibleMaskingError("DOCUMENT_TOO_LARGE")
    text = _decode_strict(original)
    if text is None:
        raise ReversibleMaskingError("INVALID_UTF8")
    # Version 1 does not escape: a look-alike already in the document could be taken for a
    # system token, or slip past the release scan.
    if _TOKEN_PREFIX_RE.search(text):
        raise ReversibleMaskingError("RESERVED_TOKEN_COLLISION")
    spans = _resolve_spans(text)
    if len(spans) > min(MAX_OCCURRENCES, 10**SEQUENCE_DIGITS - 1):
        raise ReversibleMaskingError("TOO_MANY_OCCURRENCES")

    byte_at = _byte_offsets(
        text, [position for start, end, _ in spans for position in (start, end)]
    )
    # secrets, not random: the namespace must not be reproducible or guessable.
    namespace = "".join(secrets.choice(string.ascii_lowercase) for _ in range(NAMESPACE_LENGTH))
    counts = {name: 0 for name, _ in PATTERNS}
    occurrences: list[Occurrence] = []
    pieces: list[bytes] = []
    copied_to = 0  # original byte offset up to which the bytes are already in `pieces`
    written = 0  # masked bytes so far, i.e. the next masked offset
    for sequence, (start, end, name) in enumerate(spans, start=1):
        original_start, original_end = byte_at[start], byte_at[end]
        unchanged = original[copied_to:original_start]
        entity_type = ENTITY_TYPES[name]
        token = _make_token(entity_type, namespace, sequence)
        token_bytes = token.encode("ascii")
        pieces += [unchanged, token_bytes]
        written += len(unchanged)
        occurrences.append(
            Occurrence(
                # Random ids: nothing here is derived from the value, so equal values stay unlinked.
                occurrence_id="occ-" + uuid.uuid4().hex,
                token=token,
                entity_id="ent-" + uuid.uuid4().hex,
                entity_type=entity_type,
                detector_class=name,
                original_byte_start=original_start,
                original_byte_end=original_end,
                masked_byte_start=written,
                masked_byte_end=written + len(token_bytes),
                original_value=PrivateBytes(original[original_start:original_end]),
            )
        )
        written += len(token_bytes)
        counts[name] += 1
        copied_to = original_end
    pieces.append(original[copied_to:])
    masked = b"".join(pieces)

    manifest = PrivateManifest(
        schema_version=SCHEMA_VERSION,
        manifest_id=str(uuid.uuid4()),
        binding=binding,
        token_namespace=namespace,
        original_sha256=_sha256(original),
        masked_sha256=_sha256(masked),
        parser_version=PARSER_VERSION,
        policy_version=POLICY_VERSION,
        detector_version=DETECTOR_VERSION,
        bom=original.startswith(_BOM),
        occurrences=tuple(occurrences),
        retention_deadline=retention_deadline,
    )
    masked_text = masked.decode("utf-8")
    # Fail closed: shapes only residual_pii knows, or a token problem, stop the document here.
    check_release_text(masked_text, manifest)
    safe = SafeMaskedDocument(
        schema_version=SCHEMA_VERSION,
        manifest_id=manifest.manifest_id,
        binding=binding,
        masked_text=masked_text,
        masked_sha256=manifest.masked_sha256,
        mask_counts=MappingProxyType(counts),
        occurrence_count=len(occurrences),
        parser_version=PARSER_VERSION,
        policy_version=POLICY_VERSION,
        detector_version=DETECTOR_VERSION,
    )
    return safe, manifest


def _scan_token_candidates(text: str) -> list[tuple[int, str | None]]:
    """(character index, full-grammar token or None) for every place that could be read as a token."""
    candidates: list[tuple[int, str | None]] = []
    for prefix in _TOKEN_PREFIX_RE.finditer(text):
        token = TOKEN_RE.match(text, prefix.start())
        candidates.append((prefix.start(), token.group(0) if token else None))
    return candidates


def check_release_text(text: str, manifest: PrivateManifest) -> None:
    """Outbound / release scan: only tokens issued by this manifest, everything else scanned.

    A membership check, not a completeness check: a summary may omit or repeat tokens.
    """
    if not isinstance(text, str):
        raise ReversibleMaskingError("INVALID_INPUT_TYPE")
    if not isinstance(manifest, PrivateManifest):
        raise ReversibleMaskingError("MANIFEST_INVALID")
    issued = {occurrence.token for occurrence in manifest.occurrences}
    candidates = _scan_token_candidates(text)
    if any(token is None for _, token in candidates):
        raise ReversibleMaskingError("MALFORMED_TOKEN")
    if any(token not in issued for _, token in candidates):
        raise ReversibleMaskingError("UNKNOWN_TOKEN")
    # Nothing is skipped: a valid token is inert, and the text around it is still scanned.
    residual = find_residual_sensitive_classes(text)
    if residual:
        raise ResidualPiiBlocked(residual)


def _is_plain_int(value: object) -> bool:
    # bool is an int subclass, but True as an offset is a tampered manifest, not a position.
    return isinstance(value, int) and not isinstance(value, bool)


def _occurrence_is_well_formed(occ: object, namespace: str, sequence: int) -> bool:
    if not isinstance(occ, Occurrence) or not isinstance(occ.original_value, PrivateBytes):
        return False
    offsets = (
        occ.original_byte_start,
        occ.original_byte_end,
        occ.masked_byte_start,
        occ.masked_byte_end,
    )
    if not all(_is_plain_int(offset) for offset in offsets):
        return False
    if not isinstance(occ.detector_class, str) or not isinstance(occ.token, str):
        return False
    entity_type = ENTITY_TYPES.get(occ.detector_class)
    parts = TOKEN_RE.fullmatch(occ.token)
    return (
        entity_type is not None
        and occ.entity_type == entity_type
        and parts is not None
        and parts.group(1) == entity_type
        and parts.group(2) == namespace
        and int(parts.group(3)) == sequence
        and occ.segment_id == "body"
        and _is_opaque_id(occ.occurrence_id)
        and _is_opaque_id(occ.entity_id)
    )


def _manifest_is_consistent(manifest: PrivateManifest, masked: bytes) -> bool:
    """The structure rules of ADR-0003 (Mode A, step 6) as a yes/no.

    Python slicing never raises on a bad range, so every rule is checked explicitly. Answering
    with a bool lets the caller raise outside any except block.
    """
    if manifest.schema_version != SCHEMA_VERSION:
        return False
    if manifest.encoding != "utf-8" or manifest.newline_policy != "preserve":
        return False
    # The BOM flag is informational, but it must agree with the bytes it describes.
    if not isinstance(manifest.bom, bool) or manifest.bom != masked.startswith(_BOM):
        return False
    if not (
        isinstance(manifest.token_namespace, str)
        and _NAMESPACE_RE.fullmatch(manifest.token_namespace)
    ):
        return False
    if not (
        isinstance(manifest.original_sha256, str) and _SHA256_RE.fullmatch(manifest.original_sha256)
    ):
        return False
    if not isinstance(manifest.occurrences, tuple):
        return False

    seen_ids: set[str] = set()
    seen_entities: set[str] = set()
    seen_tokens: set[str] = set()
    previous_original_end = previous_masked_end = 0
    shift = 0  # masked offset minus original offset, from every earlier token
    for sequence, occ in enumerate(manifest.occurrences, start=1):
        if not _occurrence_is_well_formed(occ, manifest.token_namespace, sequence):
            return False
        if (
            occ.occurrence_id in seen_ids
            or occ.entity_id in seen_entities
            or occ.token in seen_tokens
        ):
            return False
        seen_ids.add(occ.occurrence_id)
        seen_entities.add(occ.entity_id)
        seen_tokens.add(occ.token)
        value_length = len(occ.original_value)
        if value_length == 0:
            return False
        # Each range must be as long as the thing it covers.
        if occ.original_byte_end - occ.original_byte_start != value_length:
            return False
        if occ.masked_byte_end - occ.masked_byte_start != len(occ.token):
            return False
        # Sorted and non-overlapping, in both coordinate systems.
        if (
            occ.original_byte_start < previous_original_end
            or occ.masked_byte_start < previous_masked_end
        ):
            return False
        # The masked offset follows from the original one; both come from one run or neither does.
        if occ.masked_byte_start != occ.original_byte_start + shift:
            return False
        if occ.masked_byte_end > len(masked):
            return False
        shift += len(occ.token) - value_length
        previous_original_end, previous_masked_end = occ.original_byte_end, occ.masked_byte_end
    return True


def _verify_tokens(text: str, manifest: PrivateManifest) -> None:
    """Restore needs the complete set: every registered token exactly once, where it was put.

    Category order is malformed, unknown, duplicate, missing, position, over the whole text.
    """
    registered = {occ.token: occ for occ in manifest.occurrences}
    candidates = _scan_token_candidates(text)
    if any(token is None for _, token in candidates):
        raise ReversibleMaskingError("MALFORMED_TOKEN")
    if any(token not in registered for _, token in candidates):
        raise ReversibleMaskingError("UNKNOWN_TOKEN")
    byte_at = _byte_offsets(text, [index for index, _ in candidates])
    found: dict[str, list[int]] = {}
    for index, token in candidates:
        found.setdefault(str(token), []).append(byte_at[index])
    if any(len(offsets) > 1 for offsets in found.values()):
        raise ReversibleMaskingError("DUPLICATE_TOKEN")
    if any(token not in found for token in registered):
        raise ReversibleMaskingError("MISSING_TOKEN")
    # Two tokens swapped are each present once; only the position gives them away.
    if any(found[token][0] != occ.masked_byte_start for token, occ in registered.items()):
        raise ReversibleMaskingError("TOKEN_POSITION_MISMATCH")


def restore_original(masked: bytes, manifest: PrivateManifest, binding: DocumentBinding) -> bytes:
    """Mode A: put the original bytes back in place, or refuse. Nothing partial is returned.

    Checks run in a fixed order and stop at the first failure (ADR-0003, Mode A). Only the
    registered spans are rewritten, from the manifest's own bytes: no search-and-replace and no
    fuzzy matching, so a token that is not exactly where it was issued can never be restored.
    """
    if not isinstance(masked, bytes):
        raise ReversibleMaskingError("INVALID_INPUT_TYPE")
    if not isinstance(manifest, PrivateManifest):
        raise ReversibleMaskingError("MANIFEST_INVALID")
    if not isinstance(binding, DocumentBinding):
        raise ReversibleMaskingError("INVALID_BINDING")
    if manifest.binding != binding:
        raise ReversibleMaskingError("BINDING_MISMATCH")
    if manifest.restore_policy != RESTORE_ORIGINAL_IN_PLACE:
        raise ReversibleMaskingError("RESTORE_NOT_PERMITTED")
    # Any edit to the masked artifact, even outside a token, ends here: this mode restores an
    # unmodified artifact and never passes a changed document off as the original.
    if not _digest_equal(_sha256(masked), manifest.masked_sha256):
        raise ReversibleMaskingError("MASKED_DIGEST_MISMATCH")
    text = _decode_strict(masked)
    if text is None:
        raise ReversibleMaskingError("INVALID_UTF8")
    if not _manifest_is_consistent(manifest, masked):
        raise ReversibleMaskingError("MANIFEST_INVALID")
    _verify_tokens(text, manifest)

    pieces: list[bytes] = []
    cursor = 0
    for occ in manifest.occurrences:
        pieces.append(masked[cursor : occ.masked_byte_start])
        pieces.append(occ.original_value.reveal())
        cursor = occ.masked_byte_end
    pieces.append(masked[cursor:])
    restored = b"".join(pieces)
    # Last line of defence, e.g. two equal-length values swapped inside the manifest pass every
    # structural check above.
    if not _digest_equal(_sha256(restored), manifest.original_sha256):
        raise ReversibleMaskingError("RESTORE_DIGEST_MISMATCH")
    return restored


class InMemoryManifestRegistry:
    """RAM stand-in for the PR B vault, and the trusted load path.

    Callers hold a ``manifest_id``, never a manifest: no method returns one. Thread-safe within
    one process. Expired and discarded manifests are gone; nothing falls back to guessing.
    """

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._manifests: dict[str, PrivateManifest] = {}
        self._safe_documents: dict[str, SafeMaskedDocument] = {}
        self._manifest_of_binding: dict[tuple[str, str, str], str] = {}

    @staticmethod
    def _binding_key(binding: DocumentBinding) -> tuple[str, str, str]:
        return (binding.case_id, binding.document_id, binding.document_version)

    def _is_expired(self, manifest: PrivateManifest) -> bool:
        deadline = manifest.retention_deadline
        return deadline is not None and self._clock() >= deadline

    def _forget(self, manifest_id: str) -> None:
        # Caller holds the lock.
        manifest = self._manifests.pop(manifest_id, None)
        self._safe_documents.pop(manifest_id, None)
        if manifest is not None:
            key = self._binding_key(manifest.binding)
            if self._manifest_of_binding.get(key) == manifest_id:
                del self._manifest_of_binding[key]

    def issue(
        self,
        original: bytes,
        binding: DocumentBinding,
        *,
        retention_deadline: float | None = None,
    ) -> SafeMaskedDocument:
        """Mask and register a document; a retry of the same immutable version is idempotent."""
        if not isinstance(original, bytes):
            raise ReversibleMaskingError("INVALID_INPUT_TYPE")
        if not isinstance(binding, DocumentBinding):
            raise ReversibleMaskingError("INVALID_BINDING")
        _check_retention_deadline(retention_deadline)
        key = self._binding_key(binding)
        digest = _sha256(original)
        # Masking happens under the lock so that two racing retries cannot both create a manifest.
        with self._lock:
            existing_id = self._manifest_of_binding.get(key)
            if existing_id is not None and self._is_expired(self._manifests[existing_id]):
                self._forget(existing_id)
                existing_id = None
            if existing_id is not None:
                manifest = self._manifests[existing_id]
                same_content = _digest_equal(manifest.original_sha256, digest)
                same_rules = (
                    manifest.parser_version == PARSER_VERSION
                    and manifest.detector_version == DETECTOR_VERSION
                    and manifest.policy_version == POLICY_VERSION
                )
                if same_content and same_rules:
                    # The first retention deadline stays: a retry must not extend it.
                    return self._safe_documents[existing_id]
                # A version is immutable; other content or rules need a new version.
                raise ReversibleMaskingError("VERSION_CONTENT_MISMATCH")
            safe, manifest = mask_document(original, binding, retention_deadline=retention_deadline)
            self._manifests[manifest.manifest_id] = manifest
            self._safe_documents[manifest.manifest_id] = safe
            self._manifest_of_binding[key] = manifest.manifest_id
            return safe

    def restore_original(
        self,
        masked: bytes,
        *,
        manifest_id: str | None,
        binding: DocumentBinding,
    ) -> bytes:
        if not isinstance(masked, bytes):
            raise ReversibleMaskingError("INVALID_INPUT_TYPE")
        if not isinstance(binding, DocumentBinding):
            raise ReversibleMaskingError("INVALID_BINDING")
        manifest = None
        with self._lock:
            if isinstance(manifest_id, str):
                manifest = self._manifests.get(manifest_id)
                if manifest is not None and self._is_expired(manifest):
                    self._forget(manifest_id)
                    manifest = None
        if manifest is None:
            # A document masked by mask_sensitive_text never had a mapping; say so, and never
            # try to work one out from other content.
            legacy = _LEGACY_MARKER_RE.search(masked) is not None
            raise ReversibleMaskingError(
                "LEGACY_MAPPING_UNAVAILABLE" if legacy else "MAPPING_UNAVAILABLE"
            )
        return restore_original(masked, manifest, binding)

    def discard(self, manifest_id: str) -> None:
        """Forget a manifest. Idempotent."""
        with self._lock:
            if isinstance(manifest_id, str):
                self._forget(manifest_id)
