"""Red-phase suite for issue #28 PR A: reversible TXT masking core (cb.mask.v1).

The specification is docs/ADR-0003-reversible-masking.md. Every input here is
synthetic. The suite is deterministic: it asserts properties of random tokens,
never their values, and it contains no random-looking hex/base64 literals
(CI runs detect-secrets against .secrets.baseline). Canaries are checked in raw
and in JSON-escaped, URL-escaped, base64 and hex form.

Each TestCase class below carries a one-line comment naming the issue #28
section 10 "PR A" checklist item it proves.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import dataclasses
import hashlib
import inspect
import io
import json
import logging
import os
import pickle
import random
import re
import subprocess
import sys
import threading
import traceback
import unittest
import urllib.parse
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from tw_law_mcp.server import TOOL_SCHEMAS
from worker.secure_worker import reversible_masking as rm
from worker.secure_worker.masking import (
    NON_NAME_TERMS,
    PATTERNS,
    find_sensitive_classes,
    mask_sensitive_text,
)
from worker.secure_worker.residual_pii import (
    RESIDUAL_PATTERNS,
    ResidualPiiBlocked,
    find_residual_sensitive_classes,
)
from worker.secure_worker.reversible_masking import (
    DocumentBinding,
    InMemoryManifestRegistry,
    Occurrence,
    PrivateBytes,
    PrivateManifest,
    ReversibleMaskingError,
    SafeMaskedDocument,
    check_release_text,
    mask_document,
    restore_original,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKER_DIR = REPO_ROOT / "worker" / "secure_worker"
ADR_PATH = REPO_ROOT / "docs" / "ADR-0003-reversible-masking.md"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

BINDING_A = DocumentBinding("case-a", "doc-1", "v1")
BINDING_B = DocumentBinding("case-b", "doc-1", "v1")
BOM = b"\xef\xbb\xbf"
TOKEN_TYPES = tuple(sorted(set(rm.ENTITY_TYPES.values())))

# Synthetic values only. The Taiwan-ID shape is chosen with a low-entropy tail so
# that no quoted literal in this file looks like a random hex string.
NAME_A = "王大明"
NAME_B = "陳小美"
EMAIL_A = "owner@example.com"
MOBILE_A = "0912-345-678"
ADDRESS_A = "新北市板橋區文化路一段123號"
ID_A = "A123123123"
BARE_MOBILE = "0911222333"  # matches both the mobile and the landline pattern
# Matches residual_pii only (mixed letters and digits), not masking.PATTERNS. Built from two
# pieces so that no quoted literal in this file is a high-entropy hex string.
RESIDUAL_ONLY_ID = "AB" + "1234567"

ALL_CLASSES_TEXT = (
    "申請人：王大明\n"
    "備註 林志豪 到場\n"
    "身分證號：A123123123\n"
    "統編：87654321\n"
    "護照號碼：AB123456\n"
    "聯絡信箱：owner@example.com\n"
    "行動電話：0912-345-678\n"
    "市話：02-12345678\n"
    "生日：1990/01/02\n"
    "地號：文化段123-4\n"
    "案件編號：NTPC-12345\n"
    "案件地址：新北市板橋區文化路一段123號\n"
)
ALL_CLASSES_VALUES = [
    "王大明", "林志豪", "A123123123", "87654321", "AB123456", "owner@example.com",
    "0912-345-678", "02-12345678", "1990/01/02", "文化段123-4", "NTPC-12345",
    "新北市板橋區文化路一段123號",
]  # fmt: skip
# Detector class of each value above, in document order (not PATTERNS order).
ALL_CLASSES_DOC_ORDER = [
    "name", "personal_name", "taiwan_id", "tax_id", "passport_or_resident_id", "email",
    "mobile", "landline", "birth_date", "parcel_id", "bank_or_case_id", "address",
]  # fmt: skip

GOLDEN_TEXT = (
    "發文機關：新北市政府工務局\n"
    "主旨：室內裝修竣工查驗補正通知（合成資料）\n"
    "申請人：王大明\n"
    "聯絡電話：0912-345-678\n"
    "聯絡信箱：owner@example.com\n"
    "案件地址：新北市板橋區文化路一段123號\n"
    "說明一：依建築法第77條之2及建築物室內裝修管理辦法第33條辦理。\n"
    "說明二：請於文到30日內（115年10月31日前）補正。\n"
    "說明三：3樓走廊淨寬120公分，樓地板面積45.5平方公尺，用途H-2組。\n"
    "說明四：天花板材料耐燃一級，防火時效1小時。\n"
)
GOLDEN_EXPECTED = (
    "發文機關：新北市政府工務局\n"
    "主旨：室內裝修竣工查驗補正通知（合成資料）\n"
    "申請人：<PERSON>\n"
    "聯絡電話：<PHONE>\n"
    "聯絡信箱：<EMAIL>\n"
    "案件地址：<ADDRESS>\n"
    "說明一：依建築法第77條之2及建築物室內裝修管理辦法第33條辦理。\n"
    "說明二：請於文到30日內（115年10月31日前）補正。\n"
    "說明三：3樓走廊淨寬120公分，樓地板面積45.5平方公尺，用途H-2組。\n"
    "說明四：天花板材料耐燃一級，防火時效1小時。\n"
)

# A document whose last token is followed by a long plain tail, so that deleting a
# token outright still leaves every registered range inside the masked bytes.
TAMPER_TEXT = (
    "申請人：王大明\n承辦人：陳小美\n聯絡信箱：owner@example.com\n聯絡電話：0912-345-678\n"
    + "說明：請依規定補正並於期限內回覆。" * 6
    + "\n"
)
TAMPER_VALUES = ["王大明", "陳小美", "owner@example.com", "0912-345-678"]


@dataclasses.dataclass(frozen=True)
class Doc:
    name: str
    raw: bytes
    values: tuple[str, ...]


def _doc(name: str, text: str, values: list[str], *, bom: bool = False) -> Doc:
    raw = text.encode("utf-8")
    return Doc(name, (BOM + raw) if bom else raw, tuple(values))


_CHINESE = (
    "發文機關：新北市政府工務局\n申請人：王大明\n聯絡電話：0912-345-678\n"
    "聯絡信箱：owner@example.com\n案件地址：新北市板橋區文化路一段123號\n"
)
_CHINESE_VALUES = [NAME_A, MOBILE_A, EMAIL_A, ADDRESS_A]

CORPUS: tuple[Doc, ...] = (
    _doc("chinese", _CHINESE, _CHINESE_VALUES),
    _doc("non_bmp_next_to_pii", "備註😀 𠀋 申請人：王大明 郵件 owner@example.com 😀\n", [NAME_A, EMAIL_A]),
    _doc(
        "combining_marks_next_to_pii",
        "備註 e\N{COMBINING ACUTE ACCENT} 申請人：王大明\N{COMBINING ACUTE ACCENT} 證號 A123123123\N{COMBINING ACUTE ACCENT}\n",
        [NAME_A, ID_A],
    ),
    _doc(
        "full_width_punctuation",
        "申請人：王大明（承辦），電話：0912-345-678，信箱：owner@example.com。\n",
        [NAME_A, MOBILE_A, EMAIL_A],
    ),
    _doc("utf8_bom", _CHINESE, _CHINESE_VALUES, bom=True),
    _doc("lf", "申請人：王大明\n聯絡信箱：owner@example.com\n", [NAME_A, EMAIL_A]),
    _doc("crlf", "申請人：王大明\r\n聯絡信箱：owner@example.com\r\n", [NAME_A, EMAIL_A]),
    _doc("lone_cr", "申請人：王大明\r聯絡信箱：owner@example.com\r", [NAME_A, EMAIL_A]),
    _doc(
        "mixed_endings",
        "申請人：王大明\r\n聯絡信箱：owner@example.com\n聯絡電話：0912-345-678\r備註\r\n",
        [NAME_A, EMAIL_A, MOBILE_A],
    ),
    _doc(
        "trailing_whitespace",
        "申請人：王大明   \n聯絡信箱：owner@example.com \t \n",
        [NAME_A, EMAIL_A],
    ),
    _doc("no_final_newline", "聯絡信箱：owner@example.com", [EMAIL_A]),
    _doc("empty_document", "", []),
    Doc("bom_only", BOM, ()),
    _doc("no_pii", "說明一：請補申請書、建築物權利證明文件及室內裝修圖說，並由建築師簽章。\n", []),
    _doc("adjacent_spans", "證號A123123123王大明\n", [ID_A, NAME_A]),
    _doc("contained_spans", "信箱 x.a123123123@example.com 。\n", ["x.a123123123@example.com"]),
    _doc("identical_spans", "申請人：王大明\n聯絡電話：0911222333\n", [NAME_A, BARE_MOBILE]),
    _doc(
        "same_value_three_times",
        "聯絡信箱：owner@example.com\n備用信箱：owner@example.com\n通知信箱：owner@example.com\n",
        [EMAIL_A, EMAIL_A, EMAIL_A],
    ),
    _doc("same_literal_two_people", "申請人：王大明\n承辦人：王大明\n", [NAME_A, NAME_A]),
    _doc(
        "non_ascii_digits_inside_values",
        "證號 A1２３４５６７８９ 已附\n電話 0912-３４５-６７８\n統編：８７６５４３２１\n",
        ["A1２３４５６７８９", "0912-３４５-６７８", "８７６５４３２１"],
    ),
    _doc("all_pattern_classes", ALL_CLASSES_TEXT, ALL_CLASSES_VALUES),
    _doc("golden_notice", GOLDEN_TEXT, [NAME_A, MOBILE_A, EMAIL_A, ADDRESS_A]),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leak_forms(value: str) -> list[str]:
    """Every encoding of ``value`` that a serializer could plausibly emit."""
    utf8 = value.encode("utf-8")
    ascii_json = json.dumps(value, ensure_ascii=True)[1:-1]
    forms = {
        value,
        value.lower(),
        value.upper(),
        ascii_json,
        re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m.group(1).upper(), ascii_json),
        json.dumps(value, ensure_ascii=False)[1:-1],
        urllib.parse.quote(value, safe=""),
        urllib.parse.quote(value),
        base64.b64encode(utf8).decode("ascii"),
        base64.urlsafe_b64encode(utf8).decode("ascii"),
        utf8.hex(),
        utf8.hex().upper(),
        repr(utf8)[2:-1],
        sha(utf8),
    }
    squeezed = re.sub(r"[-\s/]", "", value)
    if squeezed != value and len(squeezed) >= 6:
        forms.add(squeezed)
    return sorted(form for form in forms if form)


def token_spans(masked: bytes) -> list[tuple[int, int, str]]:
    """(byte_start, byte_end, token) for every full-grammar token, test-side."""
    text = masked.decode("utf-8")
    spans = []
    for match in rm.TOKEN_RE.finditer(text):
        start = len(text[: match.start()].encode("utf-8"))
        spans.append((start, start + len(match.group(0).encode("utf-8")), match.group(0)))
    return spans


def splice(data: bytes, start: int, end: int, replacement: bytes) -> bytes:
    return data[:start] + replacement + data[end:]


def forge_digest(manifest: PrivateManifest, tampered: bytes) -> PrivateManifest:
    """A manifest that vouches for the tampered bytes, so only token checks can object."""
    return dataclasses.replace(manifest, masked_sha256=sha(tampered))


def normalize_tokens(masked_text: str) -> str:
    return rm.TOKEN_RE.sub(lambda m: f"<{m.group(1)}>", masked_text)


def outside_spans(data: bytes, ranges: list[tuple[int, int]]) -> bytes:
    kept, cursor = [], 0
    for start, end in sorted(ranges):
        kept.append(data[cursor:start])
        cursor = end
    kept.append(data[cursor:])
    return b"".join(kept)


def make_token(entity_type: str, namespace: str, sequence: int) -> str:
    return f"[[CB1:{entity_type}:{namespace}:{sequence:06d}]]"


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class CoreTestCase(unittest.TestCase):
    """Shared helpers. Nothing here depends on the implementation under test."""

    def mask(self, raw: bytes | str, binding: DocumentBinding = BINDING_A, **kwargs):
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        return mask_document(data, binding, **kwargs)

    def assertNoLeak(self, haystack: str, canaries, where: str = "") -> None:
        for canary in canaries:
            for form in leak_forms(canary):
                self.assertNotIn(form, haystack, f"canary form {form!r} leaked {where}")

    def assertCleanError(self, exc: BaseException, canaries=()) -> None:
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        for label, text in (
            ("str", str(exc)),
            ("repr", repr(exc)),
            ("args", repr(exc.args)),
            ("traceback", rendered),
        ):
            self.assertNoLeak(text, canaries, f"in error {label}")

    def assertRejected(self, code: str, func, *args, canaries=(), **kwargs) -> ReversibleMaskingError:
        with self.assertRaises(ReversibleMaskingError) as raised:
            func(*args, **kwargs)
        error = raised.exception
        self.assertEqual(error.code, code)
        self.assertIn(code, rm.ERROR_CODES)
        self.assertEqual(str(error), code)
        self.assertEqual(error.args, (code,))
        self.assertCleanError(error, canaries)
        return error

    def assertRestoreRejected(self, code, masked, manifest, binding=BINDING_A, canaries=()):
        return self.assertRejected(code, restore_original, masked, manifest, binding, canaries=canaries)

    def issue_tamper_doc(self):
        safe, manifest = self.mask(TAMPER_TEXT)
        self.assertEqual(len(manifest.occurrences), 4)
        return safe.masked_bytes, manifest


def corpus_doc(name: str) -> Doc:
    return next(doc for doc in CORPUS if doc.name == name)


def check_geometry(test: unittest.TestCase, raw: bytes, safe: SafeMaskedDocument, manifest: PrivateManifest) -> None:
    """Every location invariant of ADR-0003 'Byte offsets' for one masking run."""
    masked = safe.masked_bytes
    occurrences = manifest.occurrences
    test.assertEqual(safe.occurrence_count, len(occurrences))
    test.assertEqual(sum(safe.mask_counts.values()), len(occurrences))
    previous_original = previous_masked = delta = 0
    for index, occ in enumerate(occurrences, start=1):
        test.assertEqual(raw[occ.original_byte_start : occ.original_byte_end], occ.original_value.reveal())
        test.assertEqual(masked[occ.masked_byte_start : occ.masked_byte_end], occ.token.encode("ascii"))
        test.assertGreater(len(occ.original_value), 0)
        test.assertEqual(len(occ.original_value), occ.original_byte_end - occ.original_byte_start)
        test.assertGreaterEqual(occ.original_byte_start, previous_original)
        test.assertGreaterEqual(occ.masked_byte_start, previous_masked)
        test.assertEqual(occ.masked_byte_start, occ.original_byte_start + delta)
        parts = rm.TOKEN_RE.fullmatch(occ.token)
        test.assertIsNotNone(parts)
        test.assertEqual(parts.group(1), occ.entity_type)
        test.assertEqual(parts.group(2), manifest.token_namespace)
        test.assertEqual(int(parts.group(3)), index)
        test.assertEqual(occ.entity_type, rm.ENTITY_TYPES[occ.detector_class])
        test.assertEqual(occ.segment_id, "body")
        delta += len(occ.token) - len(occ.original_value)
        previous_original, previous_masked = occ.original_byte_end, occ.masked_byte_end
    test.assertEqual(
        outside_spans(raw, [(o.original_byte_start, o.original_byte_end) for o in occurrences]),
        outside_spans(masked, [(o.masked_byte_start, o.masked_byte_end) for o in occurrences]),
    )
    # The masked bytes hold exactly the registered tokens, at the registered offsets.
    test.assertEqual(
        token_spans(masked),
        [(o.masked_byte_start, o.masked_byte_end, o.token) for o in occurrences],
    )


# Proves #28 §10 PR A item 1: synthetic UTF-8 TXT round-trips byte for byte.
class RoundtripByteExactTests(CoreTestCase):
    def test_corpus_roundtrips_byte_for_byte_with_matching_digests(self) -> None:
        for doc in CORPUS:
            with self.subTest(doc=doc.name):
                safe, manifest = self.mask(doc.raw)
                restored = restore_original(safe.masked_bytes, manifest, BINDING_A)
                self.assertIs(type(restored), bytes)
                self.assertIs(type(safe.masked_bytes), bytes)
                self.assertEqual(restored, doc.raw)
                self.assertEqual(sha(restored), sha(doc.raw))
                self.assertEqual(manifest.original_sha256, sha(doc.raw))
                self.assertEqual(manifest.masked_sha256, sha(safe.masked_bytes))
                self.assertEqual(safe.masked_sha256, manifest.masked_sha256)
                # Positive control: the values are in the private manifest, in order.
                revealed = [o.original_value.reveal().decode("utf-8") for o in manifest.occurrences]
                self.assertEqual(revealed, list(doc.values))
                self.assertEqual(safe.occurrence_count, len(doc.values))
                for value in doc.values:
                    self.assertNotIn(value, safe.masked_text)
                check_geometry(self, doc.raw, safe, manifest)

    def test_documents_without_pii_pass_through_unchanged(self) -> None:
        for name in ("empty_document", "bom_only", "no_pii"):
            with self.subTest(doc=name):
                doc = corpus_doc(name)
                safe, manifest = self.mask(doc.raw)
                self.assertEqual(safe.masked_bytes, doc.raw)
                self.assertEqual(manifest.occurrences, ())
                self.assertEqual(safe.occurrence_count, 0)
                self.assertEqual(set(safe.mask_counts), {name for name, _ in PATTERNS})
                self.assertEqual(sum(safe.mask_counts.values()), 0)
                self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), doc.raw)

    def test_bom_is_kept_in_the_masked_bytes_and_recorded(self) -> None:
        with_bom, without_bom = corpus_doc("utf8_bom"), corpus_doc("chinese")
        safe, manifest = self.mask(with_bom.raw)
        self.assertTrue(safe.masked_bytes.startswith(BOM))
        self.assertTrue(safe.masked_text.startswith("\N{ZERO WIDTH NO-BREAK SPACE}"))
        self.assertIs(manifest.bom, True)
        first = manifest.occurrences[0]
        prefix = "發文機關：新北市政府工務局\n申請人：".encode("utf-8")
        # Offsets are counted from the first byte of the file, BOM included.
        self.assertEqual(first.original_byte_start, len(BOM) + len(prefix))
        self.assertEqual(with_bom.raw[first.original_byte_start : first.original_byte_end], NAME_A.encode())
        plain_safe, plain_manifest = self.mask(without_bom.raw)
        self.assertIs(plain_manifest.bom, False)
        self.assertFalse(plain_safe.masked_bytes.startswith(BOM))
        self.assertEqual(
            normalize_tokens(safe.masked_text),
            "\N{ZERO WIDTH NO-BREAK SPACE}" + normalize_tokens(plain_safe.masked_text),
        )
        only_safe, only_manifest = self.mask(BOM)
        self.assertEqual(only_safe.masked_bytes, BOM)
        self.assertIs(only_manifest.bom, True)

    def test_line_terminators_survive_byte_for_byte(self) -> None:
        for name in ("lf", "crlf", "lone_cr", "mixed_endings"):
            with self.subTest(doc=name):
                doc = corpus_doc(name)
                safe, manifest = self.mask(doc.raw)
                masked = safe.masked_bytes
                self.assertEqual(masked.count(b"\r\n"), doc.raw.count(b"\r\n"))
                self.assertEqual(masked.count(b"\n"), doc.raw.count(b"\n"))
                self.assertEqual(masked.count(b"\r"), doc.raw.count(b"\r"))
                check_geometry(self, doc.raw, safe, manifest)
        crlf_safe, _ = self.mask(corpus_doc("crlf").raw)
        self.assertEqual(crlf_safe.masked_bytes.count(b"]]\r\n"), 2)
        cr_safe, _ = self.mask(corpus_doc("lone_cr").raw)
        self.assertEqual(cr_safe.masked_bytes.count(b"]]\r"), 2)
        self.assertNotIn(b"\n", cr_safe.masked_bytes)

    def test_lone_cr_separator_inside_a_detector_span_still_roundtrips(self) -> None:
        # The existing address pattern may run across a lone CR (ADR-0003 limitations).
        # The masked shape is not pinned, but the round trip and the leak guarantee are.
        raw = f"備註\r地址：{ADDRESS_A}\r其他\r".encode("utf-8")
        safe, manifest = self.mask(raw)
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)
        self.assertNoLeak(safe.masked_text, [ADDRESS_A], "in masked text")
        check_geometry(self, raw, safe, manifest)

    def test_birth_date_value_never_swallows_the_line_terminator(self) -> None:
        # The birth_date pattern ends in \s*, so the raw match includes the terminator.
        for terminator in ("\n", "\r\n", "\r", "\n\n", "  \n", " \t\r\n"):
            with self.subTest(terminator=terminator):
                text = f"生日：1990/01/02{terminator}下一行{terminator}"
                safe, manifest = self.mask(text)
                (occ,) = manifest.occurrences
                self.assertEqual(occ.original_value.reveal(), b"1990/01/02")
                self.assertEqual(
                    normalize_tokens(safe.masked_text), f"生日：<BIRTH_DATE>{terminator}下一行{terminator}"
                )
                self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), text.encode())
        for text, value, expected in (
            ("出生日期：民國80年1月2日\r\n", "民國80年1月2日", "出生日期：<BIRTH_DATE>\r\n"),
            ("生日：1990/01/02 備註\n", "1990/01/02", "生日：<BIRTH_DATE> 備註\n"),
        ):
            with self.subTest(text=text):
                safe, manifest = self.mask(text)
                (occ,) = manifest.occurrences
                self.assertEqual(occ.original_value.reveal().decode(), value)
                self.assertEqual(normalize_tokens(safe.masked_text), expected)

    def test_trailing_whitespace_and_missing_final_newline_are_preserved(self) -> None:
        safe, manifest = self.mask(corpus_doc("trailing_whitespace").raw)
        self.assertEqual(safe.masked_bytes.count(b"]]   \n"), 1)
        self.assertTrue(safe.masked_bytes.endswith(b"]] \t \n"))
        self.assertEqual([o.original_value.reveal().decode() for o in manifest.occurrences], [NAME_A, EMAIL_A])
        safe, _ = self.mask(corpus_doc("no_final_newline").raw)
        self.assertTrue(safe.masked_bytes.endswith(b"]]"))
        self.assertFalse(safe.masked_bytes.endswith(b"\n"))

    def test_restore_is_repeatable_and_does_not_change_the_manifest(self) -> None:
        raw = corpus_doc("chinese").raw
        safe, manifest = self.mask(raw)
        before = [(o.token, o.original_value.reveal(), o.original_byte_start) for o in manifest.occurrences]
        first = restore_original(safe.masked_bytes, manifest, BINDING_A)
        second = restore_original(safe.masked_bytes, manifest, BINDING_A)
        self.assertEqual(first, raw)
        self.assertEqual(second, raw)
        after = [(o.token, o.original_value.reveal(), o.original_byte_start) for o in manifest.occurrences]
        self.assertEqual(before, after)

    def test_all_pattern_classes_roundtrip_in_one_document(self) -> None:
        raw = ALL_CLASSES_TEXT.encode("utf-8")
        safe, manifest = self.mask(raw)
        self.assertEqual([o.detector_class for o in manifest.occurrences], ALL_CLASSES_DOC_ORDER)
        self.assertEqual({o.detector_class for o in manifest.occurrences}, {name for name, _ in PATTERNS})
        self.assertEqual(set(safe.mask_counts.values()), {1})
        self.assertEqual({o.entity_type for o in manifest.occurrences}, set(TOKEN_TYPES))
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)

    def test_adjacent_spans_stay_separate_tokens(self) -> None:
        safe, manifest = self.mask(corpus_doc("adjacent_spans").raw)
        first, second = manifest.occurrences
        self.assertEqual((first.entity_type, second.entity_type), ("NATIONAL_ID", "PERSON"))
        self.assertEqual(first.masked_byte_end, second.masked_byte_start)
        self.assertEqual(first.original_byte_end, second.original_byte_start)
        self.assertEqual(safe.masked_text, f"證號{first.token}{second.token}\n")

    def test_contained_span_is_absorbed_by_the_outer_span(self) -> None:
        # taiwan_id has the lower PATTERNS index but lies inside the email span.
        safe, manifest = self.mask(corpus_doc("contained_spans").raw)
        (occ,) = manifest.occurrences
        self.assertEqual((occ.detector_class, occ.entity_type), ("email", "EMAIL"))
        self.assertEqual(occ.original_value.reveal().decode(), "x.a123123123@example.com")
        self.assertEqual(safe.masked_text, f"信箱 {occ.token} 。\n")
        self.assertEqual(dict((k, v) for k, v in safe.mask_counts.items() if v), {"email": 1})

    def test_identical_spans_keep_the_class_with_the_lowest_pattern_index(self) -> None:
        cases = (
            ("申請人：王大明\n", "name", "PERSON", "申請人：<PERSON>\n"),
            (f"聯絡電話：{BARE_MOBILE}\n", "mobile", "PHONE", "聯絡電話：<PHONE>\n"),
            (f"護照號碼：{ID_A}\n", "taiwan_id", "NATIONAL_ID", "護照號碼：<NATIONAL_ID>\n"),
        )
        for text, detector_class, entity_type, expected in cases:
            with self.subTest(text=text):
                safe, manifest = self.mask(text)
                (occ,) = manifest.occurrences
                self.assertEqual(occ.detector_class, detector_class)
                self.assertEqual(occ.entity_type, entity_type)
                self.assertEqual(normalize_tokens(safe.masked_text), expected)
                self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), text.encode())

    def test_same_value_three_times_gets_three_unrelated_tokens(self) -> None:
        raw = corpus_doc("same_value_three_times").raw
        safe, manifest = self.mask(raw)
        occurrences = manifest.occurrences
        self.assertEqual(len(occurrences), 3)
        self.assertEqual({o.original_value.reveal() for o in occurrences}, {EMAIL_A.encode()})
        self.assertEqual(len({o.token for o in occurrences}), 3)
        self.assertEqual(len({o.occurrence_id for o in occurrences}), 3)
        self.assertEqual(len({o.entity_id for o in occurrences}), 3)
        self.assertEqual(safe.masked_text.count("[[CB1:EMAIL:"), 3)
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)

    def test_same_literal_for_two_people_roundtrips_as_two_occurrences(self) -> None:
        raw = corpus_doc("same_literal_two_people").raw
        safe, manifest = self.mask(raw)
        self.assertEqual([o.entity_type for o in manifest.occurrences], ["PERSON", "PERSON"])
        self.assertEqual(normalize_tokens(safe.masked_text), "申請人：<PERSON>\n承辦人：<PERSON>\n")
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)

    def test_large_document_with_thousands_of_occurrences_roundtrips(self) -> None:
        lines = []
        for index in range(1500):
            name = (NAME_A, NAME_B)[index % 2]
            lines.append(f"申請人：{name}\n聯絡信箱：user{index}@example.com\n備註😀{index}\n")
        raw = "".join(lines).encode("utf-8")
        safe, manifest = self.mask(raw)
        self.assertEqual(len(manifest.occurrences), 3000)
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)
        check_geometry(self, raw, safe, manifest)


# Proves #28 §10 PR A item 2a: every occurrence is located exactly, in UTF-8 byte offsets.
class OccurrenceLocationTests(CoreTestCase):
    def test_every_occurrence_is_located_exactly_in_both_texts(self) -> None:
        for doc in CORPUS:
            with self.subTest(doc=doc.name):
                safe, manifest = self.mask(doc.raw)
                check_geometry(self, doc.raw, safe, manifest)
                located = [
                    doc.raw[o.original_byte_start : o.original_byte_end].decode("utf-8") for o in manifest.occurrences
                ]
                self.assertEqual(located, list(doc.values))

    def test_offsets_are_utf8_byte_offsets_not_code_points_or_utf16_units(self) -> None:
        prefix = "備註😀 𠀋 申請人："
        text = f"{prefix}{NAME_A} 郵件 {EMAIL_A}\n"
        byte_start = len(prefix.encode("utf-8"))
        code_point_start = len(prefix)
        utf16_start = len(prefix.encode("utf-16-le")) // 2
        # Guard the arithmetic of this test: the three conventions really differ.
        self.assertEqual((code_point_start, utf16_start, byte_start), (10, 12, 28))
        safe, manifest = self.mask(text)
        name, email = manifest.occurrences
        self.assertEqual(name.original_byte_start, byte_start)
        self.assertNotIn(name.original_byte_start, (code_point_start, utf16_start))
        self.assertEqual(name.original_byte_end - name.original_byte_start, len(NAME_A.encode("utf-8")))
        self.assertEqual(len(NAME_A.encode("utf-8")), 9)
        before_email = text[: text.index(EMAIL_A)]
        self.assertEqual(email.original_byte_start, len(before_email.encode("utf-8")))
        self.assertNotEqual(email.original_byte_start, len(before_email))
        self.assertEqual(name.masked_byte_start, byte_start)
        self.assertEqual(
            email.masked_byte_start,
            email.original_byte_start + len(name.token) - len(NAME_A.encode("utf-8")),
        )
        check_geometry(self, text.encode("utf-8"), safe, manifest)

    def test_han_text_uses_three_byte_offsets(self) -> None:
        safe, manifest = self.mask("申請人：王大明\n")
        (occ,) = manifest.occurrences
        self.assertEqual(occ.original_byte_start, len("申請人：".encode("utf-8")))
        self.assertEqual(occ.original_byte_start, 12)
        self.assertNotEqual(occ.original_byte_start, len("申請人："))
        self.assertEqual(occ.original_byte_end, 21)

    def test_combining_mark_before_a_value_shifts_byte_but_not_visible_offsets(self) -> None:
        prefix = "備註 e\N{COMBINING ACUTE ACCENT} 申請人："
        raw = f"{prefix}{NAME_A}\n".encode("utf-8")
        safe, manifest = self.mask(raw)
        (occ,) = manifest.occurrences
        self.assertEqual(occ.original_byte_start, len(prefix.encode("utf-8")))
        self.assertEqual(raw[occ.original_byte_start : occ.original_byte_end], NAME_A.encode("utf-8"))
        # The combining mark is its own two bytes; nothing was normalized away.
        self.assertIn("e\N{COMBINING ACUTE ACCENT}".encode("utf-8"), safe.masked_bytes)

    def test_sequence_numbers_follow_document_order(self) -> None:
        safe, manifest = self.mask(ALL_CLASSES_TEXT)
        sequences = [int(rm.TOKEN_RE.fullmatch(o.token).group(3)) for o in manifest.occurrences]
        self.assertEqual(sequences, list(range(1, 13)))
        starts = [o.original_byte_start for o in manifest.occurrences]
        self.assertEqual(starts, sorted(starts))
        self.assertEqual([t for _, _, t in token_spans(safe.masked_bytes)], [o.token for o in manifest.occurrences])


# Proves #28 §10 PR A item 2b: namespaces are never shared across cases; equal names are never merged.
class NamespaceAndEntityIsolationTests(CoreTestCase):
    def test_same_document_under_two_cases_shares_nothing(self) -> None:
        raw = corpus_doc("chinese").raw
        safe_a, man_a = self.mask(raw, BINDING_A)
        safe_b, man_b = self.mask(raw, BINDING_B)
        self.assertNotEqual(man_a.token_namespace, man_b.token_namespace)
        for attribute in ("token", "occurrence_id", "entity_id"):
            ours = {getattr(o, attribute) for o in man_a.occurrences}
            theirs = {getattr(o, attribute) for o in man_b.occurrences}
            self.assertEqual(len(ours), 4)
            self.assertTrue(ours.isdisjoint(theirs), attribute)
        self.assertNotEqual(man_a.manifest_id, man_b.manifest_id)
        self.assertNotEqual(safe_a.masked_text, safe_b.masked_text)
        self.assertEqual(normalize_tokens(safe_a.masked_text), normalize_tokens(safe_b.masked_text))
        self.assertEqual(restore_original(safe_a.masked_bytes, man_a, BINDING_A), raw)
        self.assertEqual(restore_original(safe_b.masked_bytes, man_b, BINDING_B), raw)

    def test_cross_case_restore_is_rejected_at_every_layer(self) -> None:
        raw = corpus_doc("chinese").raw
        safe_a, man_a = self.mask(raw, BINDING_A)
        safe_b, man_b = self.mask(raw, BINDING_B)
        canaries = [NAME_A, MOBILE_A, EMAIL_A, ADDRESS_A]
        self.assertRestoreRejected("BINDING_MISMATCH", safe_a.masked_bytes, man_a, BINDING_B, canaries)
        self.assertRestoreRejected("BINDING_MISMATCH", safe_a.masked_bytes, man_b, BINDING_A, canaries)
        self.assertRestoreRejected("MASKED_DIGEST_MISMATCH", safe_a.masked_bytes, man_b, BINDING_B, canaries)
        self.assertRestoreRejected("MASKED_DIGEST_MISMATCH", safe_b.masked_bytes, man_a, BINDING_A, canaries)
        # Even a manifest that vouches for the other case's bytes cannot use its tokens.
        forged = forge_digest(man_b, safe_a.masked_bytes)
        self.assertRestoreRejected("UNKNOWN_TOKEN", safe_a.masked_bytes, forged, BINDING_B, canaries)
        forged = forge_digest(man_a, safe_b.masked_bytes)
        self.assertRestoreRejected("UNKNOWN_TOKEN", safe_b.masked_bytes, forged, BINDING_A, canaries)

    def test_documents_and_versions_inside_one_case_get_their_own_namespace(self) -> None:
        raw = corpus_doc("chinese").raw
        bindings = [
            DocumentBinding("case-a", "doc-1", "v1"),
            DocumentBinding("case-a", "doc-2", "v1"),
            DocumentBinding("case-a", "doc-1", "v2"),
        ]
        namespaces = {self.mask(raw, binding)[1].token_namespace for binding in bindings}
        self.assertEqual(len(namespaces), 3)

    def test_same_binding_masked_twice_through_the_core_gets_fresh_tokens(self) -> None:
        # Retries are made idempotent by the registry, not by deterministic tokens.
        raw = corpus_doc("chinese").raw
        _, first = self.mask(raw)
        _, second = self.mask(raw)
        self.assertNotEqual(first.token_namespace, second.token_namespace)
        self.assertTrue({o.token for o in first.occurrences}.isdisjoint({o.token for o in second.occurrences}))

    def test_two_people_with_the_same_name_stay_two_entities(self) -> None:
        safe, manifest = self.mask(corpus_doc("same_literal_two_people").raw)
        first, second = manifest.occurrences
        self.assertEqual(first.original_value.reveal(), second.original_value.reveal())
        self.assertNotEqual(first.occurrence_id, second.occurrence_id)
        self.assertNotEqual(first.entity_id, second.entity_id)
        self.assertNotEqual(first.token, second.token)
        self.assertEqual(safe.masked_text.count(first.token), 1)
        self.assertEqual(safe.masked_text.count(second.token), 1)
        # Same literal in the same role is still not linked automatically.
        safe, manifest = self.mask("申請人：王大明\n聯絡人：王大明\n承辦人：王大明\n")
        self.assertEqual(len({o.entity_id for o in manifest.occurrences}), 3)
        self.assertEqual(len({o.occurrence_id for o in manifest.occurrences}), 3)

    def test_namespace_and_ids_do_not_depend_on_the_random_module(self) -> None:
        raw = corpus_doc("chinese").raw
        state = random.getstate()
        try:
            random.seed(20241004)
            _, first = self.mask(raw)
            random.seed(20241004)
            _, second = self.mask(raw)
        finally:
            random.setstate(state)
        self.assertNotEqual(first.token_namespace, second.token_namespace)
        self.assertNotEqual(first.manifest_id, second.manifest_id)
        for attribute in ("occurrence_id", "entity_id"):
            ours = {getattr(o, attribute) for o in first.occurrences}
            theirs = {getattr(o, attribute) for o in second.occurrences}
            self.assertTrue(ours.isdisjoint(theirs), attribute)

    def test_namespaces_look_uniformly_random(self) -> None:
        raw = corpus_doc("lf").raw
        manifests = [self.mask(raw)[1] for _ in range(200)]
        namespaces = [m.token_namespace for m in manifests]
        self.assertEqual(len(set(namespaces)), 200)
        for namespace in namespaces:
            self.assertRegex(namespace, r"\A[a-z]{28}\Z")
        self.assertEqual(set("".join(namespaces)), set("abcdefghijklmnopqrstuvwxyz"))
        for position in range(28):
            self.assertGreaterEqual(len({n[position] for n in namespaces}), 10, position)
        self.assertEqual(len({m.manifest_id for m in manifests}), 200)

    def test_identifiers_are_opaque_and_well_formed(self) -> None:
        safe, manifest = self.mask(ALL_CLASSES_TEXT)
        parsed = uuid.UUID(manifest.manifest_id)
        self.assertEqual(parsed.version, 4)
        self.assertEqual(str(parsed), manifest.manifest_id)
        self.assertEqual(safe.manifest_id, manifest.manifest_id)
        identifiers = [manifest.manifest_id]
        for occ in manifest.occurrences:
            for value in (occ.occurrence_id, occ.entity_id):
                self.assertTrue(rm.OPAQUE_ID_RE.fullmatch(value), value)
                identifiers.append(value)
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_no_token_or_identifier_is_derived_from_a_value(self) -> None:
        _, manifest = self.mask(ALL_CLASSES_TEXT)
        carriers = [manifest.manifest_id, manifest.token_namespace]
        for occ in manifest.occurrences:
            carriers += [occ.token, occ.occurrence_id, occ.entity_id]
        haystack = "\n".join(carriers)
        for value in ALL_CLASSES_VALUES:
            for form in leak_forms(value) + [sha(value.encode("utf-8"))[:16], sha(value.encode("utf-8"))[:32]]:
                self.assertNotIn(form, haystack)


def token_tampers(masked: bytes, manifest: PrivateManifest) -> dict[str, tuple[bytes, str]]:
    """name -> (tampered bytes, code once the digest is forged so only tokens can object).

    Every variant keeps the total length, except the two that say so, so that the
    registered ranges stay inside the masked bytes and the token-level code is reached.
    """
    (s1, e1, t1), (s2, e2, t2), (s3, e3, t3), (s4, e4, _t4) = token_spans(masked)
    namespace = manifest.token_namespace
    other = "z" * 28 if namespace != "z" * 28 else "y" * 28
    raw1, raw2, raw3 = t1.encode(), t2.encode(), t3.encode()
    assert len(raw1) == len(raw2) and len(raw1) != len(raw3)

    def malformed(replacement: bytes) -> bytes:
        return splice(masked, s2, e2, replacement)

    return {
        "missing_replaced_by_filler": (splice(masked, s2, e2, b"x" * (e2 - s2)), "MISSING_TOKEN"),
        "missing_deleted_outright": (splice(masked, s2, e2, b""), "MISSING_TOKEN"),
        "unknown_foreign_namespace": (
            splice(masked, s2, e2, make_token("PERSON", other, 2).encode()),
            "UNKNOWN_TOKEN",
        ),
        "unknown_unissued_sequence": (
            splice(masked, s2, e2, make_token("PERSON", namespace, 99).encode()),
            "UNKNOWN_TOKEN",
        ),
        "unknown_type_confusion": (
            splice(masked, s4, e4, make_token("EMAIL", namespace, 4).encode()),
            "UNKNOWN_TOKEN",
        ),
        "duplicate_token": (splice(masked, s2, e2, raw1), "DUPLICATE_TOKEN"),
        "swapped_same_type": (
            masked[:s1] + raw2 + masked[e1:s2] + raw1 + masked[e2:],
            "TOKEN_POSITION_MISMATCH",
        ),
        "swapped_different_type": (
            masked[:s1] + raw3 + masked[e1:s3] + raw1 + masked[e3:],
            "TOKEN_POSITION_MISMATCH",
        ),
        "malformed_uppercase_namespace_letter": (
            malformed(raw2.replace(namespace.encode(), namespace[0].upper().encode() + namespace[1:].encode())),
            "MALFORMED_TOKEN",
        ),
        "malformed_lowercase_prefix": (malformed(raw2.replace(b"[[CB1:", b"[[cb1:")), "MALFORMED_TOKEN"),
        "malformed_unclosed": (malformed(raw2[:-2] + b"  "), "MALFORMED_TOKEN"),
        "malformed_non_ascii_digits": (
            malformed(raw2.replace(b":000002]]", ":٠٠٠٠٠٢]]".encode("utf-8"))),
            "MALFORMED_TOKEN",
        ),
    }


def replace_occurrence(manifest: PrivateManifest, index: int, **changes) -> PrivateManifest:
    occurrences = tuple(
        dataclasses.replace(occ, **changes) if i == index else occ for i, occ in enumerate(manifest.occurrences)
    )
    return dataclasses.replace(manifest, occurrences=occurrences)


def swap_values(manifest: PrivateManifest, i: int, j: int) -> PrivateManifest:
    occurrences = list(manifest.occurrences)
    first, second = occurrences[i], occurrences[j]
    occurrences[i] = dataclasses.replace(first, original_value=second.original_value)
    occurrences[j] = dataclasses.replace(second, original_value=first.original_value)
    return dataclasses.replace(manifest, occurrences=tuple(occurrences))


# Proves #28 §10 PR A item 3a: missing/unknown/duplicated/swapped tokens are refused without leaks.
class TokenTamperRejectionTests(CoreTestCase):
    def test_every_token_tamper_is_caught_by_the_masked_digest_first(self) -> None:
        masked, manifest = self.issue_tamper_doc()
        for name, (tampered, _code) in token_tampers(masked, manifest).items():
            with self.subTest(tamper=name):
                self.assertNotEqual(tampered, masked)
                self.assertRestoreRejected("MASKED_DIGEST_MISMATCH", tampered, manifest, canaries=TAMPER_VALUES)

    def test_every_token_tamper_with_a_forged_digest_gets_its_token_level_code(self) -> None:
        masked, manifest = self.issue_tamper_doc()
        for name, (tampered, code) in token_tampers(masked, manifest).items():
            with self.subTest(tamper=name):
                forged = forge_digest(manifest, tampered)
                self.assertRestoreRejected(code, tampered, forged, canaries=TAMPER_VALUES)

    def test_untampered_masked_bytes_still_restore_after_all_of_the_above(self) -> None:
        masked, manifest = self.issue_tamper_doc()
        self.assertEqual(restore_original(masked, manifest, BINDING_A), TAMPER_TEXT.encode("utf-8"))

    def test_token_error_categories_are_ordered_over_the_whole_text(self) -> None:
        masked, manifest = self.issue_tamper_doc()
        (s1, e1, _), _, (s3, e3, t3), _ = token_spans(masked)
        namespace = manifest.token_namespace
        unknown_first = splice(masked, s1, e1, make_token("PERSON", "z" * 28, 1).encode())
        both = splice(unknown_first, s3, e3, t3.encode().replace(b"[[CB1:", b"[[cb1:"))
        self.assertRestoreRejected("MALFORMED_TOKEN", both, forge_digest(manifest, both), canaries=TAMPER_VALUES)
        self.assertRestoreRejected(
            "UNKNOWN_TOKEN", unknown_first, forge_digest(manifest, unknown_first), canaries=TAMPER_VALUES
        )
        self.assertNotEqual(namespace, "z" * 28)

    def test_a_token_that_is_merely_well_formed_is_not_enough(self) -> None:
        masked, manifest = self.issue_tamper_doc()
        # Every token in the text is grammatical and every one is issued, yet one is
        # twice and another is gone: the complete set is required, not just the format.
        _, (s2, e2, _), _, _ = token_spans(masked)
        first = token_spans(masked)[0][2].encode()
        tampered = splice(masked, s2, e2, first)
        self.assertTrue(all(rm.TOKEN_RE.fullmatch(t) for _, _, t in token_spans(tampered)))
        self.assertRestoreRejected(
            "DUPLICATE_TOKEN", tampered, forge_digest(manifest, tampered), canaries=TAMPER_VALUES
        )


# Proves #28 §10 PR A item 3b: a wrong case, document or version is refused; bindings carry no free text.
class BindingTests(CoreTestCase):
    def test_wrong_case_document_or_version_is_a_binding_mismatch(self) -> None:
        safe, manifest = self.mask(corpus_doc("chinese").raw)
        wrong = (
            DocumentBinding("case-x", "doc-1", "v1"),
            DocumentBinding("case-a", "doc-x", "v1"),
            DocumentBinding("case-a", "doc-1", "v2"),
            DocumentBinding("CASE-A", "doc-1", "v1"),
            DocumentBinding("case-a", "DOC-1", "v1"),
            DocumentBinding("case-a", "doc-1", "V1"),
        )
        for binding in wrong:
            with self.subTest(binding=binding):
                self.assertRestoreRejected(
                    "BINDING_MISMATCH", safe.masked_bytes, manifest, binding, canaries=_CHINESE_VALUES
                )
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), corpus_doc("chinese").raw)

    def test_binding_is_checked_before_policy_digest_and_structure(self) -> None:
        masked, manifest = self.issue_tamper_doc()
        tampered = splice(masked, 0, 1, b"x")
        broken = dataclasses.replace(manifest, restore_policy="masked_only", schema_version="cb.mask.v0")
        self.assertRestoreRejected("BINDING_MISMATCH", tampered, broken, BINDING_B, canaries=TAMPER_VALUES)

    def test_invalid_binding_fields_are_refused_without_echoing_them(self) -> None:
        bad_values = [
            "", " ", "case 1", "case\n", "case-1\n", "\ncase", "-case", ".case", "_case", ":case",
            "案件", "ｃａｓｅ", "case/1", "case@example.com", NAME_A, "a" * 129, "a\x00b", "a\N{RIGHT-TO-LEFT OVERRIDE}b",
            "a b", "é", "٣", None, 1, b"case", ["case"], ("case",),
        ]  # fmt: skip
        for bad in bad_values:
            for position in range(3):
                fields = ["case-a", "doc-1", "v1"]
                fields[position] = bad
                with self.subTest(bad=bad, position=position):
                    self.assertRejected("INVALID_BINDING", DocumentBinding, *fields, canaries=[NAME_A])
        for good in ("a", "A1", "0", "case-1", "a" * 128, "x.y_z:1-2", "doc:1.2-3"):
            with self.subTest(good=good):
                self.assertEqual(DocumentBinding(good, good, good).case_id, good)

    def test_binding_is_immutable_and_hashable(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BINDING_A.case_id = "bad id"  # type: ignore[misc]
        twin = DocumentBinding("case-a", "doc-1", "v1")
        self.assertEqual(BINDING_A, twin)
        self.assertEqual(hash(BINDING_A), hash(twin))
        self.assertEqual({BINDING_A: 1}[twin], 1)
        self.assertNotEqual(BINDING_A, BINDING_B)

    def test_replacing_a_field_revalidates_it(self) -> None:
        self.assertRejected("INVALID_BINDING", dataclasses.replace, BINDING_A, case_id="bad id")
        self.assertEqual(dataclasses.replace(BINDING_A, case_id="case-z").case_id, "case-z")

    def test_objects_that_are_not_bindings_are_refused_everywhere(self) -> None:
        raw = corpus_doc("chinese").raw
        safe, manifest = self.mask(raw)
        registry = InMemoryManifestRegistry()
        registry.issue(raw, BINDING_A)
        for bad in (None, ("case-a", "doc-1", "v1"), {"case_id": "case-a"}, "case-a", object()):
            with self.subTest(bad=bad):
                self.assertRejected("INVALID_BINDING", mask_document, raw, bad)
                self.assertRejected("INVALID_BINDING", restore_original, safe.masked_bytes, manifest, bad)
                self.assertRejected("INVALID_BINDING", registry.issue, raw, bad)
                self.assertRejected(
                    "INVALID_BINDING", registry.restore_original, safe.masked_bytes, manifest_id=None, binding=bad
                )


# Proves #28 §10 PR A item 3c: manifest/digest tamper and out-of-range or overlapping offsets are refused.
class ManifestTamperTests(CoreTestCase):
    def setUp(self) -> None:
        self.masked, self.manifest = self.issue_tamper_doc()

    def reject(self, code: str, manifest: PrivateManifest, masked: bytes | None = None) -> None:
        self.assertRestoreRejected(code, self.masked if masked is None else masked, manifest, canaries=TAMPER_VALUES)

    def test_changed_original_digest_is_a_restore_digest_mismatch(self) -> None:
        self.reject("RESTORE_DIGEST_MISMATCH", dataclasses.replace(self.manifest, original_sha256=sha(b"other")))
        self.reject("RESTORE_DIGEST_MISMATCH", dataclasses.replace(self.manifest, original_sha256=sha(self.masked)))

    def test_malformed_digest_text_is_manifest_invalid(self) -> None:
        for bad in ("", "abc", self.manifest.original_sha256.upper(), "g" * 64, None, 5):
            with self.subTest(bad=bad):
                self.reject("MANIFEST_INVALID", dataclasses.replace(self.manifest, original_sha256=bad))

    def test_changed_masked_digest_in_the_manifest_is_a_masked_digest_mismatch(self) -> None:
        self.reject("MASKED_DIGEST_MISMATCH", dataclasses.replace(self.manifest, masked_sha256=sha(b"other")))
        self.reject("MASKED_DIGEST_MISMATCH", dataclasses.replace(self.manifest, masked_sha256=None))

    def test_swapped_values_of_equal_length_pass_structure_and_fail_the_final_digest(self) -> None:
        a, b = self.manifest.occurrences[0], self.manifest.occurrences[1]
        self.assertEqual(len(a.original_value), len(b.original_value))
        self.reject("RESTORE_DIGEST_MISMATCH", swap_values(self.manifest, 0, 1))
        replaced = replace_occurrence(self.manifest, 0, original_value=PrivateBytes("林美玲".encode()))
        self.reject("RESTORE_DIGEST_MISMATCH", replaced)

    def test_swapped_or_replaced_values_of_other_length_are_manifest_invalid(self) -> None:
        self.reject("MANIFEST_INVALID", swap_values(self.manifest, 0, 2))
        self.reject("MANIFEST_INVALID", replace_occurrence(self.manifest, 0, original_value=PrivateBytes(b"x")))
        self.reject("MANIFEST_INVALID", replace_occurrence(self.manifest, 0, original_value=PrivateBytes(b"")))

    def test_shifted_offsets_are_manifest_invalid(self) -> None:
        occ = self.manifest.occurrences[1]
        shifted_original = replace_occurrence(
            self.manifest,
            1,
            original_byte_start=occ.original_byte_start + 1,
            original_byte_end=occ.original_byte_end + 1,
        )
        self.reject("MANIFEST_INVALID", shifted_original)
        shifted_masked = replace_occurrence(
            self.manifest,
            1,
            masked_byte_start=occ.masked_byte_start + 1,
            masked_byte_end=occ.masked_byte_end + 1,
        )
        self.reject("MANIFEST_INVALID", shifted_masked)
        every_masked = tuple(
            dataclasses.replace(o, masked_byte_start=o.masked_byte_start + 1, masked_byte_end=o.masked_byte_end + 1)
            for o in self.manifest.occurrences
        )
        self.reject("MANIFEST_INVALID", dataclasses.replace(self.manifest, occurrences=every_masked))

    def test_out_of_range_offsets_are_manifest_invalid(self) -> None:
        last = len(self.manifest.occurrences) - 1
        occ = self.manifest.occurrences[last]
        total = len(self.masked)
        cases = {
            "masked end past the text": {"masked_byte_end": total + 1},
            "masked range past the text": {"masked_byte_start": total, "masked_byte_end": total + len(occ.token)},
            "original end huge": {"original_byte_end": 10**9},
            "masked end huge": {"masked_byte_end": 10**9},
            "negative original start": {"original_byte_start": -1},
            "negative masked start": {"masked_byte_start": -1},
            "float offset": {"original_byte_start": float(occ.original_byte_start)},
            "string offset": {"masked_byte_start": str(occ.masked_byte_start)},
            "bool offset": {"original_byte_start": True},
        }
        for name, changes in cases.items():
            with self.subTest(case=name):
                self.reject("MANIFEST_INVALID", replace_occurrence(self.manifest, last, **changes))

    def test_overlapping_unsorted_or_repeated_occurrences_are_manifest_invalid(self) -> None:
        first, second = self.manifest.occurrences[0], self.manifest.occurrences[1]
        length = second.original_byte_end - second.original_byte_start
        overlap_original = replace_occurrence(
            self.manifest,
            1,
            original_byte_start=first.original_byte_end - 1,
            original_byte_end=first.original_byte_end - 1 + length,
        )
        self.reject("MANIFEST_INVALID", overlap_original)
        overlap_masked = replace_occurrence(
            self.manifest,
            1,
            masked_byte_start=first.masked_byte_end - 1,
            masked_byte_end=first.masked_byte_end - 1 + len(second.token),
        )
        self.reject("MANIFEST_INVALID", overlap_masked)
        occurrences = self.manifest.occurrences
        self.reject("MANIFEST_INVALID", dataclasses.replace(self.manifest, occurrences=occurrences[::-1]))
        repeated = (occurrences[0], occurrences[0]) + occurrences[2:]
        self.reject("MANIFEST_INVALID", dataclasses.replace(self.manifest, occurrences=repeated))

    def test_overlap_that_keeps_the_offsets_consistent_is_still_refused(self) -> None:
        # Both coordinate systems are rewritten consistently, so only the explicit
        # non-overlap rule can object.
        first, second = self.manifest.occurrences[0], self.manifest.occurrences[1]
        delta = len(first.token) - len(first.original_value)
        start = first.original_byte_end - 1
        overlapping = replace_occurrence(
            self.manifest,
            1,
            original_byte_start=start,
            original_byte_end=start + len(second.original_value),
            masked_byte_start=start + delta,
            masked_byte_end=start + delta + len(second.token),
        )
        self.assertLess(overlapping.occurrences[1].original_byte_start, first.original_byte_end)
        self.assertLess(overlapping.occurrences[1].masked_byte_start, first.masked_byte_end)
        self.reject("MANIFEST_INVALID", overlapping)

    def test_ranges_that_disagree_with_value_and_token_lengths_are_manifest_invalid(self) -> None:
        for index in (0, 1, 3):
            occ = self.manifest.occurrences[index]
            cases = {
                "masked end one short": {"masked_byte_end": occ.masked_byte_end - 1},
                "masked end one long": {"masked_byte_end": occ.masked_byte_end + 1},
                "original end one short": {"original_byte_end": occ.original_byte_end - 1},
                "original end one long": {"original_byte_end": occ.original_byte_end + 1},
            }
            for name, changes in cases.items():
                with self.subTest(index=index, case=name):
                    self.reject("MANIFEST_INVALID", replace_occurrence(self.manifest, index, **changes))

    def test_truncated_masked_artifact_with_a_forged_digest_is_manifest_invalid(self) -> None:
        last = self.manifest.occurrences[-1]
        for cut in (last.masked_byte_end - 5, last.masked_byte_start + 3, last.masked_byte_start):
            truncated = self.masked[:cut]
            with self.subTest(cut=cut):
                self.reject("MASKED_DIGEST_MISMATCH", self.manifest, truncated)
                self.reject("MANIFEST_INVALID", forge_digest(self.manifest, truncated), truncated)

    def test_a_manifest_missing_an_occurrence_is_refused(self) -> None:
        occurrences = self.manifest.occurrences
        # Dropping a middle occurrence breaks the 1..n sequence.
        self.reject(
            "MANIFEST_INVALID", dataclasses.replace(self.manifest, occurrences=occurrences[:1] + occurrences[2:])
        )
        # Dropping the last (or all) leaves tokens in the text that nobody issued.
        self.reject("UNKNOWN_TOKEN", dataclasses.replace(self.manifest, occurrences=occurrences[:-1]))
        self.reject("UNKNOWN_TOKEN", dataclasses.replace(self.manifest, occurrences=()))

    def test_structural_violations_are_manifest_invalid(self) -> None:
        namespace = self.manifest.token_namespace
        first = self.manifest.occurrences[0]
        cases = {
            "other schema": lambda m: dataclasses.replace(m, schema_version="cb.mask.v2"),
            "other encoding": lambda m: dataclasses.replace(m, encoding="utf-16"),
            "other newline policy": lambda m: dataclasses.replace(m, newline_policy="normalize"),
            "bom flag flipped": lambda m: dataclasses.replace(m, bom=not m.bom),
            "bom flag not a bool": lambda m: dataclasses.replace(m, bom=0),
            "namespace uppercase": lambda m: dataclasses.replace(m, token_namespace=namespace.upper()),
            "namespace short": lambda m: dataclasses.replace(m, token_namespace=namespace[:-1]),
            "namespace not a string": lambda m: dataclasses.replace(m, token_namespace=None),
            "occurrences as list": lambda m: dataclasses.replace(m, occurrences=list(m.occurrences)),
            "entity type mismatch": lambda m: replace_occurrence(m, 0, entity_type="EMAIL"),
            "unknown detector class": lambda m: replace_occurrence(m, 0, detector_class="ssn"),
            "token of another namespace": lambda m: replace_occurrence(m, 0, token=make_token("PERSON", "z" * 28, 1)),
            "token of another type": lambda m: replace_occurrence(m, 0, token=make_token("EMAIL", namespace, 1)),
            "token of another sequence": lambda m: replace_occurrence(m, 0, token=make_token("PERSON", namespace, 7)),
            "token not a string": lambda m: replace_occurrence(m, 0, token=None),
            "duplicate occurrence id": lambda m: replace_occurrence(m, 1, occurrence_id=first.occurrence_id),
            "duplicate entity id": lambda m: replace_occurrence(m, 1, entity_id=first.entity_id),
            "invalid occurrence id": lambda m: replace_occurrence(m, 0, occurrence_id="bad id"),
            "other segment": lambda m: replace_occurrence(m, 0, segment_id="header"),
            "value is plain bytes": lambda m: replace_occurrence(m, 0, original_value=first.original_value.reveal()),
            "occurrence is not an Occurrence": lambda m: dataclasses.replace(
                m, occurrences=(object(),) + m.occurrences[1:]
            ),
        }
        for name, tamper in cases.items():
            with self.subTest(case=name):
                self.reject("MANIFEST_INVALID", tamper(self.manifest))

    def test_restore_policy_other_than_original_in_place_is_not_permitted(self) -> None:
        for policy in ("masked_only", "bogus", "", None, "ORIGINAL_IN_PLACE"):
            with self.subTest(policy=policy):
                self.reject("RESTORE_NOT_PERMITTED", dataclasses.replace(self.manifest, restore_policy=policy))
        self.assertEqual(restore_original(self.masked, self.manifest, BINDING_A), TAMPER_TEXT.encode("utf-8"))

    def test_manifest_and_occurrences_are_immutable(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.manifest.restore_policy = "masked_only"  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.manifest.occurrences[0].original_byte_start = 0  # type: ignore[misc]
        self.assertIsInstance(self.manifest.occurrences, tuple)
        self.assertEqual(restore_original(self.masked, self.manifest, BINDING_A), TAMPER_TEXT.encode("utf-8"))

    def test_arguments_of_the_wrong_type_are_refused(self) -> None:
        for bad in (None, object(), {}, "manifest"):
            with self.subTest(manifest=bad):
                self.assertRejected("MANIFEST_INVALID", restore_original, self.masked, bad, BINDING_A)
                self.assertRejected("MANIFEST_INVALID", check_release_text, "text", bad)
        for bad in ("text", bytearray(self.masked), memoryview(self.masked), None, 5):
            with self.subTest(masked=type(bad).__name__):
                self.assertRejected("INVALID_INPUT_TYPE", restore_original, bad, self.manifest, BINDING_A)
        for bad in (b"text", None, 5):
            with self.subTest(text=type(bad).__name__):
                self.assertRejected("INVALID_INPUT_TYPE", check_release_text, bad, self.manifest)

    def test_restore_checks_run_in_the_documented_order(self) -> None:
        masked, manifest = self.masked, self.manifest
        tail = len(masked) - 1
        plain_tamper = splice(masked, 0, 1, b"x")
        invalid_utf8 = splice(masked, tail, tail + 1, b"\xff")
        missing = token_tampers(masked, manifest)["missing_replaced_by_filler"][0]
        broken = dataclasses.replace(manifest, schema_version="cb.mask.v0")
        equal_swap = swap_values(manifest, 0, 1)
        steps = (
            # (expected code, masked bytes, manifest, binding)
            ("BINDING_MISMATCH", plain_tamper, dataclasses.replace(manifest, restore_policy="masked_only"), BINDING_B),
            (
                "RESTORE_NOT_PERMITTED",
                plain_tamper,
                dataclasses.replace(manifest, restore_policy="masked_only"),
                BINDING_A,
            ),
            ("MASKED_DIGEST_MISMATCH", plain_tamper, broken, BINDING_A),
            ("INVALID_UTF8", invalid_utf8, forge_digest(broken, invalid_utf8), BINDING_A),
            ("MANIFEST_INVALID", missing, forge_digest(broken, missing), BINDING_A),
            ("MISSING_TOKEN", missing, forge_digest(equal_swap, missing), BINDING_A),
        )
        for code, data, tampered_manifest, binding in steps:
            with self.subTest(code=code):
                self.assertRestoreRejected(code, data, tampered_manifest, binding, canaries=TAMPER_VALUES)


# Proves #28 §10 PR A item 3d: reserved prefix, invalid UTF-8, size, span conflict and residual PII are refused.
class InputRejectionTests(CoreTestCase):
    CANARIES = [NAME_A, EMAIL_A, RESIDUAL_ONLY_ID]

    def test_reserved_prefix_is_refused_in_any_case(self) -> None:
        full = make_token("PERSON", "a" * 28, 1)
        variants = [full, full.lower(), "[[cb1:", "[[Cb", "[[CB", "[[cB1:PERSON", "x[[CB", "[[CBy"]
        for variant in variants:
            with self.subTest(variant=variant):
                raw = f"申請人：{NAME_A}\n{variant}\n聯絡信箱：{EMAIL_A}\n".encode("utf-8")
                self.assertRejected("RESERVED_TOKEN_COLLISION", mask_document, raw, BINDING_A, canaries=self.CANARIES)
        for raw in (BOM + b"[[CB1:", b"[[cb", f"{NAME_A} [[Cb".encode("utf-8")):
            with self.subTest(raw=raw):
                self.assertRejected("RESERVED_TOKEN_COLLISION", mask_document, raw, BINDING_A, canaries=self.CANARIES)

    def test_near_misses_of_the_reserved_prefix_pass_through(self) -> None:
        text = f"備註 [[C B]] [CB1] [[ CB1 ]] CB1:PERSON:x ［［CB1:］］ [C[B 申請人：{NAME_A}\n"
        safe, manifest = self.mask(text)
        self.assertEqual(len(manifest.occurrences), 1)
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), text.encode("utf-8"))

    def test_invalid_utf8_is_refused_without_echoing_the_input(self) -> None:
        prefix = f"申請人：{NAME_A} ".encode("utf-8")
        cases = {
            "lone continuation byte": b"\xff",
            "truncated multibyte": "申請人：王".encode("utf-8")[:-1],
            "encoded surrogate": b"\xed\xa0\x80",
            "overlong encoding": b"\xc0\x80",
            "utf-16 with bom": f"申請人：{NAME_A}".encode("utf-16"),
            "latin-1 text": "é".encode("latin-1"),
            "big5 text": f"申請人：{NAME_A}".encode("big5"),
            "pii then a bad byte": prefix + b"\xff",
            "bad byte then pii": b"\xff" + prefix,
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                self.assertRejected("INVALID_UTF8", mask_document, raw, BINDING_A, canaries=self.CANARIES)

    def test_document_too_large_uses_the_current_limit(self) -> None:
        self.assertEqual(rm.MAX_DOCUMENT_BYTES, 25 * 1024 * 1024)
        with patch.object(rm, "MAX_DOCUMENT_BYTES", 16):
            safe, manifest = self.mask(b"a" * 16)
            self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), b"a" * 16)
            self.assertRejected("DOCUMENT_TOO_LARGE", mask_document, b"a" * 17, BINDING_A)
            # The size check runs before decoding.
            self.assertRejected("DOCUMENT_TOO_LARGE", mask_document, b"\xff" * 17, BINDING_A)
            self.assertRejected(
                "DOCUMENT_TOO_LARGE",
                mask_document,
                f"申請人：{NAME_A}".encode("utf-8") + b" " * 20,
                BINDING_A,
                canaries=[NAME_A],
            )

    def test_too_many_occurrences_uses_the_current_limit(self) -> None:
        self.assertEqual(rm.MAX_OCCURRENCES, 999_999)
        text = "".join(f"聯絡信箱：user{i}@example.com\n" for i in range(3))
        with patch.object(rm, "MAX_OCCURRENCES", 3):
            safe, manifest = self.mask(text)
            self.assertEqual(len(manifest.occurrences), 3)
            self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), text.encode("utf-8"))
        with patch.object(rm, "MAX_OCCURRENCES", 2):
            self.assertRejected("TOO_MANY_OCCURRENCES", mask_document, text.encode("utf-8"), BINDING_A)

    def test_span_conflict_fails_the_whole_document(self) -> None:
        crossing = "生日：1-02-12345678\n"
        self.assertRejected("SPAN_CONFLICT", mask_document, crossing.encode("utf-8"), BINDING_A)
        doc = f"申請人：{NAME_A}\n{crossing}聯絡信箱：{EMAIL_A}\n".encode("utf-8")
        self.assertRejected("SPAN_CONFLICT", mask_document, doc, BINDING_A, canaries=[NAME_A, EMAIL_A])

    def test_input_checks_run_in_the_documented_order(self) -> None:
        crossing = "生日：1-02-12345678\n"
        self.assertRejected("INVALID_UTF8", mask_document, b"[[CB1:\xff", BINDING_A)
        self.assertRejected("RESERVED_TOKEN_COLLISION", mask_document, f"[[CB1:\n{crossing}".encode(), BINDING_A)
        with self.assertRaises(ReversibleMaskingError) as raised:
            mask_document(f"{crossing}證件 AB1234567 已附。\n".encode(), BINDING_A)
        self.assertEqual(raised.exception.code, "SPAN_CONFLICT")

    def test_shape_only_the_residual_detector_knows_blocks_the_document(self) -> None:
        for text in ("證件 AB1234567 已附。\n", f"申請人：{NAME_A}\n證件 AB1234567 已附。\n"):
            with self.subTest(text=text):
                with self.assertRaises(ResidualPiiBlocked) as raised:
                    mask_document(text.encode("utf-8"), BINDING_A)
                error = raised.exception
                self.assertEqual(str(error), "RESIDUAL_PII_BLOCKED")
                self.assertEqual(error.args, ("RESIDUAL_PII_BLOCKED",))
                self.assertIn("mixed_identity_candidate", error.classes)
                self.assertCleanError(error, self.CANARIES)
        # Masking.PATTERNS alone would have let this through as masked output.
        self.assertEqual(find_sensitive_classes("證件 AB1234567 已附。\n"), [])

    def test_wrong_input_types_are_refused(self) -> None:
        for bad in ("申請人：王大明", bytearray(b"abc"), memoryview(b"abc"), None, 5, ["a"]):
            with self.subTest(bad=type(bad).__name__):
                self.assertRejected("INVALID_INPUT_TYPE", mask_document, bad, BINDING_A)

    def test_retention_deadline_must_be_none_or_a_finite_number(self) -> None:
        raw = corpus_doc("lf").raw
        for bad in (float("nan"), float("inf"), float("-inf"), True, False, "5", [], (1,)):
            with self.subTest(bad=bad):
                self.assertRejected("INVALID_RETENTION_DEADLINE", mask_document, raw, BINDING_A, retention_deadline=bad)
        for good in (None, 0, 1, 1.5, 10**12):
            with self.subTest(good=good):
                _, manifest = self.mask(raw, retention_deadline=good)
                self.assertEqual(manifest.retention_deadline, good)


# Proves #28 §10 PR A item 3e and §5: only manifest-issued tokens pass the release scan; the rest is scanned.
class ReleaseScanTests(CoreTestCase):
    def setUp(self) -> None:
        self.safe, self.manifest = self.mask(corpus_doc("chinese").raw)
        self.tokens = [o.token for o in self.manifest.occurrences]
        self.namespace = self.manifest.token_namespace

    def test_masked_output_passes_its_own_scan(self) -> None:
        self.assertIsNone(check_release_text(self.safe.masked_text, self.manifest))
        self.assertIsNone(check_release_text(" ".join(self.tokens), self.manifest))

    def test_forged_or_foreign_tokens_are_unknown(self) -> None:
        _, other = self.mask(corpus_doc("chinese").raw, BINDING_B)
        forged = {
            "foreign namespace": make_token("PERSON", "z" * 28, 1),
            "other manifest": other.occurrences[0].token,
            "unissued sequence": make_token("PERSON", self.namespace, 99),
            "type confusion": make_token("EMAIL", self.namespace, 1),
            "unissued type": make_token("PARCEL_ID", self.namespace, 1),
        }
        for name, token in forged.items():
            with self.subTest(forged=name):
                self.assertRejected("UNKNOWN_TOKEN", check_release_text, f"備註 {token} 結束", self.manifest)
                self.assertRejected("UNKNOWN_TOKEN", check_release_text, self.safe.masked_text + token, self.manifest)

    def test_malformed_fragments_are_rejected(self) -> None:
        good = self.tokens[0]
        fragments = {
            "bare prefix": "[[CB",
            "open fragment": "[[CB1:",
            "short namespace": "[[CB1:PERSON:short:000001]]",
            "lowercase prefix": good.replace("[[CB1:", "[[cb1:"),
            "mixed case prefix": good.replace("[[CB1:", "[[Cb1:"),
            "unclosed": good[:-2],
            "uppercase namespace": good.replace(self.namespace, self.namespace.upper()),
            "non-ascii digits": good.replace(":000001]]", ":٠٠٠٠٠١]]"),
            "split by newline": good[:20] + "\n" + good[20:],
            "wrong version": good.replace("CB1", "CB2"),
        }
        for name, fragment in fragments.items():
            with self.subTest(fragment=name):
                self.assertRejected("MALFORMED_TOKEN", check_release_text, f"備註 {fragment} 結束", self.manifest)

    def test_scan_categories_are_malformed_then_unknown_then_residual(self) -> None:
        unknown = make_token("PERSON", "z" * 28, 1)
        malformed = "[[cb1:"
        self.assertRejected("MALFORMED_TOKEN", check_release_text, f"{unknown} {malformed} {ID_A}", self.manifest)
        self.assertRejected("UNKNOWN_TOKEN", check_release_text, f"{ID_A} {unknown}", self.manifest)
        with self.assertRaises(ResidualPiiBlocked):
            check_release_text(f"{self.tokens[0]} {ID_A}", self.manifest)

    def test_pii_next_to_a_valid_token_is_still_blocked(self) -> None:
        suffixes = (ID_A, EMAIL_A, MOBILE_A, ADDRESS_A, RESIDUAL_ONLY_ID, f"申請人：{NAME_B}")
        for suffix in suffixes:
            for glue in ("", " ", "\n", "，"):
                with self.subTest(suffix=suffix, glue=glue):
                    with self.assertRaises(ResidualPiiBlocked) as raised:
                        check_release_text(f"{self.tokens[0]}{glue}{suffix}", self.manifest)
                    self.assertEqual(str(raised.exception), "RESIDUAL_PII_BLOCKED")
                    self.assertCleanError(raised.exception, [suffix])
        with self.assertRaises(ResidualPiiBlocked):
            check_release_text(f"{self.tokens[0]} 與 {ID_A} 及 {self.tokens[1]}", self.manifest)

    def test_the_scan_is_a_membership_check_not_a_completeness_check(self) -> None:
        for text in (
            "",
            "沒有任何標記",
            self.tokens[0],
            f"{self.tokens[1]} {self.tokens[1]}",
            "".join(self.tokens[::-1]),
        ):
            with self.subTest(text=text):
                self.assertIsNone(check_release_text(text, self.manifest))

    def test_look_alike_brackets_that_are_not_ascii_are_not_tokens(self) -> None:
        self.assertIsNone(check_release_text("［［CB1:PERSON］］ 【【CB】】", self.manifest))

    def test_each_issued_token_is_inert_for_both_detector_sets(self) -> None:
        for token in self.tokens:
            with self.subTest(token=token):
                self.assertEqual(find_sensitive_classes(token), [])
                self.assertEqual(find_residual_sensitive_classes(token), [])


# Proves #28 §10 PR A item 3f: legacy, unknown, discarded and expired mappings are refused; versions are immutable.
class RegistryAndLegacyMappingTests(CoreTestCase):
    def registry(self, now: float = 1000.0) -> tuple[InMemoryManifestRegistry, FakeClock]:
        clock = FakeClock(now)
        return InMemoryManifestRegistry(clock=clock), clock

    def test_legacy_marker_output_has_no_mapping_and_is_never_guessed(self) -> None:
        legacy = mask_sensitive_text(GOLDEN_TEXT).text.encode("utf-8")
        self.assertIn(b"[MASKED_", legacy)
        registry, _ = self.registry()
        live = registry.issue(corpus_doc("chinese").raw, BINDING_A)
        canaries = [NAME_A, MOBILE_A, EMAIL_A, ADDRESS_A]
        for manifest_id in (None, str(uuid.uuid4()), "not-a-uuid", ""):
            with self.subTest(manifest_id=manifest_id):
                self.assertRejected(
                    "LEGACY_MAPPING_UNAVAILABLE",
                    registry.restore_original,
                    legacy,
                    manifest_id=manifest_id,
                    binding=BINDING_A,
                    canaries=canaries,
                )
        for name, _ in PATTERNS:
            with self.subTest(marker=name):
                marker = f"申請人 [MASKED_{name.upper()}] 結束".encode("utf-8")
                self.assertRejected(
                    "LEGACY_MAPPING_UNAVAILABLE",
                    registry.restore_original,
                    marker,
                    manifest_id=None,
                    binding=BINDING_A,
                )
        # With a live manifest present, legacy bytes are simply not its masked artifact.
        self.assertRejected(
            "MASKED_DIGEST_MISMATCH",
            registry.restore_original,
            legacy,
            manifest_id=live.manifest_id,
            binding=BINDING_A,
            canaries=canaries,
        )

    def test_decoys_and_plain_text_are_plain_unavailable(self) -> None:
        registry, _ = self.registry()
        decoys = (b"[MASKED_FOO]", b"[masked_name]", b"[MASKED_NAME", b"MASKED_NAME]", "申請人：王大明".encode(), b"")
        for data in decoys:
            with self.subTest(data=data):
                self.assertRejected(
                    "MAPPING_UNAVAILABLE",
                    registry.restore_original,
                    data,
                    manifest_id=None,
                    binding=BINDING_A,
                    canaries=[NAME_A],
                )

    def test_unknown_discarded_and_expired_manifests_are_unavailable(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, clock = self.registry(1000.0)
        safe = registry.issue(raw, BINDING_A, retention_deadline=1100.0)

        def restore(masked=safe.masked_bytes):
            return registry.restore_original(masked, manifest_id=safe.manifest_id, binding=BINDING_A)

        self.assertEqual(restore(), raw)
        clock.now = 1099.999
        self.assertEqual(restore(), raw)
        clock.now = 1100.0  # the deadline itself is already expired
        self.assertRejected("MAPPING_UNAVAILABLE", restore, canaries=_CHINESE_VALUES)
        clock.now = 0.0  # a clock that runs backwards cannot resurrect a purged mapping
        self.assertRejected("MAPPING_UNAVAILABLE", restore, canaries=_CHINESE_VALUES)
        self.assertRejected(
            "LEGACY_MAPPING_UNAVAILABLE",
            registry.restore_original,
            b"[MASKED_NAME]",
            manifest_id=safe.manifest_id,
            binding=BINDING_A,
        )
        self.assertRejected(
            "MAPPING_UNAVAILABLE",
            registry.restore_original,
            safe.masked_bytes,
            manifest_id=str(uuid.uuid4()),
            binding=BINDING_A,
        )
        self.assertRejected(
            "MAPPING_UNAVAILABLE", registry.restore_original, safe.masked_bytes, manifest_id=None, binding=BINDING_A
        )

    def test_discarded_manifest_is_unavailable_and_discard_is_idempotent(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, _ = self.registry()
        kept = registry.issue(raw, BINDING_B)
        gone = registry.issue(raw, BINDING_A)
        self.assertEqual(
            registry.restore_original(gone.masked_bytes, manifest_id=gone.manifest_id, binding=BINDING_A), raw
        )
        self.assertIsNone(registry.discard(gone.manifest_id))
        self.assertIsNone(registry.discard(gone.manifest_id))
        self.assertIsNone(registry.discard(str(uuid.uuid4())))
        self.assertRejected(
            "MAPPING_UNAVAILABLE",
            registry.restore_original,
            gone.masked_bytes,
            manifest_id=gone.manifest_id,
            binding=BINDING_A,
            canaries=_CHINESE_VALUES,
        )
        self.assertEqual(
            registry.restore_original(kept.masked_bytes, manifest_id=kept.manifest_id, binding=BINDING_B), raw
        )

    def test_binding_is_enforced_through_the_registry(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, _ = self.registry()
        safe = registry.issue(raw, BINDING_A)
        self.assertRejected(
            "BINDING_MISMATCH",
            registry.restore_original,
            safe.masked_bytes,
            manifest_id=safe.manifest_id,
            binding=BINDING_B,
            canaries=_CHINESE_VALUES,
        )

    def test_registry_keeps_cases_apart(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, _ = self.registry()
        safe_a = registry.issue(raw, BINDING_A)
        safe_b = registry.issue(raw, BINDING_B)
        self.assertNotEqual(safe_a.manifest_id, safe_b.manifest_id)
        self.assertNotEqual(safe_a.masked_text, safe_b.masked_text)
        self.assertRejected(
            "MASKED_DIGEST_MISMATCH",
            registry.restore_original,
            safe_a.masked_bytes,
            manifest_id=safe_b.manifest_id,
            binding=BINDING_B,
            canaries=_CHINESE_VALUES,
        )
        self.assertRejected(
            "BINDING_MISMATCH",
            registry.restore_original,
            safe_a.masked_bytes,
            manifest_id=safe_a.manifest_id,
            binding=BINDING_B,
            canaries=_CHINESE_VALUES,
        )

    def test_idempotent_reissue_returns_the_identical_safe_document(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, _ = self.registry()
        first = registry.issue(raw, BINDING_A)
        again = registry.issue(bytes(bytearray(raw)), DocumentBinding("case-a", "doc-1", "v1"))
        third = registry.issue(raw, BINDING_A)
        self.assertEqual(first, again)
        self.assertEqual(first, third)
        self.assertEqual(first.masked_bytes, again.masked_bytes)
        self.assertEqual(first.manifest_id, third.manifest_id)
        self.assertIsInstance(first, SafeMaskedDocument)
        self.assertEqual(
            registry.restore_original(again.masked_bytes, manifest_id=again.manifest_id, binding=BINDING_A), raw
        )

    def test_same_binding_with_other_content_is_refused_and_changes_nothing(self) -> None:
        raw = corpus_doc("chinese").raw
        other = corpus_doc("lf").raw
        registry, _ = self.registry()
        safe = registry.issue(raw, BINDING_A)
        self.assertRejected(
            "VERSION_CONTENT_MISMATCH", registry.issue, other, BINDING_A, canaries=_CHINESE_VALUES + [NAME_B]
        )
        self.assertEqual(
            registry.restore_original(safe.masked_bytes, manifest_id=safe.manifest_id, binding=BINDING_A), raw
        )
        self.assertEqual(registry.issue(raw, BINDING_A), safe)
        self.assertEqual(registry.issue(other, BINDING_B).binding, BINDING_B)

    def test_same_binding_under_changed_versions_is_refused(self) -> None:
        raw = corpus_doc("chinese").raw
        for attribute in ("DETECTOR_VERSION", "POLICY_VERSION", "PARSER_VERSION"):
            with self.subTest(version=attribute):
                registry, _ = self.registry()
                safe = registry.issue(raw, BINDING_A)
                with patch.object(rm, attribute, "changed-for-test"):
                    self.assertRejected("VERSION_CONTENT_MISMATCH", registry.issue, raw, BINDING_A)
                    # The old manifest keeps its own provenance and still restores.
                    self.assertEqual(
                        registry.restore_original(safe.masked_bytes, manifest_id=safe.manifest_id, binding=BINDING_A),
                        raw,
                    )
                    fresh = registry.issue(raw, BINDING_B)
                    recorded = {
                        "DETECTOR_VERSION": fresh.detector_version,
                        "POLICY_VERSION": fresh.policy_version,
                        "PARSER_VERSION": fresh.parser_version,
                    }
                    self.assertEqual(recorded[attribute], "changed-for-test")

    def test_a_retry_cannot_extend_retention(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, clock = self.registry(1000.0)
        first = registry.issue(raw, BINDING_A, retention_deadline=1100.0)
        clock.now = 1050.0
        retry = registry.issue(raw, BINDING_A, retention_deadline=9999.0)
        self.assertEqual(first, retry)
        clock.now = 1100.0
        self.assertRejected(
            "MAPPING_UNAVAILABLE",
            registry.restore_original,
            first.masked_bytes,
            manifest_id=first.manifest_id,
            binding=BINDING_A,
        )

    def test_reissue_after_expiry_returns_a_new_restorable_document(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, clock = self.registry(1000.0)
        old = registry.issue(raw, BINDING_A, retention_deadline=1100.0)
        clock.now = 1100.0
        new = registry.issue(raw, BINDING_A)
        self.assertNotEqual(new.manifest_id, old.manifest_id)
        self.assertNotEqual(new.masked_text, old.masked_text)
        self.assertEqual(
            registry.restore_original(new.masked_bytes, manifest_id=new.manifest_id, binding=BINDING_A), raw
        )
        self.assertRejected(
            "MAPPING_UNAVAILABLE",
            registry.restore_original,
            old.masked_bytes,
            manifest_id=old.manifest_id,
            binding=BINDING_A,
        )

    def test_a_failed_issue_registers_nothing(self) -> None:
        registry, _ = self.registry()
        failing = (
            f"申請人：{NAME_A}\n生日：1-02-12345678\n".encode("utf-8"),
            f"申請人：{NAME_A}\n[[CB1:\n".encode("utf-8"),
            f"申請人：{NAME_A}\n證件 AB1234567 已附。\n".encode("utf-8"),
            f"申請人：{NAME_A}\n".encode("utf-8") + b"\xff",
        )
        for raw in failing:
            with self.subTest(raw=raw):
                with self.assertRaises((ReversibleMaskingError, ResidualPiiBlocked)):
                    registry.issue(raw, BINDING_A)
        good = corpus_doc("chinese").raw
        safe = registry.issue(good, BINDING_A)  # no VERSION_CONTENT_MISMATCH left behind
        self.assertEqual(
            registry.restore_original(safe.masked_bytes, manifest_id=safe.manifest_id, binding=BINDING_A), good
        )

    def test_registry_arguments_are_validated(self) -> None:
        registry, _ = self.registry()
        for bad in ("申請人：王大明", bytearray(b"abc"), None, 5):
            with self.subTest(original=type(bad).__name__):
                self.assertRejected("INVALID_INPUT_TYPE", registry.issue, bad, BINDING_A)
                self.assertRejected(
                    "INVALID_INPUT_TYPE", registry.restore_original, bad, manifest_id=None, binding=BINDING_A
                )
        for bad in (float("nan"), float("inf"), True, "5"):
            with self.subTest(deadline=bad):
                self.assertRejected(
                    "INVALID_RETENTION_DEADLINE", registry.issue, b"abc", BINDING_A, retention_deadline=bad
                )

    def test_registry_never_hands_out_a_manifest(self) -> None:
        raw = corpus_doc("chinese").raw
        registry, _ = self.registry()
        public = sorted(name for name in dir(registry) if not name.startswith("_"))
        self.assertEqual(public, ["discard", "issue", "restore_original"])
        safe = registry.issue(raw, BINDING_A)
        self.assertIsInstance(safe, SafeMaskedDocument)
        self.assertNotIsInstance(safe, PrivateManifest)
        restored = registry.restore_original(safe.masked_bytes, manifest_id=safe.manifest_id, binding=BINDING_A)
        self.assertIsInstance(restored, bytes)
        self.assertNoLeak(repr(registry) + str(registry), _CHINESE_VALUES, "in registry repr")

    def test_concurrent_issue_of_one_binding_creates_one_manifest(self) -> None:
        raw = ("申請人：王大明\n聯絡信箱：owner@example.com\n" * 40).encode("utf-8")
        parties = 8
        for round_number in range(15):
            registry = InMemoryManifestRegistry()
            binding = DocumentBinding("case-race", f"doc-{round_number}", "v1")
            barrier = threading.Barrier(parties)

            def work() -> SafeMaskedDocument:
                barrier.wait()
                return registry.issue(raw, binding)

            with ThreadPoolExecutor(max_workers=parties) as pool:
                results = [future.result() for future in [pool.submit(work) for _ in range(parties)]]
            with self.subTest(round=round_number):
                self.assertEqual(len({safe.manifest_id for safe in results}), 1)
                self.assertTrue(all(safe == results[0] for safe in results))

    def test_concurrent_restore_and_discard_never_return_wrong_bytes(self) -> None:
        raw = corpus_doc("chinese").raw
        registry = InMemoryManifestRegistry()
        safe = registry.issue(raw, BINDING_A)
        barrier = threading.Barrier(9)

        def restore_many() -> list[str]:
            outcomes = []
            barrier.wait()
            for _ in range(60):
                try:
                    data = registry.restore_original(safe.masked_bytes, manifest_id=safe.manifest_id, binding=BINDING_A)
                except ReversibleMaskingError as error:
                    outcomes.append(error.code)
                else:
                    outcomes.append("ok" if data == raw else "WRONG_BYTES")
            return outcomes

        def discard_once() -> list[str]:
            barrier.wait()
            registry.discard(safe.manifest_id)
            return []

        with ThreadPoolExecutor(max_workers=9) as pool:
            futures = [pool.submit(restore_many) for _ in range(8)] + [pool.submit(discard_once)]
            seen = {outcome for future in futures for outcome in future.result()}
        self.assertLessEqual(seen, {"ok", "MAPPING_UNAVAILABLE"})
        self.assertRejected(
            "MAPPING_UNAVAILABLE",
            registry.restore_original,
            safe.masked_bytes,
            manifest_id=safe.manifest_id,
            binding=BINDING_A,
        )


# Proves #28 §10 PR A item 4 (meta): the canary checker sees every encoding, so zero hits are meaningful.
class LeakCheckerSelfTests(CoreTestCase):
    def test_the_leak_detector_itself_sees_every_encoding(self) -> None:
        # Without this, "zero hits" below could just mean the checker is blind.
        for value in (NAME_A, EMAIL_A, MOBILE_A, ADDRESS_A, ID_A):
            for form in leak_forms(value):
                with self.subTest(value=value, form=form):
                    with self.assertRaises(AssertionError):
                        self.assertNoLeak(f"前 {form} 後", [value])
        for text in (
            json.dumps({"v": NAME_A}),
            json.dumps({"v": NAME_A}, ensure_ascii=False),
            re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m.group(1).upper(), json.dumps({"v": NAME_A})),
            json.dumps({"v": EMAIL_A}),
        ):
            with self.assertRaises(AssertionError):
                self.assertNoLeak(text, [NAME_A, EMAIL_A])
        self.assertNoLeak("[[CB1:PERSON:" + "a" * 28 + ":000001]]", ALL_CLASSES_VALUES)

    def test_exception_class_carries_a_code_and_nothing_else(self) -> None:
        error = ReversibleMaskingError("MASKED_DIGEST_MISMATCH")
        self.assertIsInstance(error, ValueError)
        self.assertEqual(error.code, "MASKED_DIGEST_MISMATCH")
        self.assertEqual(str(error), "MASKED_DIGEST_MISMATCH")
        self.assertEqual(error.args, ("MASKED_DIGEST_MISMATCH",))
        self.assertNotIsInstance(error, ResidualPiiBlocked)
        self.assertNotIsInstance(ResidualPiiBlocked(["x"]), ReversibleMaskingError)


# Proves #28 §10 PR A item 4: zero raw-canary hits in safe DTO, reprs, errors, logs and outbound payload.
class LeakProofTests(CoreTestCase):
    def setUp(self) -> None:
        self.raw = ALL_CLASSES_TEXT.encode("utf-8")
        self.canaries = ALL_CLASSES_VALUES
        self.safe, self.manifest = self.mask(self.raw)
        self.original_digest = sha(self.raw)

    def test_no_canary_in_any_safe_surface(self) -> None:
        safe = self.safe
        payload = safe.outbound_payload()
        surfaces = {
            "repr": repr(safe),
            "str": str(safe),
            "masked_text": safe.masked_text,
            "masked_bytes": safe.masked_bytes.decode("utf-8"),
            "payload repr": repr(payload),
            "payload json utf-8": json.dumps(payload, ensure_ascii=False),
            "payload json ascii": json.dumps(payload, ensure_ascii=True),
            "payload json sorted": json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2),
        }
        for field in dataclasses.fields(safe):
            surfaces[f"field {field.name}"] = repr(getattr(safe, field.name))
        for where, text in surfaces.items():
            with self.subTest(surface=where):
                self.assertNoLeak(text, self.canaries, f"in {where}")
        for where in ("repr", "str", "payload json utf-8", "payload json ascii", "payload repr"):
            self.assertNotIn(self.original_digest, surfaces[where], where)

    def test_values_exist_only_in_private_structures(self) -> None:
        revealed = [o.original_value.reveal().decode("utf-8") for o in self.manifest.occurrences]
        self.assertEqual(revealed, ALL_CLASSES_VALUES)  # positive control
        names = {f.name for f in dataclasses.fields(SafeMaskedDocument)}
        self.assertEqual(
            names,
            {
                "schema_version", "manifest_id", "binding", "masked_text", "masked_sha256", "mask_counts",
                "occurrence_count", "parser_version", "policy_version", "detector_version", "status",
            },
        )  # fmt: skip
        for field in dataclasses.fields(self.safe):
            value = getattr(self.safe, field.name)
            self.assertNotIsInstance(value, (PrivateBytes, Occurrence, PrivateManifest, bytes, bytearray))
        self.assertNotEqual(self.safe.masked_sha256, self.manifest.original_sha256)
        self.assertEqual(self.manifest.original_sha256, self.original_digest)

    def test_private_objects_have_redacted_repr_and_str(self) -> None:
        values = [o.original_value for o in self.manifest.occurrences]
        self.assertEqual([v.reveal().decode("utf-8") for v in values], ALL_CLASSES_VALUES)  # positive control
        everything = [self.manifest, *self.manifest.occurrences, *values]
        for obj in everything:
            for render in (repr, str, format, lambda o: f"{o}", lambda o: "%s" % (o,), lambda o: "%r" % (o,)):
                self.assertNoLeak(render(obj), self.canaries, f"in {type(obj).__name__} rendering")
        for container in (
            self.manifest.occurrences,
            list(values),
            {"value": values[0], "manifest": self.manifest},
            (values[0], self.manifest.occurrences[0]),
        ):
            self.assertNoLeak(repr(container) + str(container), self.canaries, "in a container rendering")

    def test_manifest_repr_names_only_id_schema_and_count(self) -> None:
        text = repr(self.manifest) + str(self.manifest)
        self.assertIn(self.manifest.manifest_id, text)
        self.assertIn(self.manifest.schema_version, text)
        hidden = [
            self.manifest.original_sha256,
            self.manifest.masked_sha256,
            self.manifest.token_namespace,
            self.manifest.binding.case_id,
            self.manifest.binding.document_id,
            *(o.token for o in self.manifest.occurrences),
            *(o.occurrence_id for o in self.manifest.occurrences),
        ]
        for item in hidden:
            self.assertNotIn(item, text)

    def test_private_bytes_refuses_every_bulk_accessor(self) -> None:
        occurrence = self.manifest.occurrences[0]
        private = occurrence.original_value
        self.assertEqual(private.reveal(), NAME_A.encode("utf-8"))  # positive control first
        self.assertEqual(len(private), 9)
        operations = {
            "bytes()": lambda: bytes(private),
            "iter()": lambda: iter(private),
            "index": lambda: private[0],
            "slice": lambda: private[0:1],
            "contains": lambda: b"x" in private,
            "json": lambda: json.dumps(private),
            "memoryview": lambda: memoryview(private),
            "str concatenation": lambda: "x" + private,
            "bytes concatenation": lambda: b"x" + private,
            "int()": lambda: int(private),
            "pickle": lambda: pickle.dumps(private),
            "copy": lambda: copy.copy(private),
            "deepcopy": lambda: copy.deepcopy(private),
            "asdict of the occurrence": lambda: dataclasses.asdict(occurrence),
            "deepcopy of the occurrence": lambda: copy.deepcopy(occurrence),
            "pickle of the occurrence": lambda: pickle.dumps(occurrence),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                with self.assertRaises(TypeError):
                    operation()
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                with self.assertRaises(TypeError):
                    pickle.dumps(private, protocol)

    def test_private_bytes_copies_its_input_and_returns_immutable_bytes(self) -> None:
        buffer = bytearray(b"abc")
        private = PrivateBytes(buffer)
        self.assertEqual(private.reveal(), b"abc")  # positive control first
        buffer[0] = ord("z")
        self.assertEqual(private.reveal(), b"abc")
        self.assertIs(type(private.reveal()), bytes)
        self.assertEqual(PrivateBytes(memoryview(b"xyz")).reveal(), b"xyz")
        self.assertEqual(len(PrivateBytes(b"")), 0)
        for bad in ("abc", None, 5, ["a"]):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    PrivateBytes(bad)  # type: ignore[arg-type]

    def test_manifest_cannot_be_serialized_or_copied(self) -> None:
        # replace() must keep working: the tamper tests and PR B both rely on it.
        clone = dataclasses.replace(self.manifest, bom=self.manifest.bom)
        self.assertEqual(clone.manifest_id, self.manifest.manifest_id)
        operations = {
            "copy.copy": lambda: copy.copy(self.manifest),
            "copy.deepcopy": lambda: copy.deepcopy(self.manifest),
            "dataclasses.asdict": lambda: dataclasses.asdict(self.manifest),
            "dataclasses.astuple": lambda: dataclasses.astuple(self.manifest),
            "json.dumps": lambda: json.dumps(self.manifest),
            "json.dumps of fields": lambda: json.dumps(self.manifest.occurrences),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                with self.assertRaises(TypeError):
                    operation()
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                with self.assertRaises(TypeError):
                    pickle.dumps(self.manifest, protocol)

    def test_outbound_payload_is_exactly_the_allowlist(self) -> None:
        payload = self.safe.outbound_payload()
        self.assertIs(type(payload), dict)
        self.assertEqual(set(payload), {"schema_version", "masked_text", "mask_counts"})
        self.assertEqual(payload["schema_version"], "cb.mask.v1")
        self.assertEqual(payload["masked_text"], self.safe.masked_text)
        self.assertIs(type(payload["mask_counts"]), dict)
        self.assertEqual(payload["mask_counts"], dict(self.safe.mask_counts))
        self.assertEqual(json.loads(json.dumps(payload)), payload)
        serialized = json.dumps(payload, ensure_ascii=False)
        for forbidden in (
            self.original_digest,
            self.manifest.manifest_id,
            self.manifest.binding.case_id,
            self.manifest.binding.document_id,
            self.manifest.original_sha256,
        ):
            self.assertNotIn(forbidden, serialized)
        # A fresh copy every time: callers cannot reach back into the safe document.
        payload["mask_counts"]["name"] = 99
        payload["masked_text"] = "tampered"
        again = self.safe.outbound_payload()
        self.assertEqual(again["mask_counts"], dict(self.safe.mask_counts))
        self.assertEqual(again["masked_text"], self.safe.masked_text)
        self.assertIsNot(again, payload)

    def test_outbound_payload_keeps_every_class_even_at_zero(self) -> None:
        for text in (GOLDEN_TEXT, "", "說明一：請補申請書。\n"):
            with self.subTest(text=text[:12]):
                safe, _ = self.mask(text)
                payload = safe.outbound_payload()
                self.assertEqual(list(payload["mask_counts"]), [name for name, _ in PATTERNS])
                self.assertEqual(payload["mask_counts"], dict(safe.mask_counts))
                self.assertEqual(sum(payload["mask_counts"].values()), safe.occurrence_count)

    def test_safe_document_is_read_only(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.safe.masked_text = "tampered"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            self.safe.mask_counts["name"] = 99  # type: ignore[index]
        self.assertEqual(self.safe.masked_bytes, self.safe.masked_text.encode("utf-8"))
        self.assertEqual(self.safe.status, "masked")
        self.assertEqual(set(self.safe.mask_counts), {name for name, _ in PATTERNS})

    def test_logging_the_objects_does_not_leak(self) -> None:
        registry = InMemoryManifestRegistry()
        registry.issue(self.raw, BINDING_A)
        masked, manifest = self.safe.masked_bytes, self.manifest
        logger = logging.getLogger("reversible-masking-probe")
        with self.assertLogs(logger, level="DEBUG") as captured:
            logger.debug("safe=%s %r", self.safe, self.safe)
            logger.info("manifest=%s %r occurrences=%s", manifest, manifest, manifest.occurrences)
            for occurrence in manifest.occurrences:
                logger.warning(
                    "occ=%s %r value=%s %r",
                    occurrence,
                    occurrence,
                    occurrence.original_value,
                    occurrence.original_value,
                )
            logger.error("payload=%s", self.safe.outbound_payload())
            logger.info("registry=%s %r", registry, registry)
            try:
                restore_original(splice(masked, 0, 1, b"x"), manifest, BINDING_A)
            except ReversibleMaskingError:
                logger.exception("restore refused")
        self.assertGreater(len(captured.output), 5)
        text = "\n".join(captured.output)
        text += "\n".join(record.getMessage() + (record.exc_text or "") for record in captured.records)
        self.assertNoLeak(text, self.canaries, "in captured log output")

    def test_core_calls_do_not_print_log_or_warn_raw_values(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertLogs(level="DEBUG") as captured:
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    logging.getLogger("probe").debug("sentinel so that assertLogs has a record")
                    safe, manifest = self.mask(self.raw)
                    restore_original(safe.masked_bytes, manifest, BINDING_A)
                    check_release_text(safe.masked_text, manifest)
                    registry = InMemoryManifestRegistry()
                    issued = registry.issue(self.raw, BINDING_A)
                    registry.restore_original(issued.masked_bytes, manifest_id=issued.manifest_id, binding=BINDING_A)
                    registry.discard(issued.manifest_id)
                    for attempt in (
                        lambda: mask_document(b"\xff" + self.raw, BINDING_A),
                        lambda: mask_document(self.raw + b"[[CB1:", BINDING_A),
                        lambda: mask_document("生日：1-02-12345678\n".encode("utf-8") + self.raw, BINDING_A),
                        lambda: restore_original(splice(safe.masked_bytes, 0, 1, b"x"), manifest, BINDING_A),
                        lambda: registry.restore_original(safe.masked_bytes, manifest_id=None, binding=BINDING_A),
                    ):
                        with self.assertRaises((ReversibleMaskingError, ResidualPiiBlocked)):
                            attempt()
        emitted = "\n".join([out.getvalue(), err.getvalue(), *captured.output, *(str(w.message) for w in caught)])
        self.assertNoLeak(emitted, self.canaries, "in stdout/stderr/log/warnings")
        self.assertEqual(out.getvalue() + err.getvalue(), "")


# (detector class, input line, masked value, expected line with each token shown as <TYPE>)
LABEL_CASES = (
    ("name", "申請人：王大明\n", "王大明", "申請人：<PERSON>\n"),
    ("name", "業主為陳小美\n", "陳小美", "業主為<PERSON>\n"),
    ("name", "所有權人 林美玲\n", "林美玲", "所有權人 <PERSON>\n"),
    ("name", "聯絡人：林美玲\n", "林美玲", "聯絡人：<PERSON>\n"),
    ("name", "姓名：王大明\n", "王大明", "姓名：<PERSON>\n"),
    ("name", "承辦人 張大華\n", "張大華", "承辦人 <PERSON>\n"),
    ("tax_id", "營業人統編：12345678\n", "12345678", "營業人統編：<TAX_ID>\n"),
    ("tax_id", "統一編號 12345678\n", "12345678", "統一編號 <TAX_ID>\n"),
    ("tax_id", "統編12345678\n", "12345678", "統編<TAX_ID>\n"),
    ("passport_or_resident_id", "護照號碼：AB123456\n", "AB123456", "護照號碼：<IDENTITY_DOCUMENT>\n"),
    ("passport_or_resident_id", "居留證號 AB12345678\n", "AB12345678", "居留證號 <IDENTITY_DOCUMENT>\n"),
    ("passport_or_resident_id", "護照 AB123456\n", "AB123456", "護照 <IDENTITY_DOCUMENT>\n"),
    ("birth_date", "出生日期：民國80年1月2日\n", "民國80年1月2日", "出生日期：<BIRTH_DATE>\n"),
    ("birth_date", "生日 1990/01/02\n", "1990/01/02", "生日 <BIRTH_DATE>\n"),
    ("birth_date", "DOB: 1990-01-02\n", "1990-01-02", "DOB: <BIRTH_DATE>\n"),
    ("birth_date", "dob 1990.01.02\n", "1990.01.02", "dob <BIRTH_DATE>\n"),
    ("birth_date", "出生年月日為民國80年1月2日\n", "民國80年1月2日", "出生年月日為<BIRTH_DATE>\n"),
    ("parcel_id", "地號：文化段123-4\n", "文化段123-4", "地號：<PARCEL_ID>\n"),
    ("parcel_id", "建號 123\n", "123", "建號 <PARCEL_ID>\n"),
    ("bank_or_case_id", "案件編號：NTPC-12345\n", "NTPC-12345", "案件編號：<ACCOUNT_OR_CASE_ID>\n"),
    ("bank_or_case_id", "銀行帳號：1234-5678-90\n", "1234-5678-90", "銀行帳號：<ACCOUNT_OR_CASE_ID>\n"),
    ("bank_or_case_id", "申請案號 NTPC-67890\n", "NTPC-67890", "申請案號 <ACCOUNT_OR_CASE_ID>\n"),
    ("address", "案件地址：新北市板橋區文化路一段123號\n", ADDRESS_A, "案件地址：<ADDRESS>\n"),
    ("address", "地址：新北市板橋區文化路一段123號\n", ADDRESS_A, "地址：<ADDRESS>\n"),
    ("address", "戶籍住址為新北市板橋區文化路一段123號\n", ADDRESS_A, "戶籍住址為<ADDRESS>\n"),
    ("address", "施工地點：新北市板橋區文化路一段123號\n", ADDRESS_A, "施工地點：<ADDRESS>\n"),
    ("address", "工程位置：新北市板橋區文化路一段123號\n", ADDRESS_A, "工程位置：<ADDRESS>\n"),
)

# (detector class, input line, masked value, expected line): no label rule applies at the
# start of the match, so the whole match is the value (over-masking, never under-masking).
WHOLE_MATCH_CASES = (
    ("parcel_id", "文化段 123 地號\n", "文化段 123 地號", "<PARCEL_ID>\n"),
    ("address", "位於新北市板橋區文化路一段123號\n", "位於" + ADDRESS_A, "<ADDRESS>\n"),
    ("address", "說明五：地址 新北市板橋區文化路一段123號\n", "說明五：地址 " + ADDRESS_A, "<ADDRESS>\n"),
    ("taiwan_id", f"證號 {ID_A}\n", ID_A, "證號 <NATIONAL_ID>\n"),
    ("email", f"信箱 {EMAIL_A}\n", EMAIL_A, "信箱 <EMAIL>\n"),
    ("mobile", f"電話 {MOBILE_A}\n", MOBILE_A, "電話 <PHONE>\n"),
    ("landline", "市話 02-12345678\n", "02-12345678", "市話 <PHONE>\n"),
)

FACTS_THAT_MUST_SURVIVE = (
    "發文機關：新北市政府工務局",
    "建築法第77條之2",
    "建築物室內裝修管理辦法第33條",
    "文到30日內",
    "（115年10月31日前）",
    "3樓走廊淨寬120公分",
    "45.5平方公尺",
    "用途H-2組",
    "耐燃一級",
    "防火時效1小時",
    "申請人：",
    "聯絡電話：",
    "聯絡信箱：",
    "案件地址：",
)


# Proves #28 §10 PR A item 5: legal references, deadlines, sizes, usage and field labels survive masking.
class GoldenPreservationTests(CoreTestCase):
    def test_golden_notice_keeps_every_fact_and_label(self) -> None:
        safe, manifest = self.mask(GOLDEN_TEXT)
        self.assertEqual(normalize_tokens(safe.masked_text), GOLDEN_EXPECTED)
        for fact in FACTS_THAT_MUST_SURVIVE:
            self.assertIn(fact, safe.masked_text)
        self.assertEqual(
            [o.original_value.reveal().decode("utf-8") for o in manifest.occurrences],
            [NAME_A, MOBILE_A, EMAIL_A, ADDRESS_A],
        )
        self.assertEqual([o.entity_type for o in manifest.occurrences], ["PERSON", "PHONE", "EMAIL", "ADDRESS"])
        self.assertEqual(safe.occurrence_count, 4)
        self.assertEqual(
            dict((name, count) for name, count in safe.mask_counts.items() if count),
            {"name": 1, "mobile": 1, "email": 1, "address": 1},
        )
        self.assertEqual(len(rm.TOKEN_RE.findall(safe.masked_text)), 4)
        self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), GOLDEN_TEXT.encode("utf-8"))

    def test_golden_lines_without_pii_are_byte_identical(self) -> None:
        safe, _ = self.mask(GOLDEN_TEXT)
        original_lines = GOLDEN_TEXT.splitlines(keepends=True)
        masked_lines = safe.masked_text.splitlines(keepends=True)
        self.assertEqual(len(masked_lines), len(original_lines))
        for index in (0, 1, 6, 7, 8, 9):
            self.assertEqual(masked_lines[index], original_lines[index])
        for index in (2, 3, 4, 5):
            self.assertNotEqual(masked_lines[index], original_lines[index])
            self.assertTrue(masked_lines[index].endswith("]]\n"))

    def test_each_label_rule_keeps_the_label_and_masks_only_the_value(self) -> None:
        self.assertEqual({case[0] for case in LABEL_CASES}, set(rm.LABEL_RULES))
        for detector_class, line, value, expected in LABEL_CASES:
            with self.subTest(line=line):
                safe, manifest = self.mask(line)
                (occ,) = manifest.occurrences
                self.assertEqual(occ.detector_class, detector_class)
                self.assertEqual(occ.original_value.reveal().decode("utf-8"), value)
                self.assertEqual(normalize_tokens(safe.masked_text), expected)
                label = line[: line.index(value)]
                self.assertTrue(safe.masked_text.startswith(label))
                self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), line.encode("utf-8"))

    def test_label_rules_are_anchored_at_the_start_of_the_match(self) -> None:
        for detector_class, line, value, expected in WHOLE_MATCH_CASES:
            with self.subTest(line=line):
                safe, manifest = self.mask(line)
                (occ,) = manifest.occurrences
                self.assertEqual(occ.detector_class, detector_class)
                self.assertEqual(occ.original_value.reveal().decode("utf-8"), value)
                self.assertEqual(normalize_tokens(safe.masked_text), expected)
                self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), line.encode("utf-8"))

    def test_dates_deadlines_and_quantities_without_a_birth_label_are_kept(self) -> None:
        lines = (
            "請於115年10月31日前補正。\n",
            "民國115年10月31日\n",
            "說明：114/12/31 前補件，並於30日內回覆。\n",
            "第77條之2 淨寬120公分 面積45.5平方公尺 用途H-2組 樓高3.2公尺 12345\n",
            "防火時效1小時，耐燃一級，3樓走廊。\n",
        )
        for line in lines:
            with self.subTest(line=line):
                safe, manifest = self.mask(line)
                self.assertEqual(safe.masked_text, line)
                self.assertEqual(manifest.occurrences, ())

    def test_reversible_core_masks_the_repository_fixtures_and_restores_them(self) -> None:
        demo = (FIXTURE_DIR / "demo_correction_notice.txt").read_bytes()
        upload = (FIXTURE_DIR / "secure_upload_canary.txt").read_bytes()
        upload_id = re.search(r"[A-Z][12]\d{8}", upload.decode("utf-8")).group(0)
        for name, raw, canaries in (
            ("demo", demo, [NAME_A, MOBILE_A, EMAIL_A, ADDRESS_A]),
            ("upload canary", upload, [upload_id, EMAIL_A, MOBILE_A, ADDRESS_A]),
        ):
            with self.subTest(fixture=name):
                safe, manifest = self.mask(raw)
                self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)
                self.assertNoLeak(safe.masked_text, canaries, "in masked fixture")
                self.assertEqual(find_sensitive_classes(safe.masked_text), [])
                self.assertEqual(find_residual_sensitive_classes(safe.masked_text), [])
                self.assertGreaterEqual(len(manifest.occurrences), 4)

    def test_masked_output_is_stable_under_the_legacy_masker(self) -> None:
        for doc in CORPUS:
            with self.subTest(doc=doc.name):
                safe, _ = self.mask(doc.raw)
                self.assertEqual(mask_sensitive_text(safe.masked_text).text, safe.masked_text)


# What mask_sensitive_text produced on main@4aabfe9 for these inputs. The reversible core is a
# separate opt-in module, so the legacy API must keep returning exactly this.
LEGACY_DEMO_NOTICE = (
    "發文機關：新北市政府工務局\n"
    "發文字號：DEMO-SYNTHETIC-0001\n"
    "主旨：室內裝修竣工查驗補正通知（示範用合成資料，非真實案件）\n"
    "說明一：請補申請書、建築物權利證明文件及室內裝修圖說，並由建築師簽章。\n"
    "說明二：請補消防安全設備竣工文件並確認。\n"
    "說明三：風管貫穿防火區劃處請補防火填塞說明。\n"
    "說明四：請補天花板材料之耐燃等級證明文件。\n"
    "[MASKED_NAME]\n"
    "聯絡電話 [MASKED_MOBILE]\n"
    "聯絡信箱 [MASKED_EMAIL]\n"
    "[MASKED_ADDRESS]\n"
)
LEGACY_UPLOAD_CANARY = (
    "補正通知測試資料\n"
    "[MASKED_NAME] [MASKED_TAIWAN_ID]\n"
    "聯絡信箱 [MASKED_EMAIL]\n"
    "行動電話 [MASKED_MOBILE]\n"
    "[MASKED_ADDRESS]\n"
    "消防設備與材料證明文件需人工確認。\n"
)
LEGACY_GOLDEN = (
    "發文機關：新北市政府工務局\n"
    "主旨：室內裝修竣工查驗補正通知（合成資料）\n"
    "[MASKED_NAME]\n"
    "聯絡電話：[MASKED_MOBILE]\n"
    "聯絡信箱：[MASKED_EMAIL]\n"
    "[MASKED_ADDRESS]\n"
    "說明一：依建築法第77條之2及建築物室內裝修管理辦法第33條辦理。\n"
    "說明二：請於文到30日內（115年10月31日前）補正。\n"
    "說明三：3樓走廊淨寬120公分，樓地板面積45.5平方公尺，用途H-2組。\n"
    "說明四：天花板材料耐燃一級，防火時效1小時。\n"
)
# Note what the legacy masker does that the reversible core must not: it swallows the field
# labels, and the birth date takes its line terminator with it (two lines are joined).
LEGACY_ALL_CLASSES = (
    "[MASKED_NAME]\n"
    "備註 [MASKED_PERSONAL_NAME] 到場\n"
    "身分證號：[MASKED_TAIWAN_ID]\n"
    "[MASKED_TAX_ID]\n"
    "[MASKED_PASSPORT_OR_RESIDENT_ID]\n"
    "聯絡信箱：[MASKED_EMAIL]\n"
    "行動電話：[MASKED_MOBILE]\n"
    "市話：[MASKED_LANDLINE]\n"
    "[MASKED_BIRTH_DATE][MASKED_PARCEL_ID]\n"
    "[MASKED_BANK_OR_CASE_ID]\n"
    "[MASKED_ADDRESS]\n"
)


# Proves #28 §10 PR A item 5 (regression): the legacy masking API and detector registries are unchanged.
class LegacyApiUnchangedTests(CoreTestCase):
    def test_legacy_masker_output_is_pinned(self) -> None:
        cases = (
            ((FIXTURE_DIR / "demo_correction_notice.txt").read_text(encoding="utf-8"), LEGACY_DEMO_NOTICE,
             {"name": 1, "email": 1, "mobile": 1, "address": 1}),
            ((FIXTURE_DIR / "secure_upload_canary.txt").read_text(encoding="utf-8"), LEGACY_UPLOAD_CANARY,
             {"name": 1, "taiwan_id": 1, "email": 1, "mobile": 1, "address": 1}),
            (GOLDEN_TEXT, LEGACY_GOLDEN, {"name": 1, "email": 1, "mobile": 1, "address": 1}),
            (ALL_CLASSES_TEXT, LEGACY_ALL_CLASSES, {name: 1 for name, _ in PATTERNS}),
        )  # fmt: skip
        for text, expected, counts in cases:
            with self.subTest(expected=expected[:20]):
                result = mask_sensitive_text(text)
                self.assertEqual(result.text, expected)
                self.assertEqual({k: v for k, v in result.counts.items() if v}, counts)
                self.assertEqual(list(result.counts), [name for name, _ in PATTERNS])
                self.assertEqual(result.total, sum(counts.values()))

    def test_detector_registries_are_unchanged(self) -> None:
        self.assertEqual(
            [name for name, _ in PATTERNS],
            [
                "name", "taiwan_id", "tax_id", "passport_or_resident_id", "email", "mobile", "landline",
                "birth_date", "parcel_id", "bank_or_case_id", "address", "personal_name",
            ],
        )  # fmt: skip
        self.assertEqual(len(NON_NAME_TERMS), 107)
        self.assertEqual(
            [name for name, _ in RESIDUAL_PATTERNS],
            [
                "taiwan_id_candidate", "email_candidate", "phone_candidate", "identity_document_candidate",
                "person_name_candidate", "unlabeled_name_candidate", "birth_date_candidate",
                "mixed_identity_candidate", "address_candidate", "account_or_case_candidate",
            ],
        )  # fmt: skip

    def test_using_the_reversible_core_does_not_change_legacy_state(self) -> None:
        patterns_before = tuple(PATTERNS)
        terms_before = frozenset(NON_NAME_TERMS)
        legacy_before = mask_sensitive_text(GOLDEN_TEXT)
        safe, manifest = self.mask(GOLDEN_TEXT)
        restore_original(safe.masked_bytes, manifest, BINDING_A)
        self.assertEqual(tuple(PATTERNS), patterns_before)
        self.assertEqual(frozenset(NON_NAME_TERMS), terms_before)
        self.assertEqual(mask_sensitive_text(GOLDEN_TEXT), legacy_before)
        self.assertEqual(legacy_before.text, LEGACY_GOLDEN)


CORE_SOURCE_PATH = WORKER_DIR / "reversible_masking.py"
EXPECTED_PUBLIC_API = (
    "DETECTOR_VERSION", "DocumentBinding", "ENTITY_TYPES", "ERROR_CODES", "InMemoryManifestRegistry",
    "LABEL_RULES", "MAX_DOCUMENT_BYTES", "MAX_OCCURRENCES", "Occurrence", "PARSER_VERSION",
    "POLICY_VERSION", "PrivateBytes", "PrivateManifest", "ReversibleMaskingError", "SCHEMA_VERSION",
    "SafeMaskedDocument", "TOKEN_RE", "check_release_text", "derive_detector_version",
    "derive_policy_version", "mask_document", "restore_original",
)  # fmt: skip
FORBIDDEN_MODULES = frozenset(
    {
        "sqlite3", "socket", "ssl", "http", "urllib", "subprocess", "multiprocessing", "pickle", "marshal",
        "shelve", "dbm", "tempfile", "pathlib", "shutil", "ctypes", "asyncio", "smtplib", "ftplib", "xmlrpc",
        "webbrowser", "requests", "httpx",
    }
)  # fmt: skip
RESTORE_FRAGMENTS = ("reidentif", "restore", "unmask", "rehydrat")


# Proves #28 §10 PR A item 6: private and safe interfaces are separate; no sidecar, endpoint, tool or model call.
class SeparationOfInterfacesTests(CoreTestCase):
    def guarded_modules(self) -> list[Path]:
        return sorted(path for path in WORKER_DIR.glob("*.py") if path != CORE_SOURCE_PATH)

    def test_no_worker_module_imports_or_mentions_the_core(self) -> None:
        self.assertGreaterEqual(len(self.guarded_modules()), 8)
        for path in self.guarded_modules():
            with self.subTest(module=path.name):
                source = path.read_text(encoding="utf-8")
                imported = set()
                for node in ast.walk(ast.parse(source)):
                    if isinstance(node, ast.Import):
                        imported.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        imported.add(node.module or "")
                        imported.update(alias.name for alias in node.names)
                self.assertFalse([name for name in imported if "reversible_masking" in name])
                self.assertNotIn("reversible_masking", source)
                self.assertNotIn("cb.mask", source)

    def test_package_exports_are_unchanged(self) -> None:
        import worker.secure_worker as package

        self.assertEqual(sorted(package.__all__), ["MaskingResult", "WorkerConfig", "mask_sensitive_text"])
        self.assertNotIn("reversible_masking", (WORKER_DIR / "__init__.py").read_text(encoding="utf-8"))

    def test_the_documented_public_api_is_the_whole_public_api(self) -> None:
        self.assertEqual(sorted(rm.__all__), sorted(EXPECTED_PUBLIC_API))
        for name in rm.__all__:
            self.assertTrue(hasattr(rm, name), name)
        defined = {
            name
            for name, obj in vars(rm).items()
            if not name.startswith("_")
            and getattr(obj, "__module__", None) == rm.__name__
            and (inspect.isfunction(obj) or inspect.isclass(obj))
        }
        self.assertLessEqual(defined, set(rm.__all__))

    def test_core_imports_only_the_standard_library_and_no_io_modules(self) -> None:
        tree = ast.parse(CORE_SOURCE_PATH.read_text(encoding="utf-8"))
        absolute, relative, calls = set(), set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                absolute.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    relative.add(node.module)
                else:
                    absolute.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.add(node.func.id)
        self.assertLessEqual(absolute, set(sys.stdlib_module_names))
        self.assertEqual(absolute & FORBIDDEN_MODULES, set())
        self.assertLessEqual(relative, {"masking", "residual_pii"})
        self.assertEqual(calls & {"open", "print", "exec", "eval", "__import__", "compile", "input"}, set())

    def test_core_restores_by_registered_spans_never_by_search_and_replace(self) -> None:
        # Issue #28 section 4.A.5: no fuzzy matching and no global str.replace. With the
        # earlier checks in place a replace would behave the same, so this is enforced
        # statically: the core contains no search-and-replace primitive at all.
        tree = ast.parse(CORE_SOURCE_PATH.read_text(encoding="utf-8"))
        banned = {"replace", "sub", "subn", "translate", "expandtabs"}
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in banned}
        imported = {
            alias.name
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom)
            for alias in n.names
            if alias.name in banned
        }
        self.assertEqual(sorted(attributes | imported), [])

    def test_a_full_cycle_touches_no_file_network_subprocess_or_database(self) -> None:
        import shutil
        import socket
        import sqlite3
        import tempfile
        import urllib.request

        targets = (
            "builtins.open", "io.open", "os.open", "os.system", "subprocess.Popen", "socket.socket",
            "socket.create_connection", "sqlite3.connect", "shutil.copyfile", "shutil.copy",
            "pathlib.Path.write_bytes", "pathlib.Path.write_text", "pathlib.Path.open", "tempfile.mkstemp",
            "tempfile.NamedTemporaryFile", "urllib.request.urlopen",
        )  # fmt: skip
        self.assertTrue(all((shutil, socket, sqlite3, tempfile, urllib.request)))
        raw = ALL_CLASSES_TEXT.encode("utf-8")
        before = sorted(os.listdir("."))
        with contextlib.ExitStack() as stack:
            for target in targets:
                stack.enter_context(patch(target, side_effect=AssertionError(f"forbidden side effect: {target}")))
            safe, manifest = mask_document(raw, BINDING_A)
            self.assertEqual(restore_original(safe.masked_bytes, manifest, BINDING_A), raw)
            check_release_text(safe.masked_text, manifest)
            registry = InMemoryManifestRegistry()
            issued = registry.issue(raw, BINDING_A, retention_deadline=1e12)
            registry.restore_original(issued.masked_bytes, manifest_id=issued.manifest_id, binding=BINDING_A)
            registry.discard(issued.manifest_id)
            with self.assertRaises(ReversibleMaskingError):
                mask_document(b"\xff", BINDING_A)
            with self.assertRaises(ReversibleMaskingError):
                restore_original(splice(safe.masked_bytes, 0, 1, b"x"), manifest, BINDING_A)
        self.assertEqual(sorted(os.listdir(".")), before)

    def test_no_mcp_tool_or_http_route_can_restore(self) -> None:
        names = [tool["name"].lower() for tool in TOOL_SCHEMAS]
        self.assertGreater(len(names), 30)
        for fragment in RESTORE_FRAGMENTS:
            self.assertEqual([name for name in names if fragment in name], [], fragment)
        server_source = (WORKER_DIR / "server.py").read_text(encoding="utf-8").lower()
        for fragment in RESTORE_FRAGMENTS:
            self.assertNotIn(fragment, server_source, fragment)
        for path in sorted((REPO_ROOT / "tw_law_mcp").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("reversible_masking", text, path.name)
            self.assertNotIn("cb.mask", text, path.name)

    def test_mode_b_is_not_present_in_pr_a(self) -> None:
        fragments = ("template", "slot", "approved_field", "reidentif", "rehydrat", "unmask", "result_digest")
        names = [name.lower() for name in dir(rm)]
        for fragment in fragments:
            self.assertEqual([n for n in names if fragment in n], [], fragment)
        self.assertEqual(
            sorted(name for name in dir(InMemoryManifestRegistry) if not name.startswith("_")),
            ["discard", "issue", "restore_original"],
        )


def inert_under_both_detector_sets(text: str) -> bool:
    return not find_sensitive_classes(text) and not find_residual_sensitive_classes(text)


def adr_text() -> str:
    return ADR_PATH.read_text(encoding="utf-8")


# Proves #28 §10 PR A items 5-6 (contract): grammar, versions, entity map and error codes match ADR-0003.
class ContractTests(CoreTestCase):
    def test_constants_are_the_documented_values(self) -> None:
        self.assertEqual(rm.SCHEMA_VERSION, "cb.mask.v1")
        self.assertEqual(rm.PARSER_VERSION, "txt-utf8-strict/1")
        self.assertEqual(rm.MAX_DOCUMENT_BYTES, 25 * 1024 * 1024)
        self.assertEqual(rm.MAX_OCCURRENCES, 999_999)
        self.assertEqual(rm.RESERVED_PREFIX, "[[CB")
        self.assertTrue(rm.OPAQUE_ID_RE.fullmatch("a" * 128))
        self.assertIsNone(rm.OPAQUE_ID_RE.fullmatch("a" * 129))
        self.assertIsNone(rm.OPAQUE_ID_RE.fullmatch("a\n"))

    def test_entity_type_map_covers_exactly_the_pattern_classes(self) -> None:
        names = [name for name, _ in PATTERNS]
        self.assertEqual(len(names), 12)
        self.assertEqual(set(rm.ENTITY_TYPES), set(names))
        self.assertEqual(
            dict(rm.ENTITY_TYPES),
            {
                "name": "PERSON", "personal_name": "PERSON", "taiwan_id": "NATIONAL_ID", "tax_id": "TAX_ID",
                "passport_or_resident_id": "IDENTITY_DOCUMENT", "email": "EMAIL", "mobile": "PHONE",
                "landline": "PHONE", "birth_date": "BIRTH_DATE", "parcel_id": "PARCEL_ID",
                "bank_or_case_id": "ACCOUNT_OR_CASE_ID", "address": "ADDRESS",
            },
        )  # fmt: skip
        for entity_type in rm.ENTITY_TYPES.values():
            self.assertRegex(entity_type, r"\A[A-Z][A-Z_]{0,31}\Z")
        with self.assertRaises(TypeError):
            rm.ENTITY_TYPES["name"] = "OTHER"  # type: ignore[index]

    def test_label_rules_cover_the_documented_classes(self) -> None:
        self.assertEqual(
            set(rm.LABEL_RULES),
            {"name", "tax_id", "passport_or_resident_id", "birth_date", "parcel_id", "bank_or_case_id", "address"},
        )
        for name, rule in rm.LABEL_RULES.items():
            self.assertIsInstance(rule, re.Pattern)
            self.assertEqual(bool(rule.flags & re.IGNORECASE), name == "birth_date", name)
        with self.assertRaises(TypeError):
            rm.LABEL_RULES["name"] = re.compile("x")  # type: ignore[index]

    def test_token_regex_is_the_documented_grammar(self) -> None:
        self.assertEqual(rm.TOKEN_RE.pattern, r"\[\[CB1:([A-Z][A-Z_]{0,31}):([a-z]{28}):([0-9]{6})\]\]")
        valid = make_token("PERSON", "a" * 28, 1)
        parts = rm.TOKEN_RE.fullmatch(valid)
        self.assertEqual(parts.groups(), ("PERSON", "a" * 28, "000001"))
        edge = ("A", "A_B", "A_", "A" + "B" * 31, "ACCOUNT_OR_CASE_ID")
        for entity_type in edge:
            self.assertIsNotNone(rm.TOKEN_RE.fullmatch(make_token(entity_type, "z" * 28, 999_999)), entity_type)
        invalid = {
            "27 letters": make_token("PERSON", "a" * 27, 1),
            "29 letters": make_token("PERSON", "a" * 29, 1),
            "uppercase namespace": make_token("PERSON", "A" * 28, 1),
            "digit in namespace": make_token("PERSON", "a" * 27 + "1", 1),
            "hex namespace": make_token("PERSON", "a1" * 14, 1),
            "5 digit sequence": valid.replace(":000001]]", ":00001]]"),
            "7 digit sequence": valid.replace(":000001]]", ":0000001]]"),
            "non-ascii digits": valid.replace(":000001]]", ":٠٠٠٠٠١]]"),
            "lowercase type": make_token("person", "a" * 28, 1),
            "type with digit": make_token("PERSON1", "a" * 28, 1),
            "type starts with underscore": make_token("_PERSON", "a" * 28, 1),
            "type too long": make_token("A" * 33, "a" * 28, 1),
            "empty type": make_token("", "a" * 28, 1),
            "other version": valid.replace("CB1", "CB2"),
            "single brackets": valid[1:-1],
            "trailing newline": valid + "\n",
            "leading space": " " + valid,
            "unclosed": valid[:-2],
        }
        for name, text in invalid.items():
            with self.subTest(case=name):
                self.assertIsNone(rm.TOKEN_RE.fullmatch(text))

    def test_generated_tokens_are_inert_under_both_detector_sets(self) -> None:
        rng = random.Random(20241004)
        letters = "abcdefghijklmnopqrstuvwxyz"
        tokens = []
        for _ in range(250):
            namespace = "".join(rng.choice(letters) for _ in range(28))
            for entity_type in TOKEN_TYPES:
                tokens.append(make_token(entity_type, namespace, rng.randrange(1, 1_000_000)))
        for sequence in (1, 999_999, 100_000, 123_456, 654_321):
            tokens.append(make_token("PERSON", "a" * 28, sequence))
        self.assertGreaterEqual(len(tokens), 2000)
        self.assertEqual({rm.TOKEN_RE.fullmatch(t).group(1) for t in tokens}, set(TOKEN_TYPES))
        for token in tokens:
            self.assertTrue(inert_under_both_detector_sets(token), token)
        for start in range(0, len(tokens), 50):
            batch = tokens[start : start + 50]
            for joiner in ("", " ", "\n", "，", "-"):
                self.assertTrue(inert_under_both_detector_sets(joiner.join(batch)), joiner)

    def test_issued_tokens_are_inert_under_both_detector_sets(self) -> None:
        tokens = []
        for _ in range(250):
            safe, manifest = self.mask(ALL_CLASSES_TEXT)
            tokens.extend(o.token for o in manifest.occurrences)
            self.assertEqual(find_sensitive_classes(safe.masked_text), [])
            self.assertEqual(find_residual_sensitive_classes(safe.masked_text), [])
        self.assertGreaterEqual(len(tokens), 2000)
        self.assertEqual({rm.TOKEN_RE.fullmatch(t).group(1) for t in tokens}, set(TOKEN_TYPES))
        for token in tokens:
            self.assertTrue(inert_under_both_detector_sets(token), token)

    def test_versions_are_well_formed_and_recorded(self) -> None:
        self.assertRegex(rm.DETECTOR_VERSION, r"\Adet-[0-9a-f]{16}\Z")
        self.assertRegex(rm.POLICY_VERSION, r"\Apol-[0-9a-f]{16}\Z")
        self.assertEqual(rm.DETECTOR_VERSION, rm.derive_detector_version())
        self.assertEqual(rm.DETECTOR_VERSION, rm.derive_detector_version(PATTERNS, NON_NAME_TERMS))
        self.assertEqual(rm.POLICY_VERSION, rm.derive_policy_version())
        safe, manifest = self.mask(GOLDEN_TEXT)
        for record in (safe, manifest):
            self.assertEqual(record.schema_version, rm.SCHEMA_VERSION)
            self.assertEqual(record.parser_version, rm.PARSER_VERSION)
            self.assertEqual(record.policy_version, rm.POLICY_VERSION)
            self.assertEqual(record.detector_version, rm.DETECTOR_VERSION)
        self.assertEqual(manifest.encoding, "utf-8")
        self.assertEqual(manifest.newline_policy, "preserve")
        self.assertEqual(manifest.restore_policy, "original_in_place")
        self.assertIsNone(manifest.key_id)
        self.assertEqual(manifest.binding, BINDING_A)
        self.assertEqual(safe.binding, BINDING_A)
        self.assertEqual(safe.status, "masked")

    def test_detector_version_tracks_patterns_flags_order_and_terms(self) -> None:
        base = rm.derive_detector_version(PATTERNS, NON_NAME_TERMS)
        self.assertEqual(rm.derive_detector_version(PATTERNS, NON_NAME_TERMS), base)
        self.assertEqual(rm.derive_detector_version(PATTERNS, sorted(NON_NAME_TERMS, reverse=True)), base)
        self.assertEqual(rm.derive_detector_version(PATTERNS, list(NON_NAME_TERMS)), base)
        variants = {
            "pattern text": tuple(
                (n, re.compile(p.pattern + "x", p.flags) if n == "email" else p) for n, p in PATTERNS
            ),
            "pattern flags": tuple(
                (n, re.compile(p.pattern, p.flags ^ re.IGNORECASE) if n == "taiwan_id" else p) for n, p in PATTERNS
            ),
            "order": (PATTERNS[1], PATTERNS[0]) + PATTERNS[2:],
            "name": (("renamed", PATTERNS[0][1]),) + PATTERNS[1:],
            "dropped": PATTERNS[:-1],
        }
        seen = {base}
        for name, patterns in variants.items():
            with self.subTest(change=name):
                version = rm.derive_detector_version(patterns, NON_NAME_TERMS)
                self.assertRegex(version, r"\Adet-[0-9a-f]{16}\Z")
                self.assertNotIn(version, seen)
                seen.add(version)
        for name, terms in {
            "added term": NON_NAME_TERMS | {"新增詞"},
            "removed term": frozenset(sorted(NON_NAME_TERMS)[1:]),
            "empty": frozenset(),
        }.items():
            with self.subTest(change=name):
                version = rm.derive_detector_version(PATTERNS, terms)
                self.assertNotIn(version, seen)
                seen.add(version)

    def test_policy_version_tracks_label_rules_entity_map_and_policy_id(self) -> None:
        base = rm.derive_policy_version(rm.LABEL_RULES, rm.ENTITY_TYPES, rm.RESOLUTION_POLICY_ID)
        self.assertEqual(base, rm.POLICY_VERSION)
        rules = dict(rm.LABEL_RULES)
        variants = {
            "label rule text": ({**rules, "name": re.compile(rules["name"].pattern + "x")}, rm.ENTITY_TYPES, rm.RESOLUTION_POLICY_ID),
            "label rule flags": ({**rules, "birth_date": re.compile(rules["birth_date"].pattern)}, rm.ENTITY_TYPES, rm.RESOLUTION_POLICY_ID),
            "dropped label rule": ({k: v for k, v in rules.items() if k != "address"}, rm.ENTITY_TYPES, rm.RESOLUTION_POLICY_ID),
            "entity type value": (rules, {**rm.ENTITY_TYPES, "name": "HUMAN"}, rm.RESOLUTION_POLICY_ID),
            "dropped entity": (rules, {k: v for k, v in rm.ENTITY_TYPES.items() if k != "mobile"}, rm.RESOLUTION_POLICY_ID),
            "resolution policy": (rules, rm.ENTITY_TYPES, "span-resolution/2"),
        }  # fmt: skip
        seen = {base}
        for name, (label_rules, entity_types, policy_id) in variants.items():
            with self.subTest(change=name):
                version = rm.derive_policy_version(label_rules, entity_types, policy_id)
                self.assertRegex(version, r"\Apol-[0-9a-f]{16}\Z")
                self.assertNotIn(version, seen)
                seen.add(version)

    def test_versions_do_not_depend_on_hash_randomization(self) -> None:
        code = "from worker.secure_worker import reversible_masking as r; print(r.DETECTOR_VERSION, r.POLICY_VERSION)"
        outputs = set()
        for seed in ("1", "2", "3"):
            process = subprocess.run(
                [sys.executable, "-c", code],
                cwd=REPO_ROOT,
                env={**os.environ, "PYTHONHASHSEED": seed},
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            outputs.add(process.stdout.strip())
        self.assertEqual(len(outputs), 1)
        detector, policy = outputs.pop().split()
        self.assertRegex(detector, r"\Adet-[0-9a-f]{16}\Z")
        self.assertRegex(policy, r"\Apol-[0-9a-f]{16}\Z")
        self.assertEqual((detector, policy), (rm.DETECTOR_VERSION, rm.POLICY_VERSION))

    def test_error_codes_match_the_adr_table(self) -> None:
        adr = adr_text()
        section = adr.split("\n## Error codes\n", 1)[1].split("\n## ", 1)[0]
        documented = re.findall(r"^\| `([A-Z][A-Z0-9_]+)` \|", section, flags=re.MULTILINE)
        self.assertEqual(len(documented), len(set(documented)))
        self.assertEqual(set(documented), set(rm.ERROR_CODES))
        self.assertEqual(len(rm.ERROR_CODES), 21)
        for code in rm.ERROR_CODES:
            self.assertRegex(code, r"\A[A-Z][A-Z0-9_]+\Z")
        self.assertNotIn("RESIDUAL_PII_BLOCKED", rm.ERROR_CODES)
        self.assertIn("RESIDUAL_PII_BLOCKED", section)

    def test_adr_header_follows_the_house_format(self) -> None:
        lines = adr_text().splitlines()
        self.assertEqual(lines[0], "# ADR-0003: Reversible TXT masking core (`cb.mask.v1`)")
        self.assertEqual(lines[2], "Status: Accepted (PR A scope)")
        self.assertRegex(lines[3], r"\ADate: \d{4}-\d{2}-\d{2}\Z")
        self.assertEqual(lines[4], "Decision maker: repository owner")
        self.assertTrue(lines[5].startswith("Delivery: GitHub issue #28"))
        self.assertTrue(
            (REPO_ROOT / "docs" / "ADR-0002-secure-web.md").read_text(encoding="utf-8").startswith("# ADR-0002")
        )

    def test_adr_pins_grammar_label_rules_entity_map_and_limits(self) -> None:
        adr = adr_text()
        self.assertIn(rm.TOKEN_RE.pattern, adr)
        for constant in (rm.SCHEMA_VERSION, rm.PARSER_VERSION, rm.RESOLUTION_POLICY_ID):
            self.assertIn(constant, adr)
        for name, entity_type in rm.ENTITY_TYPES.items():
            self.assertIn(f"`{name}`", adr, name)
            self.assertIn(f"`{entity_type}`", adr, entity_type)
        for name, rule in rm.LABEL_RULES.items():
            self.assertIn(rule.pattern.replace("|", "\\|"), adr, name)
        self.assertIn(f"{rm.MAX_OCCURRENCES:_}", adr)
        self.assertIn("25 MiB", adr)

    def test_adr_states_scope_limits_modes_and_follow_up_gates(self) -> None:
        adr = adr_text()
        for heading in (
            "## Context", "## Decision", "## Data contract", "## Token grammar",
            "### Why the namespace is letters only", "## Detection, label preservation and span resolution",
            "## Release scan", "## Mode A: restore algorithm", "## Registry (RAM stand-in for the PR B vault)",
            "## Mode B (deferred to PR C, described only)", "## Error codes", "## What PR A does not do",
            "## Follow-up gates", "## Known limitations",
        ):  # fmt: skip
            self.assertIn("\n" + heading + "\n", adr, heading)
        for phrase in (
            "template_id", "template_version", "field_id", "source_occurrence_id", "expected_entity_type",
            "result_digest", "SPAN_CONFLICT", "`reidentify`", "PR B", "PR C", "PR D",
        ):  # fmt: skip
            self.assertIn(phrase, adr, phrase)
        prose = adr.lower()
        for phrase in (
            "no persistence",
            "no http endpoint",
            "no model call",
            "utf-8 txt only",
            "full-width",
            "combining",
            "normalization",
            "tombstone",
            "known limitations",
        ):
            self.assertIn(phrase, prose, phrase)
