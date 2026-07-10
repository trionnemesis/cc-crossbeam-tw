from __future__ import annotations

import re
from dataclasses import dataclass


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "name",
        re.compile(r"(?:申請人|業主|所有權人|聯絡人|姓名|承辦人)\s*(?:為|[:：])?\s*[\u3400-\u9fff]{2,4}"),
    ),
    ("taiwan_id", re.compile(r"(?<![A-Z0-9])[A-Z][12]\d{8}(?!\d)", re.IGNORECASE)),
    (
        "tax_id",
        re.compile(r"(?:營業人統編|統一編號|統編)\s*[:：]?\s*\d{8}"),
    ),
    (
        "passport_or_resident_id",
        re.compile(r"(?:護照|居留證)(?:號碼|號)?\s*[:：]?\s*[A-Z0-9]{6,12}", re.IGNORECASE),
    ),
    (
        "email",
        re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE),
    ),
    (
        "mobile",
        re.compile(r"(?<!\d)(?:\+886[-\s]?)?0?9\d{2}[-\s]?\d{3}[-\s]?\d{3}(?!\d)"),
    ),
    ("landline", re.compile(r"(?<!\d)0\d{1,2}[-\s]?\d{6,8}(?!\d)")),
    (
        "parcel_id",
        re.compile(
            r"(?:地號\s*)?[\u3400-\u9fff]{1,16}(?:段|小段)\s*\d+(?:-\d+)?\s*(?:地號|建號)"
            r"|(?:地號|建號)\s*[:：]?\s*[\u3400-\u9fff0-9-]{2,32}"
        ),
    ),
    (
        "bank_or_case_id",
        re.compile(r"(?:銀行帳號|帳戶號碼|案件編號|申請案號)\s*[:：]?\s*[A-Z0-9-]{5,30}", re.IGNORECASE),
    ),
    (
        "address",
        re.compile(
            r"(?:[\u3400-\u9fff]{2,6}(?:市|縣))?"
            r"[\u3400-\u9fff]{1,8}(?:區|鄉|鎮|市)?"
            r"[^\n，,。]{0,16}(?:路|街|大道)[^\n，,。]{0,12}"
            r"(?:巷[^\n，,。]{0,6})?(?:弄[^\n，,。]{0,6})?\d+號(?:之\d+)?"
        ),
    ),
)


@dataclass(frozen=True)
class MaskingResult:
    text: str
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def mask_sensitive_text(text: str) -> MaskingResult:
    masked = text
    counts: dict[str, int] = {}
    for name, pattern in PATTERNS:
        masked, count = pattern.subn(f"[MASKED_{name.upper()}]", masked)
        counts[name] = count
    return MaskingResult(text=masked, counts=counts)


def find_sensitive_classes(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS if pattern.search(text)]
