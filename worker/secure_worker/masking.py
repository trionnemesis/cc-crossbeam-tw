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
        "birth_date",
        re.compile(
            r"(?:出生年月日|出生日期|出生|生日|D\.?O\.?B\.?)\s*(?:為|[:：])?\s*"
            r"(?:中華民國|民國)?\s*\d{1,4}\s*[./年-]\s*\d{1,2}\s*[./月-]\s*\d{1,2}\s*日?",
            re.IGNORECASE,
        ),
    ),
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
    # Unlabeled personal names run last so addresses and parcel identifiers are
    # already masked and cannot be split by a surname match inside them.
    (
        "personal_name",
        re.compile(
            r"(?<![\u3400-\u9fff])"
            r"(?:歐陽|司馬|諸葛|上官|王|李|張|陳|林|黃|吳|劉|蔡|楊|許|鄭|謝|洪|郭|邱|曾|廖|賴|徐"
            r"|周|葉|蘇|莊|呂|江|何|蕭|羅|高|潘|簡|朱|鍾|游|彭|詹|胡|施|沈|余|盧|梁|趙|顏|柯|翁"
            r"|魏|孫|戴|范|方|宋|鄧|杜|傅|侯|曹|溫|薛|丁|馬|蔣)"
            # A place or organization suffix immediately after the surname means
            # this is a location or an authority, not a person.
            r"(?![\u3400-\u9fff]?(?:區|鄉|鎮|市|縣|里|村|路|街|段|巷|弄|號|樓|室|棟|局|處|科|課"
            r"|股|會|社|司|廠|場|院|校|署|府|所|部|組|隊|站|園|館|寺|廟|橋|山|河|江|湖|海|島)"
            r"(?![\u3400-\u9fff]))"
            r"[\u3400-\u9fff]{1,2}(?![\u3400-\u9fff])"
        ),
    ),
)


# Short Han runs that start with a surname character but are ordinary legal or
# construction vocabulary. Masking them would corrupt the correction text without
# protecting anyone.
NON_NAME_TERMS: frozenset[str] = frozenset(
    {
        "方式", "方法", "方案", "方向", "方位", "方面", "方形",
        "高度", "高程", "高層", "高溫", "高於", "高低",
        "許可", "施工", "施行", "施作", "施設",
        "何時", "何種", "周邊", "周圍", "周界",
        "溫度", "馬路", "黃線", "黃色", "白色", "朱色",
        "江河", "宋體", "簡易", "簡化", "簡報", "余額",
        "葉片", "范圍", "范例", "胡同", "丁字", "丁掛",
        "杜絕", "曹操", "侯車", "薛西", "戴上", "孫子",
        "游泳", "游離", "沈陷", "沉陷", "梁柱", "梁上",
        "趙氏", "柯達", "翁仲", "魏晉", "范本", "方能",
        "何況", "羅列", "羅盤", "潘朵", "彭湃", "詹姆",
        "莊嚴", "莊重", "蘇醒", "呂宋", "顏色", "顏料",
        "盧森", "鄧氏", "傅立", "溫控", "溫水", "丁類",
        "曾經", "曾有", "徐緩", "廖續", "賴以", "邱陵",
        "洪水", "洪災", "郭氏", "謝絕", "鄭重", "楊桃",
        "蔡氏", "劉氏", "吳氏", "黃金", "林地", "林木",
        "陳述", "陳報", "陳列", "張貼", "張力", "李氏",
        "王牌", "朱紅", "鍾情", "范疇", "宋朝", "杜門",
    }
)


@dataclass(frozen=True)
class MaskingResult:
    text: str
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _is_masked_class(name: str, value: str) -> bool:
    if name == "personal_name":
        return value not in NON_NAME_TERMS
    return True


def mask_sensitive_text(text: str) -> MaskingResult:
    masked = text
    counts: dict[str, int] = {}
    for name, pattern in PATTERNS:
        replaced = 0

        def substitute(match: re.Match[str], _name: str = name) -> str:
            nonlocal replaced
            value = match.group(0)
            if not _is_masked_class(_name, value):
                return value
            replaced += 1
            return f"[MASKED_{_name.upper()}]"

        masked = pattern.sub(substitute, masked)
        counts[name] = replaced
    return MaskingResult(text=masked, counts=counts)


def find_sensitive_classes(text: str) -> list[str]:
    return [
        name
        for name, pattern in PATTERNS
        if any(_is_masked_class(name, match.group(0)) for match in pattern.finditer(text))
    ]
