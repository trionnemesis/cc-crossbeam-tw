from __future__ import annotations

import re


# This detector is deliberately independent from masking.PATTERNS and more
# conservative. A hit blocks model delivery for human review; false positives
# do not expose data.
RESIDUAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("taiwan_id_candidate", re.compile(r"(?<![A-Z0-9])[A-Z][12]\d{8}(?!\d)", re.IGNORECASE)),
    (
        "email_candidate",
        re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE),
    ),
    (
        "phone_candidate",
        re.compile(r"(?<!\d)(?:\+?886[-\s]?)?(?:0?9\d{2}|0\d{1,2})[-\s]?\d{3,4}[-\s]?\d{3,4}(?!\d)"),
    ),
    (
        "identity_document_candidate",
        re.compile(r"(?:護照|居留證|身分證)(?:號碼|號)?\s*[:：]?\s*[A-Z0-9-]{6,16}", re.IGNORECASE),
    ),
    (
        "person_name_candidate",
        re.compile(r"(?:申請人|業主|所有權人|聯絡人|姓名|承辦人)\s*(?:為|[:：])?\s*[\u3400-\u9fff]{2,6}"),
    ),
    (
        "unlabeled_name_candidate",
        re.compile(
            r"(?<![\u3400-\u9fff])"
            r"(?:王|李|張|陳|林|黃|吳|劉|蔡|楊|許|鄭|謝|洪|郭|邱|曾|廖|賴|徐|周|葉|蘇|莊|呂|江|何|蕭|羅|高|潘|簡|朱|鍾|游|彭|詹|胡|施|沈|余|盧|梁|趙|顏|柯|翁|魏|孫|戴|范|方|宋|鄧|杜|傅|侯|曹|溫|薛|丁|馬|蔣|歐陽)"
            # A place or organization suffix right after the surname means this is
            # a location or an authority, not a person. Without this guard every
            # document mentioning \u6797\u53e3\u5340 or \u9ad8\u96c4\u5e02 would block model delivery.
            r"(?![\u3400-\u9fff]?(?:\u5340|\u9109|\u93ae|\u5e02|\u7e23|\u91cc|\u6751|\u8def|\u8857|\u6bb5|\u5df7|\u5f04|\u865f|\u6a13|\u5ba4|\u68df|\u5c40|\u8655"
            r"|\u79d1|\u8ab2|\u80a1|\u6703|\u793e|\u53f8|\u5ee0|\u5834|\u9662|\u6821|\u7f72|\u5e9c|\u6240|\u90e8|\u7d44|\u968a|\u7ad9|\u5712|\u9928|\u5bfa|\u5edf|\u6a4b|\u5c71|\u6cb3"
            r"|\u6c5f|\u6e56|\u6d77|\u5cf6)(?![\u3400-\u9fff]))"
            r"[\u3400-\u9fff]{1,2}(?![\u3400-\u9fff])"
        ),
    ),
    (
        "birth_date_candidate",
        re.compile(
            r"(?:\u51fa\u751f|\u751f\u65e5|D\.?O\.?B\.?)[^\n]{0,8}?"
            r"(?:\u4e2d\u83ef\u6c11\u570b|\u6c11\u570b)?\s*\d{1,4}\s*[./\u5e74-]\s*\d{1,2}\s*[./\u6708-]\s*\d{1,2}",
            re.IGNORECASE,
        ),
    ),
    (
        "mixed_identity_candidate",
        re.compile(r"(?<![A-Z0-9])(?=[A-Z0-9]{8,16}(?![A-Z0-9]))(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{8,16}", re.IGNORECASE),
    ),
    (
        "address_candidate",
        re.compile(
            r"(?:[\u3400-\u9fff]{2,6}(?:市|縣))?"
            r"[\u3400-\u9fff]{1,10}(?:區|鄉|鎮|市)"
            r"[^\n，,。]{0,28}(?:路|街|大道|巷|弄)[^\n，,。]{0,16}\d+號"
        ),
    ),
    (
        "account_or_case_candidate",
        re.compile(r"(?:帳號|帳戶|案件編號|申請案號)\s*[:：]?\s*[A-Z0-9-]{5,32}", re.IGNORECASE),
    ),
)


def find_residual_sensitive_classes(text: str) -> list[str]:
    return [name for name, pattern in RESIDUAL_PATTERNS if pattern.search(text)]
