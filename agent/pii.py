"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])"
)
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)0(?:[\s-]?\d){9,10}(?!\d)")
_BANK_RE = re.compile(
    r"(?i)(?:\bSTK\b|\bsố\s+tài\s+kh[oảa]n\b)\s*:?\s*(\d{8,16})(?!\d)"
)


def _entity(entity_type: str, match: re.Match[str], group: int = 0) -> dict:
    start, end = match.span(group)
    return {"type": entity_type, "start": start, "end": end}


def _overlaps(first: dict, second: dict) -> bool:
    return first["start"] < second["end"] and second["start"] < first["end"]


def detect(text: str) -> list[dict]:
    candidates: list[dict] = []
    candidates.extend(_entity("EMAIL", match) for match in _EMAIL_RE.finditer(text))
    candidates.extend(_entity("VN_BANK_ACCOUNT", match, 1) for match in _BANK_RE.finditer(text))
    candidates.extend(_entity("VN_CCCD", match) for match in _CCCD_RE.finditer(text))
    candidates.extend(_entity("VN_PHONE", match) for match in _PHONE_RE.finditer(text))

    # Keep the more specific/contextual match when numeric patterns overlap.
    selected: list[dict] = []
    for candidate in sorted(
        candidates,
        key=lambda item: (
            item["start"],
            {"EMAIL": 0, "VN_BANK_ACCOUNT": 1, "VN_CCCD": 2, "VN_PHONE": 3}[
                item["type"]
            ],
            -(item["end"] - item["start"]),
        ),
    ):
        if not any(_overlaps(candidate, existing) for existing in selected):
            selected.append(candidate)

    return sorted(selected, key=lambda item: item["start"])


def redact(text: str) -> str:
    redacted = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = (
            redacted[: entity["start"]]
            + replacement
            + redacted[entity["end"] :]
        )
    return redacted
