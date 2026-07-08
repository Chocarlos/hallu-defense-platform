from __future__ import annotations

import re
import unicodedata

TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]+")


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", " ", ascii_text).strip().lower()


def tokenize(value: str) -> set[str]:
    return {
        token
        for token in TOKEN_RE.findall(normalize_text(value))
        if len(token) > 2 and token not in {"the", "and", "for", "con", "los", "las", "una", "uno"}
    }


def bounded(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 20].rstrip() + "\n[output truncated]"

