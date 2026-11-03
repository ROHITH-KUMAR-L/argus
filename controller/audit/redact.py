"""Secret redaction and bounded capture for anything written to the audit store."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATION_MARKER = "\n[... truncated by argus: {dropped} bytes omitted ...]"

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}"),  # OpenAI / Anthropic-style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # GitHub tokens
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack tokens
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(
        r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)\b(\s*[:=]\s*)"
        r"(\"[^\"]*\"|'[^']*'|[^\s,;}&]+)"
    ),
]

_SENSITIVE_KEY = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|authorization|credential)"
)


class Redactor:
    """Redacts known secret values exactly, plus common secret patterns."""

    def __init__(self, known_secrets: Iterable[str] = ()) -> None:
        self._known = sorted({s for s in known_secrets if s and len(s) >= 6}, key=len, reverse=True)

    def text(self, s: str) -> str:
        for secret in self._known:
            s = s.replace(secret, REDACTED)
        for pat in _PATTERNS:
            if pat.groups >= 3:
                s = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
            else:
                s = pat.sub(REDACTED, s)
        return s

    def value(self, v: Any) -> Any:
        """Recursively redact strings inside JSON-like data (keys included)."""
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, dict):
            return {
                self.text(str(k)): REDACTED
                if _SENSITIVE_KEY.search(str(k)) and isinstance(x, str | int | float)
                else self.value(x)
                for k, x in v.items()
            }
        if isinstance(v, list | tuple):
            return [self.value(x) for x in v]
        return v


def bound(data: str | bytes, cap: int) -> tuple[str, bool]:
    """Truncate to ``cap`` UTF-8 bytes with an explicit marker. Returns (text, truncated)."""
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else data
    if len(raw) <= cap:
        return raw.decode("utf-8", "replace"), False
    kept = raw[:cap].decode("utf-8", "ignore")
    return kept + TRUNCATION_MARKER.format(dropped=len(raw) - cap), True
