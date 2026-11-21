from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RedactionEvent:
    category: str
    count: int


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("nvidia_key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE)),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    (
        "assigned_secret",
        re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*[^\s,;]{6,}"),
    ),
)


def redact_secrets(text: str) -> tuple[str, list[RedactionEvent]]:
    redacted = text
    events: list[RedactionEvent] = []
    for category, pattern in _PATTERNS:
        redacted, count = pattern.subn(f"[REDACTED:{category}]", redacted)
        if count:
            events.append(RedactionEvent(category=category, count=count))
    return redacted, events
