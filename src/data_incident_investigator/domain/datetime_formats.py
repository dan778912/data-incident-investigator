"""Canonical datetime format identifiers shared by bounded data operations."""

from __future__ import annotations

from typing import Final, Literal

type CanonicalDatetimeFormat = Literal[
    "rfc3339",
    "MM/DD/YYYY hh:mm AM UTC",
]

CANONICAL_DATETIME_FORMAT_ORDER: Final[tuple[CanonicalDatetimeFormat, ...]] = (
    "rfc3339",
    "MM/DD/YYYY hh:mm AM UTC",
)

# Pandas parsing formats are implementation details. Model-facing schemas expose
# only the stable identifiers above.
PANDAS_DATETIME_FORMATS: Final[dict[CanonicalDatetimeFormat, str]] = {
    "rfc3339": "ISO8601",
    "MM/DD/YYYY hh:mm AM UTC": "%m/%d/%Y %I:%M %p UTC",
}

RFC3339_PATTERN: Final[str] = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
