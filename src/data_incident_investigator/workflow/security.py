"""Security primitives for approval-bound workflow state."""

from __future__ import annotations

import hashlib
import json


class ApprovalValidationError(RuntimeError):
    """Base class for a rejected approval resume payload."""


class ApprovalBindingMismatchError(ApprovalValidationError):
    """Raised when signed context differs from the current proposal or sources."""


class ApprovalExpiredError(ApprovalValidationError):
    """Raised when an approval is resumed after its expiry."""


class ApprovalReplayError(ApprovalValidationError):
    """Raised when an approval nonce has already been consumed or is unknown."""


def canonical_json(value: object) -> bytes:
    """Encode strict JSON deterministically for hashing and signing."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApprovalBindingMismatchError("approval context is not strict JSON") from exc


def canonical_sha256(value: object) -> str:
    """Return the SHA-256 digest of a canonical JSON value."""

    return hashlib.sha256(canonical_json(value)).hexdigest()
