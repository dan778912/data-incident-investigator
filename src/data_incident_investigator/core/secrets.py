from __future__ import annotations

import secrets
from pathlib import Path

from data_incident_investigator.core.config import Settings


class SecretConfigurationError(RuntimeError):
    """Raised when production secrets are missing or malformed."""


def load_or_create_approval_key(settings: Settings) -> bytes:
    """Load an environment key or persist a local random key outside source control."""

    configured = settings.approval_hmac_key
    if configured is not None:
        key = configured.get_secret_value().encode("utf-8")
        if len(key) < 32:
            raise SecretConfigurationError("APPROVAL_HMAC_KEY must contain at least 32 bytes")
        return key

    if settings.app_env == "production":
        raise SecretConfigurationError("APPROVAL_HMAC_KEY is required in production")

    path = settings.resolved_data_dir / ".approval_hmac_key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return _read_local_key(path)

    key = secrets.token_bytes(32)
    try:
        with path.open("xb") as stream:
            stream.write(key)
    except FileExistsError:
        return _read_local_key(path)
    return key


def _read_local_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) < 32:
        raise SecretConfigurationError("persisted approval key is invalid")
    return key
