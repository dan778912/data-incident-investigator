from __future__ import annotations

from pathlib import Path

import pytest

from data_incident_investigator.core.config import Settings
from data_incident_investigator.core.secrets import (
    SecretConfigurationError,
    load_or_create_approval_key,
)


def test_local_approval_key_is_generated_and_reused(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, app_env="test")

    first = load_or_create_approval_key(settings)
    second = load_or_create_approval_key(settings)

    assert len(first) == 32
    assert first == second
    assert (tmp_path / ".approval_hmac_key").read_bytes() == first


def test_configured_key_is_used_without_writing_file(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        app_env="production",
        approval_hmac_key="x" * 32,
    )
    assert load_or_create_approval_key(settings) == b"x" * 32
    assert not (tmp_path / ".approval_hmac_key").exists()


def test_production_requires_key(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, app_env="production")
    with pytest.raises(SecretConfigurationError, match="required"):
        load_or_create_approval_key(settings)


def test_short_configured_or_persisted_keys_fail(tmp_path: Path) -> None:
    with pytest.raises(SecretConfigurationError, match="at least 32"):
        load_or_create_approval_key(Settings(data_dir=tmp_path, approval_hmac_key="short"))

    (tmp_path / ".approval_hmac_key").write_bytes(b"short")
    with pytest.raises(SecretConfigurationError, match="persisted"):
        load_or_create_approval_key(Settings(data_dir=tmp_path))
