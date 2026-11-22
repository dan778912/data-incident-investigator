from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from data_incident_investigator.core.config import Settings


def test_settings_prepare_local_directories(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, llm_provider="fake")

    settings.prepare_directories()

    assert settings.resolved_data_dir == tmp_path.resolve()
    assert settings.cases_dir.is_dir()
    assert settings.application_database.parent == tmp_path.resolve()
    assert settings.checkpoint_database.name == "checkpoints.sqlite3"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("app_port", 0),
        ("max_retrieval_rounds", 0),
        ("max_plan_revisions", 6),
        ("max_patch_operations", 11),
    ],
)
def test_settings_reject_unsafe_limits(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_settings_normalize_string_path(tmp_path: Path) -> None:
    settings = Settings(data_dir=str(tmp_path))
    assert isinstance(settings.data_dir, Path)


def test_nvidia_settings_use_free_development_endpoint_defaults() -> None:
    settings = Settings(
        nvidia_api_key="nvapi-test-key",
        nvidia_model="  nvidia/nemotron-3.5-lightning-30b-a3b  ",
        nvidia_base_url="https://integrate.api.nvidia.com/v1/",
    )

    assert settings.nvidia_api_key is not None
    assert settings.nvidia_api_key.get_secret_value() == "nvapi-test-key"
    assert settings.nvidia_model == "nvidia/nemotron-3.5-lightning-30b-a3b"
    assert settings.nvidia_base_url == "https://integrate.api.nvidia.com/v1"
    assert settings.nvidia_input_cost_per_million == 0
    assert settings.nvidia_cached_input_cost_per_million == 0
    assert settings.nvidia_output_cost_per_million == 0


@pytest.mark.parametrize("field", ["openai_api_key", "nvidia_api_key", "approval_hmac_key"])
@pytest.mark.parametrize("value", ["", "   ", "\t\r\n"])
def test_settings_treat_blank_secrets_as_missing(field: str, value: str) -> None:
    settings = Settings(**{field: value})
    assert getattr(settings, field) is None


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434/v1/",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1",
    ],
)
def test_nvidia_settings_allow_plaintext_only_for_local_endpoints(url: str) -> None:
    settings = Settings(nvidia_base_url=url)
    assert settings.nvidia_base_url == url.rstrip("/")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("nvidia_model", "   "),
        ("nvidia_base_url", "integrate.api.nvidia.com/v1"),
        ("nvidia_base_url", "http://integrate.api.nvidia.com/v1"),
        ("nvidia_base_url", "https://user:password@example.test/v1"),
        ("nvidia_input_cost_per_million", -0.01),
        ("nvidia_cached_input_cost_per_million", -0.01),
        ("nvidia_output_cost_per_million", -0.01),
    ],
)
def test_settings_reject_invalid_nvidia_configuration(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})
