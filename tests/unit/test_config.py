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
