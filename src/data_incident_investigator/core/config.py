from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed settings with conservative local defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["development", "test", "production"] = "development"
    app_host: str = "127.0.0.1"
    app_port: int = Field(default=8000, ge=1, le=65535)
    data_dir: Path = Path("data")
    frontend_dir: Path = Path("web/dist")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    llm_provider: Literal["fake", "openai", "nvidia"] = "fake"
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-6.2-astra"
    openai_reasoning_effort: Literal["low", "medium", "high", "xhigh", "max"] = "low"
    openai_input_cost_per_million: float = Field(default=8.0, ge=0)
    openai_cached_input_cost_per_million: float = Field(default=0.4, ge=0)
    openai_output_cost_per_million: float = Field(default=40.0, ge=0)
    approval_hmac_key: SecretStr | None = None

    max_upload_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=100 * 1024 * 1024)
    max_dataset_rows: int = Field(default=100_000, ge=1, le=1_000_000)
    max_retrieval_rounds: int = Field(default=3, ge=1, le=5)
    max_plan_revisions: int = Field(default=2, ge=1, le=5)
    max_patch_operations: int = Field(default=5, ge=1, le=10)

    @field_validator("data_dir", mode="before")
    @classmethod
    def normalize_data_dir(cls, value: object) -> Path:
        return Path(str(value)).expanduser()

    @field_validator("frontend_dir", mode="before")
    @classmethod
    def normalize_frontend_dir(cls, value: object) -> Path:
        return Path(str(value)).expanduser()

    @field_validator("openai_api_key", "approval_hmac_key", mode="before")
    @classmethod
    def empty_secret_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir.resolve()

    @property
    def resolved_frontend_dir(self) -> Path:
        return self.frontend_dir.resolve()

    @property
    def cases_dir(self) -> Path:
        return self.resolved_data_dir / "cases"

    @property
    def application_database(self) -> Path:
        return self.resolved_data_dir / "application.sqlite3"

    @property
    def checkpoint_database(self) -> Path:
        return self.resolved_data_dir / "checkpoints.sqlite3"

    @property
    def approval_database(self) -> Path:
        return self.resolved_data_dir / "approvals.sqlite3"

    @property
    def retrieval_database(self) -> Path:
        return self.resolved_data_dir / "retrieval.sqlite3"

    def prepare_directories(self) -> None:
        self.cases_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.prepare_directories()
    return settings
