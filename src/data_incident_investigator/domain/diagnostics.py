from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DiagnosticTool(StrEnum):
    PROFILE_DATASET = "profile_dataset"
    CHECK_NULL_RATIO = "check_null_ratio"
    CHECK_DUPLICATE_KEYS = "check_duplicate_keys"
    CHECK_TYPE_CONFORMANCE = "check_type_conformance"
    CHECK_DATETIME_PARSE = "check_datetime_parse"
    INSPECT_LOG_SIGNATURES = "inspect_log_signatures"


class DiagnosticArguments(BaseModel):
    """Strict base model for every allowlisted diagnostic capability."""

    model_config = ConfigDict(extra="forbid")


class ProfileDatasetArgs(DiagnosticArguments):
    sample_rows: int = Field(default=5, ge=1, le=20)
    column: str | None = Field(default=None, min_length=1, max_length=128)
    value_counts: bool = False
    value_count_limit: int = Field(default=20, ge=1, le=50)
    keep_default_na: bool = True

    @model_validator(mode="after")
    def value_counts_require_column(self) -> ProfileDatasetArgs:
        if self.value_counts and self.column is None:
            raise ValueError("value_counts requires one explicit column")
        if self.column == "*":
            raise ValueError("profile diagnostics require an explicit column name")
        return self


class CheckNullRatioArgs(DiagnosticArguments):
    column: str | None = Field(default=None, min_length=1, max_length=128)
    columns: list[str] = Field(default_factory=list, max_length=50)
    threshold: float = Field(default=0.10, ge=0.0, le=1.0)
    keep_default_na: bool = True
    na_values: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def select_one_column_shape(self) -> CheckNullRatioArgs:
        if self.column is not None and self.columns:
            raise ValueError("use either column or columns, not both")
        if self.column == "*":
            raise ValueError("null-ratio checks require an explicit column name")
        return self

    @field_validator("columns")
    @classmethod
    def columns_must_be_specific(cls, value: list[str]) -> list[str]:
        if any(not column.strip() or column == "*" for column in value):
            raise ValueError("null-ratio checks require explicit column names")
        return value

    @field_validator("na_values")
    @classmethod
    def limit_marker_length(cls, value: list[str]) -> list[str]:
        if any(len(item) > 128 for item in value):
            raise ValueError("null markers may be at most 128 characters")
        return value


class CheckDuplicateKeysArgs(DiagnosticArguments):
    keys: list[str] = Field(min_length=1, max_length=10)

    @field_validator("keys")
    @classmethod
    def keys_must_be_specific(cls, value: list[str]) -> list[str]:
        if any(not key.strip() or key == "*" for key in value):
            raise ValueError("duplicate-key checks require explicit column names")
        return value


class CheckTypeConformanceArgs(DiagnosticArguments):
    expected_types: dict[str, str] = Field(min_length=1, max_length=50)


class CheckDatetimeParseArgs(DiagnosticArguments):
    column: str = Field(min_length=1, max_length=128)
    accepted_formats: list[str] = Field(default_factory=list, max_length=10)


class InspectLogSignaturesArgs(DiagnosticArguments):
    signatures: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("signatures")
    @classmethod
    def limit_signature_length(cls, value: list[str]) -> list[str]:
        if any(len(item) > 200 for item in value):
            raise ValueError("log signatures may be at most 200 characters")
        return value


TOOL_ARGUMENT_MODELS: dict[DiagnosticTool, type[BaseModel]] = {
    DiagnosticTool.PROFILE_DATASET: ProfileDatasetArgs,
    DiagnosticTool.CHECK_NULL_RATIO: CheckNullRatioArgs,
    DiagnosticTool.CHECK_DUPLICATE_KEYS: CheckDuplicateKeysArgs,
    DiagnosticTool.CHECK_TYPE_CONFORMANCE: CheckTypeConformanceArgs,
    DiagnosticTool.CHECK_DATETIME_PARSE: CheckDatetimeParseArgs,
    DiagnosticTool.INSPECT_LOG_SIGNATURES: InspectLogSignaturesArgs,
}


class DiagnosticRequest(BaseModel):
    tool: DiagnosticTool
    artifact_id: UUID
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=1000)


class DiagnosticObservation(BaseModel):
    tool: DiagnosticTool
    artifact_id: UUID
    success: bool
    summary: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
