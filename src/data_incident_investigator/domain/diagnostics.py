from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class DiagnosticTool(StrEnum):
    PROFILE_DATASET = "profile_dataset"
    CHECK_NULL_RATIO = "check_null_ratio"
    CHECK_DUPLICATE_KEYS = "check_duplicate_keys"
    CHECK_TYPE_CONFORMANCE = "check_type_conformance"
    CHECK_DATETIME_PARSE = "check_datetime_parse"
    INSPECT_LOG_SIGNATURES = "inspect_log_signatures"


class ProfileDatasetArgs(BaseModel):
    sample_rows: int = Field(default=5, ge=1, le=20)


class CheckNullRatioArgs(BaseModel):
    columns: list[str] = Field(default_factory=list, max_length=50)
    threshold: float = Field(default=0.10, ge=0.0, le=1.0)


class CheckDuplicateKeysArgs(BaseModel):
    keys: list[str] = Field(min_length=1, max_length=10)

    @field_validator("keys")
    @classmethod
    def keys_must_be_specific(cls, value: list[str]) -> list[str]:
        if any(not key.strip() or key == "*" for key in value):
            raise ValueError("duplicate-key checks require explicit column names")
        return value


class CheckTypeConformanceArgs(BaseModel):
    expected_types: dict[str, str] = Field(min_length=1, max_length=50)


class CheckDatetimeParseArgs(BaseModel):
    column: str = Field(min_length=1, max_length=128)
    accepted_formats: list[str] = Field(default_factory=list, max_length=10)


class InspectLogSignaturesArgs(BaseModel):
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
