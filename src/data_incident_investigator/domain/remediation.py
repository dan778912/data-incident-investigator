from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

_COLUMN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_. -]{0,127}$")


def _validate_column(value: str) -> str:
    if value == "*" or not _COLUMN_PATTERN.fullmatch(value):
        raise ValueError("column must be an explicit, valid column name")
    return value


class RenameColumn(BaseModel):
    op: Literal["rename_column"] = "rename_column"
    from_name: str
    to_name: str

    _validate_from = field_validator("from_name")(_validate_column)
    _validate_to = field_validator("to_name")(_validate_column)


class CastColumn(BaseModel):
    op: Literal["cast_column"] = "cast_column"
    column: str
    target_type: Literal["string", "integer", "float", "boolean"]
    invalid_policy: Literal["reject", "coerce_null"] = "reject"

    _validate_name = field_validator("column")(_validate_column)


class FillMissing(BaseModel):
    op: Literal["fill_missing"] = "fill_missing"
    column: str
    strategy: Literal["constant", "median", "mode"]
    value: str | int | float | bool | None = None

    _validate_name = field_validator("column")(_validate_column)

    @model_validator(mode="after")
    def constant_requires_value(self) -> FillMissing:
        if self.strategy == "constant" and self.value is None:
            raise ValueError("constant fill requires a value")
        return self


class DropDuplicates(BaseModel):
    op: Literal["drop_duplicates"] = "drop_duplicates"
    keys: list[str] = Field(min_length=1, max_length=10)
    keep: Literal["first", "last"] = "last"

    @field_validator("keys")
    @classmethod
    def validate_keys(cls, value: list[str]) -> list[str]:
        return [_validate_column(item) for item in value]


class ParseDatetime(BaseModel):
    op: Literal["parse_datetime"] = "parse_datetime"
    column: str
    accepted_formats: list[str] = Field(min_length=1, max_length=10)
    timezone: str = Field(default="UTC", max_length=64)
    on_error: Literal["reject", "coerce_null"] = "reject"

    _validate_name = field_validator("column")(_validate_column)


class NormalizeString(BaseModel):
    op: Literal["normalize_string"] = "normalize_string"
    columns: list[str] = Field(min_length=1, max_length=20)
    trim: bool = True
    casefold: bool = False
    unicode_form: Literal["NFC", "NFKC"] = "NFKC"

    @field_validator("columns")
    @classmethod
    def validate_columns(cls, value: list[str]) -> list[str]:
        return [_validate_column(item) for item in value]


class ReplaceValues(BaseModel):
    op: Literal["replace_values"] = "replace_values"
    column: str
    mapping: dict[str, str] = Field(min_length=1, max_length=50)

    _validate_name = field_validator("column")(_validate_column)


RemediationOperation = Annotated[
    RenameColumn
    | CastColumn
    | FillMissing
    | DropDuplicates
    | ParseDatetime
    | NormalizeString
    | ReplaceValues,
    Field(discriminator="op"),
]


class RemediationPlan(BaseModel):
    plan_id: UUID = Field(default_factory=uuid4)
    source_artifact_id: UUID
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    operations: list[RemediationOperation] = Field(min_length=1, max_length=5)
    expected_effects: list[str] = Field(min_length=1, max_length=10)
    required_post_checks: list[str] = Field(min_length=1, max_length=20)
    citation_ids: list[str] = Field(min_length=1, max_length=20)
    rationale: str = Field(min_length=1, max_length=4000)
    plan_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    def canonical_payload(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"plan_hash"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def calculate_hash(self) -> str:
        return hashlib.sha256(self.canonical_payload()).hexdigest()

    @model_validator(mode="after")
    def populate_or_check_hash(self) -> RemediationPlan:
        expected = self.calculate_hash()
        if self.plan_hash is None:
            self.plan_hash = expected
        elif self.plan_hash != expected:
            raise ValueError("plan hash does not match normalized plan contents")
        return self


class ApprovalDecision(BaseModel):
    approval_id: UUID = Field(default_factory=uuid4)
    plan_id: UUID
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved: bool
    note: str | None = Field(default=None, max_length=1000)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + timedelta(hours=1))
    nonce: UUID = Field(default_factory=uuid4)

    @model_validator(mode="after")
    def expiry_must_follow_decision(self) -> ApprovalDecision:
        if self.expires_at <= self.decided_at:
            raise ValueError("approval expiry must be after the decision time")
        return self
