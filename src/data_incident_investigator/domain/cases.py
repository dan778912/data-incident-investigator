from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class CaseStatus(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    ANALYZING = "analyzing"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class IncidentCase(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=160)
    incident_summary: str = Field(min_length=1, max_length=4000)
    status: CaseStatus = CaseStatus.DRAFT
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CreateCaseRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    incident_summary: str = Field(min_length=1, max_length=4000)
