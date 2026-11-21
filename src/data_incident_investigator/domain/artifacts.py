from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class ArtifactKind(StrEnum):
    DATASET = "dataset"
    LOG = "log"
    SCHEMA = "schema"
    RUNBOOK = "runbook"
    WORKING_COPY = "working_copy"
    REPORT = "report"


class StoredArtifact(BaseModel):
    """Metadata for a case-scoped artifact; paths never enter model prompts."""

    model_config = ConfigDict(frozen=True)

    artifact_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    kind: ArtifactKind
    original_filename: str
    storage_path: Path
    media_type: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    immutable: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ArtifactView(BaseModel):
    """Public artifact metadata that never exposes a server filesystem path."""

    artifact_id: UUID
    case_id: UUID
    kind: ArtifactKind
    original_filename: str
    media_type: str
    size_bytes: int
    sha256: str
    immutable: bool
    created_at: datetime

    @classmethod
    def from_stored(cls, artifact: StoredArtifact) -> ArtifactView:
        return cls(**artifact.model_dump(exclude={"storage_path"}))
