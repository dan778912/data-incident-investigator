from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from data_incident_investigator.domain.artifacts import ArtifactKind, StoredArtifact
from data_incident_investigator.domain.cases import CaseStatus, CreateCaseRequest
from data_incident_investigator.persistence import ApplicationRepository


@pytest.mark.asyncio
async def test_case_artifact_and_audit_round_trip(tmp_path: Path) -> None:
    repository = ApplicationRepository(tmp_path / "application.sqlite3")
    await repository.setup()
    assert await repository.healthcheck() is True

    case = await repository.create_case(
        CreateCaseRequest(
            name="Timestamp incident",
            incident_summary="Rows disappeared after UTC rollout",
        )
    )
    artifact = StoredArtifact(
        case_id=case.case_id,
        kind=ArtifactKind.DATASET,
        original_filename="events.csv",
        storage_path=tmp_path / "events.csv",
        media_type="text/csv",
        size_bytes=20,
        sha256="a" * 64,
    )
    await repository.add_artifact(artifact)
    sequence = await repository.append_audit_event(
        case_id=case.case_id,
        event_type="artifact_ingested",
        actor="system",
        payload={"artifact_id": str(artifact.artifact_id)},
    )

    loaded_case = await repository.get_case(case.case_id)
    loaded_artifact = await repository.get_artifact(artifact.artifact_id)
    case_artifacts = await repository.list_artifacts(case.case_id)
    cases = await repository.list_cases()

    assert sequence == 1
    assert loaded_case == case
    assert loaded_artifact == artifact
    assert case_artifacts == [artifact]
    assert cases == [case]


@pytest.mark.asyncio
async def test_status_update_and_missing_records(tmp_path: Path) -> None:
    repository = ApplicationRepository(tmp_path / "application.sqlite3")
    await repository.setup()
    case = await repository.create_case(
        CreateCaseRequest(name="Schema drift", incident_summary="A column was renamed")
    )

    assert await repository.set_case_status(case.case_id, CaseStatus.ANALYZING) is True
    updated = await repository.get_case(case.case_id)

    assert updated is not None and updated.status == CaseStatus.ANALYZING
    assert await repository.set_case_status(uuid4(), CaseStatus.COMPLETED) is False
    assert await repository.get_case(uuid4()) is None
    assert await repository.get_artifact(uuid4()) is None
