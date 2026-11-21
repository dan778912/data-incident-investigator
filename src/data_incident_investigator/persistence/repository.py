from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import aiosqlite

from data_incident_investigator.domain.artifacts import ArtifactKind, StoredArtifact
from data_incident_investigator.domain.cases import CaseStatus, CreateCaseRequest, IncidentCase


class ApplicationRepository:
    """Small async repository for the single-user local deployment."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path

    async def setup(self) -> None:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self._database_path) as connection:
            await connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;

                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    incident_summary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    immutable INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            await connection.commit()

    async def healthcheck(self) -> bool:
        try:
            async with aiosqlite.connect(self._database_path) as connection:
                row = await (await connection.execute("SELECT 1")).fetchone()
            return row == (1,)
        except aiosqlite.Error:
            return False

    async def create_case(self, request: CreateCaseRequest) -> IncidentCase:
        case = IncidentCase(name=request.name, incident_summary=request.incident_summary)
        async with aiosqlite.connect(self._database_path) as connection:
            await connection.execute(
                """
                INSERT INTO cases(case_id, name, incident_summary, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(case.case_id),
                    case.name,
                    case.incident_summary,
                    case.status.value,
                    case.created_at.isoformat(),
                    case.updated_at.isoformat(),
                ),
            )
            await connection.commit()
        return case

    async def get_case(self, case_id: UUID) -> IncidentCase | None:
        async with aiosqlite.connect(self._database_path) as connection:
            connection.row_factory = aiosqlite.Row
            row = await (
                await connection.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id),))
            ).fetchone()
        return self._case_from_row(row) if row else None

    async def list_cases(self) -> list[IncidentCase]:
        async with aiosqlite.connect(self._database_path) as connection:
            connection.row_factory = aiosqlite.Row
            rows = await (
                await connection.execute("SELECT * FROM cases ORDER BY created_at DESC")
            ).fetchall()
        return [self._case_from_row(row) for row in rows]

    async def set_case_status(self, case_id: UUID, status: CaseStatus) -> bool:
        now = datetime.now(UTC).isoformat()
        async with aiosqlite.connect(self._database_path) as connection:
            cursor = await connection.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                (status.value, now, str(case_id)),
            )
            await connection.commit()
            return cursor.rowcount == 1

    async def add_artifact(self, artifact: StoredArtifact) -> None:
        async with aiosqlite.connect(self._database_path) as connection:
            await connection.execute(
                """
                INSERT INTO artifacts(
                    artifact_id, case_id, kind, original_filename, storage_path, media_type,
                    size_bytes, sha256, immutable, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(artifact.artifact_id),
                    str(artifact.case_id),
                    artifact.kind.value,
                    artifact.original_filename,
                    str(artifact.storage_path),
                    artifact.media_type,
                    artifact.size_bytes,
                    artifact.sha256,
                    int(artifact.immutable),
                    artifact.created_at.isoformat(),
                ),
            )
            await connection.commit()

    async def get_artifact(self, artifact_id: UUID) -> StoredArtifact | None:
        async with aiosqlite.connect(self._database_path) as connection:
            connection.row_factory = aiosqlite.Row
            row = await (
                await connection.execute(
                    "SELECT * FROM artifacts WHERE artifact_id = ?", (str(artifact_id),)
                )
            ).fetchone()
        if row is None:
            return None
        return StoredArtifact(
            artifact_id=UUID(row["artifact_id"]),
            case_id=UUID(row["case_id"]),
            kind=ArtifactKind(row["kind"]),
            original_filename=row["original_filename"],
            storage_path=Path(row["storage_path"]),
            media_type=row["media_type"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            immutable=bool(row["immutable"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    async def list_artifacts(self, case_id: UUID) -> list[StoredArtifact]:
        async with aiosqlite.connect(self._database_path) as connection:
            connection.row_factory = aiosqlite.Row
            rows = await (
                await connection.execute(
                    "SELECT artifact_id FROM artifacts WHERE case_id = ? ORDER BY created_at",
                    (str(case_id),),
                )
            ).fetchall()
        artifacts: list[StoredArtifact] = []
        for row in rows:
            artifact = await self.get_artifact(UUID(row["artifact_id"]))
            if artifact is not None:
                artifacts.append(artifact)
        return artifacts

    async def append_audit_event(
        self,
        *,
        case_id: UUID,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> int:
        safe_payload = json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))
        async with aiosqlite.connect(self._database_path) as connection:
            cursor = await connection.execute(
                """
                INSERT INTO audit_events(case_id, event_type, actor, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(case_id),
                    event_type,
                    actor,
                    safe_payload,
                    datetime.now(UTC).isoformat(),
                ),
            )
            await connection.commit()
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return an audit event sequence")
            return cursor.lastrowid

    @staticmethod
    def _case_from_row(row: aiosqlite.Row) -> IncidentCase:
        return IncidentCase(
            case_id=UUID(row["case_id"]),
            name=row["name"],
            incident_summary=row["incident_summary"],
            status=CaseStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
