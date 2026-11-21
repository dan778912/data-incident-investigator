from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import UUID, uuid4

from data_incident_investigator.domain.artifacts import ArtifactKind, StoredArtifact
from data_incident_investigator.security.paths import CasePathResolver, sanitize_filename


class ArtifactValidationError(ValueError):
    """Raised when an uploaded artifact fails a deterministic validation rule."""


_EXTENSIONS_BY_KIND: dict[ArtifactKind, set[str]] = {
    ArtifactKind.DATASET: {".csv", ".json"},
    ArtifactKind.LOG: {".log", ".txt"},
    ArtifactKind.SCHEMA: {".json", ".yaml", ".yml"},
    ArtifactKind.RUNBOOK: {".md", ".txt", ".yaml", ".yml"},
}

_MEDIA_BY_EXTENSION = {
    ".csv": "text/csv",
    ".json": "application/json",
    ".log": "text/plain",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


class ArtifactStore:
    """Writes validated, immutable originals to case-scoped storage."""

    def __init__(self, resolver: CasePathResolver, max_upload_bytes: int) -> None:
        self._resolver = resolver
        self._max_upload_bytes = max_upload_bytes

    def save(
        self,
        *,
        case_id: UUID,
        filename: str,
        content: bytes,
        kind: ArtifactKind,
    ) -> StoredArtifact:
        safe_name = sanitize_filename(filename)
        suffix = Path(safe_name).suffix.lower()
        self._validate(kind=kind, suffix=suffix, content=content)

        artifact_id = uuid4()
        destination = self._resolver.artifact_path(case_id, artifact_id, safe_name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(content)

        return StoredArtifact(
            artifact_id=artifact_id,
            case_id=case_id,
            kind=kind,
            original_filename=safe_name,
            storage_path=destination,
            media_type=_MEDIA_BY_EXTENSION[suffix],
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            immutable=True,
        )

    def _validate(self, *, kind: ArtifactKind, suffix: str, content: bytes) -> None:
        if kind not in _EXTENSIONS_BY_KIND:
            raise ArtifactValidationError(f"uploads do not support artifact kind {kind}")
        if suffix not in _EXTENSIONS_BY_KIND[kind]:
            label = suffix or "extensionless"
            raise ArtifactValidationError(f"{label} files are not valid for {kind}")
        if not content:
            raise ArtifactValidationError("artifact is empty")
        if len(content) > self._max_upload_bytes:
            raise ArtifactValidationError("artifact exceeds the configured upload limit")
        if b"\x00" in content and suffix not in {".json"}:
            raise ArtifactValidationError("binary or NUL-containing content is not supported")

        try:
            decoded = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ArtifactValidationError("artifacts must be UTF-8 encoded") from exc

        if suffix == ".json":
            try:
                json.loads(decoded)
            except json.JSONDecodeError as exc:
                raise ArtifactValidationError("JSON artifact is not valid JSON") from exc
