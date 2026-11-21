from __future__ import annotations

import re
from pathlib import Path
from uuid import UUID

_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")


class PathBoundaryError(ValueError):
    """Raised when a path would escape case-scoped storage."""


def sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip().replace("\x00", "")
    name = _SAFE_FILENAME_CHARS.sub("_", name)
    if name in {"", ".", ".."}:
        raise PathBoundaryError("filename is empty after sanitization")
    return name[:180]


class CasePathResolver:
    def __init__(self, data_root: Path) -> None:
        self._root = data_root.resolve()

    @property
    def root(self) -> Path:
        return self._root

    def case_root(self, case_id: UUID) -> Path:
        return self._ensure_within_root(self._root / "cases" / str(case_id))

    def originals_dir(self, case_id: UUID) -> Path:
        return self._ensure_within_root(self.case_root(case_id) / "originals")

    def working_dir(self, case_id: UUID) -> Path:
        return self._ensure_within_root(self.case_root(case_id) / "working")

    def artifact_path(self, case_id: UUID, artifact_id: UUID, filename: str) -> Path:
        safe_name = sanitize_filename(filename)
        suffix = Path(safe_name).suffix.lower()
        return self._ensure_within_root(self.originals_dir(case_id) / f"{artifact_id}{suffix}")

    def working_path(self, case_id: UUID, plan_id: UUID, source_suffix: str) -> Path:
        suffix = source_suffix.lower()
        if suffix not in {".csv", ".json"}:
            raise PathBoundaryError("working copies support only CSV and JSON datasets")
        return self._ensure_within_root(self.working_dir(case_id) / f"{plan_id}{suffix}")

    def _ensure_within_root(self, candidate: Path) -> Path:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self._root):
            raise PathBoundaryError("resolved path escapes the configured data directory")
        return resolved
