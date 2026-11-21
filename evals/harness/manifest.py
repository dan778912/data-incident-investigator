"""Loading and validation for the frozen JSONL incident manifest."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import cast

from .models import ManifestCase

_INCIDENT_PATTERN = re.compile(r"^I[0-9]{2}$")
_VALID_STATUSES = frozenset({"planned", "ready"})
_VALID_APPROVAL_SCENARIOS = frozenset({"approve", "reject"})


class ManifestValidationError(ValueError):
    """Raised when the frozen evaluation manifest is malformed."""


def load_manifest(path: Path, *, validate_fixture_paths: bool = True) -> tuple[ManifestCase, ...]:
    """Load, normalize, and validate a JSONL manifest.

    Duplicate incident IDs/slugs and mixed corpus versions are rejected. Ready
    fixtures must point to an in-corpus directory containing the expected
    incident and ground-truth files.
    """

    if not path.is_file():
        raise ManifestValidationError(f"manifest does not exist: {path}")

    cases: list[ManifestCase] = []
    seen_ids: set[str] = set()
    seen_slugs: set[str] = set()
    corpus_versions: set[str] = set()

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ManifestValidationError(
                f"manifest line {line_number} is not valid JSON: {exc.msg}"
            ) from exc
        if not isinstance(parsed, Mapping):
            raise ManifestValidationError(f"manifest line {line_number} must be a JSON object")
        try:
            case = _case_from_mapping(cast(Mapping[str, object], parsed))
        except ValueError as exc:
            raise ManifestValidationError(f"manifest line {line_number}: {exc}") from exc

        if case.incident_id in seen_ids:
            raise ManifestValidationError(f"duplicate incident_id: {case.incident_id}")
        if case.slug in seen_slugs:
            raise ManifestValidationError(f"duplicate slug: {case.slug}")
        seen_ids.add(case.incident_id)
        seen_slugs.add(case.slug)
        corpus_versions.add(case.corpus_version)

        if validate_fixture_paths and case.fixture_status == "ready":
            _validate_ready_fixture(path.parent, case)
        cases.append(case)

    if not cases:
        raise ManifestValidationError("manifest contains no cases")
    if len(corpus_versions) != 1:
        versions = ", ".join(sorted(corpus_versions))
        raise ManifestValidationError(f"manifest mixes corpus versions: {versions}")
    return tuple(cases)


def index_cases(cases: tuple[ManifestCase, ...]) -> dict[str, ManifestCase]:
    """Index validated cases by incident ID and reject duplicates defensively."""

    indexed: dict[str, ManifestCase] = {}
    for case in cases:
        if case.incident_id in indexed:
            raise ManifestValidationError(f"duplicate incident_id: {case.incident_id}")
        indexed[case.incident_id] = case
    return indexed


def _case_from_mapping(data: Mapping[str, object]) -> ManifestCase:
    status = _required_string(data, "fixture_status")
    if status not in _VALID_STATUSES:
        raise ValueError(f"fixture_status must be one of {sorted(_VALID_STATUSES)}")

    incident_id = _required_string(data, "incident_id")
    if _INCIDENT_PATTERN.fullmatch(incident_id) is None:
        raise ValueError("incident_id must match I followed by two digits")

    root_cause_codes = _string_tuple(data, "root_cause_codes", required=True)
    approval_scenario = _required_string(data, "approval_scenario")
    if approval_scenario not in _VALID_APPROVAL_SCENARIOS:
        raise ValueError(f"approval_scenario must be one of {sorted(_VALID_APPROVAL_SCENARIOS)}")

    minimum_retrieval_rounds = _required_int(data, "minimum_retrieval_rounds")
    if minimum_retrieval_rounds < 1:
        raise ValueError("minimum_retrieval_rounds must be at least 1")

    fixture_path = _optional_string(data, "fixture_path")
    if fixture_path is not None:
        pure_path = PurePosixPath(fixture_path)
        if pure_path.is_absolute() or ".." in pure_path.parts:
            raise ValueError("fixture_path must stay within the evals directory")
    if status == "ready" and fixture_path is None:
        raise ValueError("ready fixtures require fixture_path")

    return ManifestCase(
        corpus_version=_required_string(data, "corpus_version"),
        incident_id=incident_id,
        slug=_required_string(data, "slug"),
        title=_required_string(data, "title"),
        fixture_status=status,
        root_cause_codes=root_cause_codes,
        must_replan=_required_bool(data, "must_replan"),
        minimum_retrieval_rounds=minimum_retrieval_rounds,
        approval_scenario=approval_scenario,
        tags=_string_tuple(data, "tags"),
        fixture_path=fixture_path,
        required_evidence_ids=_string_tuple(data, "required_evidence_ids"),
        required_source_ids=_string_tuple(data, "required_source_ids"),
        allowed_patch_operations=_string_tuple(data, "allowed_patch_operations"),
        forbidden_operations=_string_tuple(data, "forbidden_operations"),
        validation_assertion_ids=_string_tuple(data, "validation_assertion_ids"),
        initial_hypothesis_trap=_optional_string(data, "initial_hypothesis_trap"),
    )


def _validate_ready_fixture(root: Path, case: ManifestCase) -> None:
    if case.fixture_path is None:
        raise ManifestValidationError(f"ready fixture {case.incident_id} has no path")
    fixture_dir = root / Path(case.fixture_path)
    required_paths = (
        fixture_dir / "incident.yaml",
        fixture_dir / "expected" / "ground_truth.json",
        fixture_dir / "expected" / "assertions.json",
    )
    missing = [str(item) for item in required_paths if not item.is_file()]
    if missing:
        raise ManifestValidationError(
            f"ready fixture {case.incident_id} is incomplete: {', '.join(missing)}"
        )


def _required_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_string(data: Mapping[str, object], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string when provided")
    return value


def _required_bool(data: Mapping[str, object], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _required_int(data: Mapping[str, object], key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _string_tuple(
    data: Mapping[str, object],
    key: str,
    *,
    required: bool = False,
) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{key} must be a list of non-empty strings")
    result = tuple(cast(list[str], value))
    if required and not result:
        raise ValueError(f"{key} cannot be empty")
    if len(result) != len(set(result)):
        raise ValueError(f"{key} cannot contain duplicates")
    return result
