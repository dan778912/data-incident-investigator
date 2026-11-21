"""JSONL trace writing and JSON Schema validation."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from .models import TraceEvent


class TraceValidationError(ValueError):
    """Raised when an event or a complete trace violates the trace contract."""


class TraceValidator:
    """Validate individual trace events against the versioned JSON Schema."""

    def __init__(self, schema_path: Path) -> None:
        if not schema_path.is_file():
            raise TraceValidationError(f"trace schema does not exist: {schema_path}")
        try:
            parsed: object = json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise TraceValidationError(f"trace schema is invalid JSON: {exc.msg}") from exc
        if not isinstance(parsed, Mapping):
            raise TraceValidationError("trace schema must be a JSON object")
        schema = cast(Mapping[str, object], parsed)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # jsonschema exposes several schema-error subclasses
            raise TraceValidationError(f"trace schema is invalid: {exc}") from exc
        self._validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def validate(self, event: Mapping[str, object]) -> None:
        """Validate one event and report every discovered schema violation."""

        errors = sorted(self._validator.iter_errors(event), key=lambda error: error.json_path)
        if not errors:
            return
        detail = "; ".join(f"{error.json_path}: {error.message}" for error in errors)
        raise TraceValidationError(detail)


class JsonlTraceWriter:
    """Append validated trace events as canonical JSONL."""

    def __init__(self, path: Path, validator: TraceValidator) -> None:
        self._path = path
        self._validator = validator

    @property
    def path(self) -> Path:
        """Return the destination trace path."""

        return self._path

    def write(self, event: TraceEvent) -> None:
        """Validate and append one event.

        Invalid events are never written. ``allow_nan=False`` keeps trace files
        compatible with strict JSON readers and the assignment evidence report.
        """

        normalized: dict[str, object] = dict(event)
        self._validator.validate(normalized)
        serialized = json.dumps(
            normalized,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.write("\n")


def load_trace(path: Path, validator: TraceValidator) -> tuple[dict[str, object], ...]:
    """Load a JSONL trace and validate each event plus stream ordering."""

    if not path.is_file():
        raise TraceValidationError(f"trace does not exist: {path}")
    events: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceValidationError(
                f"trace line {line_number} is not valid JSON: {exc.msg}"
            ) from exc
        if not isinstance(parsed, Mapping):
            raise TraceValidationError(f"trace line {line_number} must be a JSON object")
        event = dict(cast(Mapping[str, object], parsed))
        try:
            validator.validate(event)
        except TraceValidationError as exc:
            raise TraceValidationError(f"trace line {line_number}: {exc}") from exc
        events.append(event)
    if not events:
        raise TraceValidationError("trace contains no events")
    _validate_stream(events)
    return tuple(events)


def _validate_stream(events: Sequence[Mapping[str, object]]) -> None:
    run_ids = {event["run_id"] for event in events}
    fixture_ids = {event["fixture_id"] for event in events}
    if len(run_ids) != 1:
        raise TraceValidationError("one trace file cannot contain multiple run_id values")
    if len(fixture_ids) != 1:
        raise TraceValidationError("one trace file cannot contain multiple fixture_id values")
    sequences = [cast(int, event["sequence"]) for event in events]
    expected = list(range(sequences[0], sequences[0] + len(sequences)))
    if sequences != expected:
        raise TraceValidationError("trace sequence values must be contiguous and ordered")
