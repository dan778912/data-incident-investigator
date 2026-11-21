"""Small CLI for grading normalized JSONL run observations."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from .graders import grade_suite
from .manifest import load_manifest
from .models import RunObservation


class ObservationValidationError(ValueError):
    """Raised when a normalized observation JSONL file is malformed."""


def load_observations(path: Path) -> tuple[RunObservation, ...]:
    """Load provider-neutral run observations from JSONL."""

    if not path.is_file():
        raise ObservationValidationError(f"observation file does not exist: {path}")
    observations: list[RunObservation] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ObservationValidationError(
                f"observation line {line_number} is invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(parsed, Mapping):
            raise ObservationValidationError(
                f"observation line {line_number} must be a JSON object"
            )
        try:
            observations.append(RunObservation.from_mapping(cast(Mapping[str, object], parsed)))
        except ValueError as exc:
            raise ObservationValidationError(f"observation line {line_number}: {exc}") from exc
    if not observations:
        raise ObservationValidationError("observation file contains no runs")
    return tuple(observations)


def main(argv: Sequence[str] | None = None) -> int:
    """Grade an observation file and emit JSON or Markdown."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    cases = load_manifest(args.manifest)
    observations = load_observations(args.observations)
    summary = grade_suite(cases, observations)
    rendered = summary.to_json() if args.format == "json" else summary.to_markdown()

    if args.output is None:
        print(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    return 0
