from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
from pydantic import BaseModel

from data_incident_investigator.domain.diagnostics import (
    CheckDatetimeParseArgs,
    CheckDuplicateKeysArgs,
    CheckNullRatioArgs,
    CheckTypeConformanceArgs,
    DiagnosticObservation,
    DiagnosticRequest,
    DiagnosticTool,
    InspectLogSignaturesArgs,
    ProfileDatasetArgs,
)
from data_incident_investigator.security.policy import PolicyGateway


class DiagnosticExecutionError(RuntimeError):
    """Raised when a validated diagnostic cannot be executed."""


class DiagnosticEngine:
    def __init__(self, policy: PolicyGateway, *, max_rows: int = 100_000) -> None:
        self._policy = policy
        self._max_rows = max_rows

    def run(self, request: DiagnosticRequest, trusted_artifact_path: Path) -> DiagnosticObservation:
        arguments = self._policy.validate_diagnostic_request(request)
        try:
            if request.tool == DiagnosticTool.INSPECT_LOG_SIGNATURES:
                metrics, summary, warnings = self._inspect_log(trusted_artifact_path, arguments)
            else:
                frame = self._load_frame(trusted_artifact_path)
                metrics, summary, warnings = self._run_frame_tool(request.tool, frame, arguments)
        except (DiagnosticExecutionError, OSError, ValueError, KeyError, TypeError) as exc:
            return DiagnosticObservation(
                tool=request.tool,
                artifact_id=request.artifact_id,
                success=False,
                summary=f"Diagnostic failed safely: {exc}",
                warnings=[type(exc).__name__],
            )
        return DiagnosticObservation(
            tool=request.tool,
            artifact_id=request.artifact_id,
            success=True,
            summary=summary,
            metrics=metrics,
            warnings=warnings,
        )

    def _load_frame(self, path: Path) -> pd.DataFrame:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            return pd.read_csv(path, nrows=self._max_rows)
        if suffix == ".json":
            frame = pd.read_json(path)
            return frame.head(self._max_rows)
        raise DiagnosticExecutionError("dataset diagnostics support only CSV and JSON")

    def _run_frame_tool(
        self,
        tool: DiagnosticTool,
        frame: pd.DataFrame,
        arguments: BaseModel,
    ) -> tuple[dict[str, Any], str, list[str]]:
        if tool == DiagnosticTool.PROFILE_DATASET:
            assert isinstance(arguments, ProfileDatasetArgs)
            sample = frame.head(arguments.sample_rows).astype(object)
            sample = sample.where(sample.notna(), "<NULL>")
            metrics = {
                "row_count": len(frame),
                "column_count": len(frame.columns),
                "columns": [str(column) for column in frame.columns],
                "dtypes": {str(column): str(dtype) for column, dtype in frame.dtypes.items()},
                "sample": sample.to_dict("records"),
            }
            return metrics, f"Profiled {len(frame)} rows and {len(frame.columns)} columns.", []

        if tool == DiagnosticTool.CHECK_NULL_RATIO:
            assert isinstance(arguments, CheckNullRatioArgs)
            columns = arguments.columns or [str(column) for column in frame.columns]
            self._require_columns(frame, columns)
            ratios = {column: float(frame[column].isna().mean()) for column in columns}
            exceeding = {
                column: ratio for column, ratio in ratios.items() if ratio > arguments.threshold
            }
            return (
                {"null_ratios": ratios, "exceeding_threshold": exceeding},
                f"Found {len(exceeding)} columns above the null-ratio threshold.",
                [],
            )

        if tool == DiagnosticTool.CHECK_DUPLICATE_KEYS:
            assert isinstance(arguments, CheckDuplicateKeysArgs)
            self._require_columns(frame, arguments.keys)
            duplicates = frame.duplicated(subset=arguments.keys, keep=False)
            count = int(duplicates.sum())
            return (
                {"duplicate_row_count": count, "keys": arguments.keys},
                f"Detected {count} rows participating in duplicate keys.",
                [],
            )

        if tool == DiagnosticTool.CHECK_TYPE_CONFORMANCE:
            assert isinstance(arguments, CheckTypeConformanceArgs)
            self._require_columns(frame, list(arguments.expected_types))
            actual = {
                column: self._normalized_dtype(frame[column]) for column in arguments.expected_types
            }
            mismatches = {
                column: {"expected": expected, "actual": actual[column]}
                for column, expected in arguments.expected_types.items()
                if actual[column] != expected
            }
            return (
                {"actual_types": actual, "mismatches": mismatches},
                f"Found {len(mismatches)} type-conformance mismatches.",
                [],
            )

        if tool == DiagnosticTool.CHECK_DATETIME_PARSE:
            assert isinstance(arguments, CheckDatetimeParseArgs)
            self._require_columns(frame, [arguments.column])
            series = frame[arguments.column]
            parsed = pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
            failures = int((series.notna() & parsed.isna()).sum())
            return (
                {
                    "column": arguments.column,
                    "parse_failure_count": failures,
                    "parse_success_rate": float(1 - failures / max(int(series.notna().sum()), 1)),
                },
                f"Found {failures} non-null values that could not be parsed as datetimes.",
                [],
            )

        raise DiagnosticExecutionError(f"tool is not implemented: {tool}")

    def _inspect_log(
        self,
        path: Path,
        arguments: BaseModel,
    ) -> tuple[dict[str, Any], str, list[str]]:
        assert isinstance(arguments, InspectLogSignaturesArgs)
        text = path.read_text(encoding="utf-8", errors="replace")[:1_000_000]
        signatures = arguments.signatures or [
            "error",
            "exception",
            "timeout",
            "schema",
            "duplicate",
            "parse",
        ]
        lowered = text.casefold()
        counts = {signature: lowered.count(signature.casefold()) for signature in signatures}
        matched = {signature: count for signature, count in counts.items() if count}
        return matched, f"Matched {len(matched)} configured log signatures.", []

    @staticmethod
    def _require_columns(frame: pd.DataFrame, columns: list[str]) -> None:
        missing = [column for column in columns if column not in frame.columns]
        if missing:
            raise KeyError(f"unknown columns: {missing}")

    @staticmethod
    def _normalized_dtype(series: pd.Series[Any]) -> str:
        dtype = series.dtype
        if pd.api.types.is_integer_dtype(dtype):
            return "integer"
        if pd.api.types.is_float_dtype(dtype):
            return "float"
        if pd.api.types.is_bool_dtype(dtype):
            return "boolean"
        if pd.api.types.is_datetime64_any_dtype(dtype):
            return "datetime"
        return "string"
