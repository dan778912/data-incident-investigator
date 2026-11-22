from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
from pydantic import BaseModel

from data_incident_investigator.domain.datetime_formats import (
    PANDAS_DATETIME_FORMATS,
    RFC3339_PATTERN,
    CanonicalDatetimeFormat,
)
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
from data_incident_investigator.security.redaction import redact_secrets

_MAX_LOG_MATCHING_LINES = 10
_MAX_LOG_LINE_LENGTH = 500


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
                frame = self._load_frame(trusted_artifact_path, arguments)
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

    def _load_frame(self, path: Path, arguments: BaseModel) -> pd.DataFrame:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            keep_default_na = True
            na_values: list[str] | None = None
            if isinstance(arguments, ProfileDatasetArgs):
                keep_default_na = arguments.keep_default_na
            elif isinstance(arguments, CheckNullRatioArgs):
                keep_default_na = arguments.keep_default_na
                na_values = arguments.na_values or None
            return pd.read_csv(
                path,
                nrows=self._max_rows,
                keep_default_na=keep_default_na,
                na_values=na_values,
            )
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
            if arguments.column is not None:
                self._require_columns(frame, [arguments.column])
            sample = frame.head(arguments.sample_rows).astype(object)
            sample = sample.where(sample.notna(), "<NULL>")
            metrics = {
                "row_count": len(frame),
                "column_count": len(frame.columns),
                "columns": [str(column) for column in frame.columns],
                "dtypes": {str(column): str(dtype) for column, dtype in frame.dtypes.items()},
                "sample": sample.to_dict("records"),
            }
            if arguments.value_counts and arguments.column is not None:
                series = frame[arguments.column]
                rendered = series.astype("string").fillna("<NULL>")
                rendered = rendered.mask(rendered == "", "<EMPTY>")
                counts = rendered.value_counts(dropna=False).head(arguments.value_count_limit)
                rendered_counts: dict[str, int] = {}
                for value, count in counts.items():
                    rendered_counts[str(value)[:200]] = int(count)
                metrics["value_counts"] = {arguments.column: rendered_counts}
                metrics["distinct_value_count"] = int(series.nunique(dropna=False))
            return metrics, f"Profiled {len(frame)} rows and {len(frame.columns)} columns.", []

        if tool == DiagnosticTool.CHECK_NULL_RATIO:
            assert isinstance(arguments, CheckNullRatioArgs)
            columns = (
                [arguments.column]
                if arguments.column is not None
                else arguments.columns or [str(column) for column in frame.columns]
            )
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
            non_null = series.notna()
            parsed_by_format: dict[str, pd.Series[Any]]
            if arguments.accepted_formats:
                parsed_by_format = {
                    format_name: self._parse_datetime_format(series, format_name)
                    for format_name in arguments.accepted_formats
                }
            else:
                parsed_by_format = {
                    "mixed": pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
                }
            successes = pd.Series(False, index=series.index, dtype=bool)
            format_results: dict[str, dict[str, int]] = {}
            for format_name, parsed in parsed_by_format.items():
                matched = non_null & parsed.notna()
                successes |= matched
                format_results[format_name] = {
                    "parse_success_count": int(matched.sum()),
                    "parse_failure_count": int((non_null & parsed.isna()).sum()),
                }
            non_null_count = int(non_null.sum())
            failures = int((non_null & ~successes).sum())
            return (
                {
                    "column": arguments.column,
                    "accepted_formats": arguments.accepted_formats,
                    "format_results": format_results,
                    "parse_failure_count": failures,
                    "parse_success_rate": float(1 - failures / max(non_null_count, 1)),
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
        folded_signatures = tuple(signature.casefold() for signature in signatures)
        matching_lines: list[dict[str, int | str]] = []
        seen_lines: set[str] = set()
        truncated = False
        redacted_any = False
        for line_number, line in enumerate(text.splitlines(), start=1):
            folded_line = line.casefold()
            if not any(signature in folded_line for signature in folded_signatures):
                continue
            clean_line, redactions = redact_secrets(line)
            redacted_any = redacted_any or bool(redactions)
            bounded_line = clean_line[:_MAX_LOG_LINE_LENGTH]
            if bounded_line in seen_lines:
                continue
            seen_lines.add(bounded_line)
            if len(matching_lines) >= _MAX_LOG_MATCHING_LINES:
                truncated = True
                break
            matching_lines.append({"line_number": line_number, "text": bounded_line})
        metrics: dict[str, Any] = {
            "signature_counts": matched,
            "matching_lines": matching_lines,
            "matching_lines_truncated": truncated,
        }
        warnings: list[str] = []
        if truncated:
            warnings.append("Matching log context was truncated to the safe line limit.")
        if redacted_any:
            warnings.append("Credential-like text was redacted from matching log context.")
        return (
            metrics,
            f"Matched {len(matched)} configured signatures across "
            f"{len(matching_lines)} bounded log lines.",
            warnings,
        )

    @staticmethod
    def _require_columns(frame: pd.DataFrame, columns: list[str]) -> None:
        missing = [column for column in columns if column not in frame.columns]
        if missing:
            raise KeyError(f"unknown columns: {missing}")

    @staticmethod
    def _parse_datetime_format(
        series: pd.Series[Any],
        format_name: CanonicalDatetimeFormat,
    ) -> pd.Series[Any]:
        source = series
        if format_name == "rfc3339":
            eligible = series.astype("string").str.fullmatch(RFC3339_PATTERN, na=False)
            source = series.where(eligible)
        return pd.to_datetime(
            source,
            errors="coerce",
            utc=True,
            format=PANDAS_DATETIME_FORMATS[format_name],
        )

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
