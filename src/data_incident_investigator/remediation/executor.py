from __future__ import annotations

import hashlib
import shutil
import unicodedata
from pathlib import Path
from typing import Any, Literal

import pandas as pd

from data_incident_investigator.domain.datetime_formats import (
    PANDAS_DATETIME_FORMATS,
    RFC3339_PATTERN,
    CanonicalDatetimeFormat,
)
from data_incident_investigator.domain.remediation import (
    ApprovalDecision,
    CastColumn,
    DropDuplicates,
    FillMissing,
    NormalizeString,
    ParseDatetime,
    PostconditionKind,
    PostFixCheck,
    RemediationOperation,
    RemediationPlan,
    RenameColumn,
    ReplaceValues,
)
from data_incident_investigator.security.policy import PolicyGateway


class RemediationResult:
    def __init__(
        self,
        *,
        output_path: Path,
        original_sha256: str,
        output_sha256: str,
        rows_before: int,
        rows_after: int,
        checks: list[PostFixCheck],
    ) -> None:
        self.output_path = output_path
        self.original_sha256 = original_sha256
        self.output_sha256 = output_sha256
        self.rows_before = rows_before
        self.rows_after = rows_after
        self.checks = checks


class PostFixValidationError(RuntimeError):
    """Raised when a deterministic remediation postcondition fails."""

    def __init__(self, checks: list[PostFixCheck]) -> None:
        self.checks = checks
        failed = [check.kind.value for check in checks if not check.passed]
        super().__init__(f"post-fix validation failed: {', '.join(failed)}")


class RemediationExecutor:
    """Applies a validated plan to a new working copy and never edits the original."""

    def __init__(self, policy: PolicyGateway, *, max_rows: int = 100_000) -> None:
        self._policy = policy
        self._max_rows = max_rows

    def apply(
        self,
        *,
        plan: RemediationPlan,
        approval: ApprovalDecision,
        trusted_source_path: Path,
        trusted_output_path: Path,
    ) -> RemediationResult:
        source_hash_before = self._sha256(trusted_source_path)
        if source_hash_before != plan.source_sha256:
            raise ValueError("source artifact hash no longer matches the remediation plan")
        self._policy.authorize_plan(plan, approval)

        trusted_output_path.parent.mkdir(parents=True, exist_ok=True)
        checks: list[PostFixCheck] = []
        try:
            shutil.copy2(trusted_source_path, trusted_output_path)
            frame = self._read(trusted_output_path)
            rows_before = len(frame)
            for operation in plan.operations:
                frame = self._apply_operation(frame, operation)

            # Validate every operation against the final frame. A later operation can
            # otherwise undo an earlier transformation while the earlier, transient
            # postcondition remains recorded as successful.
            checks.extend(
                self._validate_operation(frame, operation, index=index)
                for index, operation in enumerate(plan.operations)
            )
            if any(not check.passed for check in checks):
                raise PostFixValidationError(checks)
            expected_output_sha256 = hashlib.sha256(
                self._serialized_bytes(frame, trusted_output_path)
            ).hexdigest()
            self._write(frame, trusted_output_path)

            source_hash_after = self._sha256(trusted_source_path)
            source_check = PostFixCheck(
                kind=PostconditionKind.ORIGINAL_UNCHANGED,
                target=str(plan.source_artifact_id),
                passed=source_hash_after == source_hash_before,
                metrics={
                    "expected_sha256": source_hash_before,
                    "actual_sha256": source_hash_after,
                },
            )
            checks.append(source_check)
            if not source_check.passed:
                raise PostFixValidationError(checks)

            output_sha256 = self._sha256(trusted_output_path)
            hash_check = PostFixCheck(
                kind=PostconditionKind.OUTPUT_HASH_MATCHES,
                target=str(trusted_output_path.name),
                passed=output_sha256 == expected_output_sha256,
                metrics={
                    "scope": "serialized_transformation",
                    "expected_sha256": expected_output_sha256,
                    "actual_sha256": output_sha256,
                },
            )
            checks.append(hash_check)
            if not hash_check.passed:
                raise PostFixValidationError(checks)

            try:
                written = self._read(trusted_output_path)
                output_check = PostFixCheck(
                    kind=PostconditionKind.OUTPUT_READABLE,
                    target=str(trusted_output_path.name),
                    passed=(
                        len(written) == len(frame) and list(written.columns) == list(frame.columns)
                    ),
                    metrics={
                        "expected_rows": len(frame),
                        "actual_rows": len(written),
                        "expected_columns": len(frame.columns),
                        "actual_columns": len(written.columns),
                    },
                )
            except (OSError, TypeError, ValueError) as exc:
                output_check = PostFixCheck(
                    kind=PostconditionKind.OUTPUT_READABLE,
                    target=str(trusted_output_path.name),
                    passed=False,
                    metrics={"error_type": type(exc).__name__},
                )
            checks.append(output_check)
            if not output_check.passed:
                raise PostFixValidationError(checks)

            return RemediationResult(
                output_path=trusted_output_path,
                original_sha256=source_hash_after,
                output_sha256=output_sha256,
                rows_before=rows_before,
                rows_after=len(frame),
                checks=checks,
            )
        except Exception:
            trusted_output_path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _validate_operation(
        frame: pd.DataFrame,
        operation: RemediationOperation,
        *,
        index: int,
    ) -> PostFixCheck:
        if isinstance(operation, RenameColumn):
            from_present = operation.from_name in frame.columns
            to_present = operation.to_name in frame.columns
            return PostFixCheck(
                kind=PostconditionKind.COLUMN_RENAMED,
                operation_index=index,
                target=f"{operation.from_name}->{operation.to_name}",
                passed=not from_present and to_present,
                metrics={"from_present": from_present, "to_present": to_present},
            )
        if isinstance(operation, CastColumn):
            if operation.column not in frame.columns:
                return PostFixCheck(
                    kind=PostconditionKind.COLUMN_CAST,
                    operation_index=index,
                    target=operation.column,
                    passed=False,
                    metrics={"column_present": False, "target_type": operation.target_type},
                )
            dtype = frame[operation.column].dtype
            target_checks = {
                "integer": pd.api.types.is_integer_dtype(dtype),
                "float": pd.api.types.is_float_dtype(dtype),
                "boolean": pd.api.types.is_bool_dtype(dtype),
                "string": pd.api.types.is_string_dtype(dtype),
            }
            return PostFixCheck(
                kind=PostconditionKind.COLUMN_CAST,
                operation_index=index,
                target=operation.column,
                passed=target_checks[operation.target_type],
                metrics={
                    "target_type": operation.target_type,
                    "actual_dtype": str(dtype),
                },
            )
        if isinstance(operation, FillMissing):
            if operation.column not in frame.columns:
                return PostFixCheck(
                    kind=PostconditionKind.MISSING_VALUES_FILLED,
                    operation_index=index,
                    target=operation.column,
                    passed=False,
                    metrics={"column_present": False, "strategy": operation.strategy},
                )
            null_count = int(frame[operation.column].isna().sum())
            return PostFixCheck(
                kind=PostconditionKind.MISSING_VALUES_FILLED,
                operation_index=index,
                target=operation.column,
                passed=null_count == 0,
                metrics={"null_count": null_count, "strategy": operation.strategy},
            )
        if isinstance(operation, DropDuplicates):
            missing_columns = [column for column in operation.keys if column not in frame.columns]
            if missing_columns:
                return PostFixCheck(
                    kind=PostconditionKind.DUPLICATES_REMOVED,
                    operation_index=index,
                    target=",".join(operation.keys),
                    passed=False,
                    metrics={
                        "missing_columns": ",".join(missing_columns),
                        "keep": operation.keep,
                    },
                )
            duplicate_count = int(frame.duplicated(subset=operation.keys, keep=False).sum())
            return PostFixCheck(
                kind=PostconditionKind.DUPLICATES_REMOVED,
                operation_index=index,
                target=",".join(operation.keys),
                passed=duplicate_count == 0,
                metrics={"duplicate_count": duplicate_count, "keep": operation.keep},
            )
        if isinstance(operation, ParseDatetime):
            if operation.column not in frame.columns:
                return PostFixCheck(
                    kind=PostconditionKind.DATETIME_PARSED,
                    operation_index=index,
                    target=operation.column,
                    passed=False,
                    metrics={"column_present": False, "on_error": operation.on_error},
                )
            dtype = frame[operation.column].dtype
            return PostFixCheck(
                kind=PostconditionKind.DATETIME_PARSED,
                operation_index=index,
                target=operation.column,
                passed=pd.api.types.is_datetime64_any_dtype(dtype),
                metrics={"actual_dtype": str(dtype), "on_error": operation.on_error},
            )
        if isinstance(operation, NormalizeString):
            missing_columns = [
                column for column in operation.columns if column not in frame.columns
            ]
            if missing_columns:
                return PostFixCheck(
                    kind=PostconditionKind.STRINGS_NORMALIZED,
                    operation_index=index,
                    target=",".join(operation.columns),
                    passed=False,
                    metrics={
                        "missing_columns": ",".join(missing_columns),
                        "unicode_form": operation.unicode_form,
                    },
                )
            mismatch_count = 0
            for column in operation.columns:
                for value in frame[column].dropna().astype(str):
                    expected = unicodedata.normalize(operation.unicode_form, value)
                    if operation.trim:
                        expected = expected.strip()
                    if operation.casefold:
                        expected = expected.casefold()
                    if value != expected:
                        mismatch_count += 1
            return PostFixCheck(
                kind=PostconditionKind.STRINGS_NORMALIZED,
                operation_index=index,
                target=",".join(operation.columns),
                passed=mismatch_count == 0,
                metrics={
                    "mismatch_count": mismatch_count,
                    "unicode_form": operation.unicode_form,
                },
            )
        if isinstance(operation, ReplaceValues):
            if operation.column not in frame.columns:
                return PostFixCheck(
                    kind=PostconditionKind.VALUES_REPLACED,
                    operation_index=index,
                    target=operation.column,
                    passed=False,
                    metrics={"column_present": False},
                )
            remaining_keys = set(operation.mapping) - set(operation.mapping.values())
            remaining_count = int(frame[operation.column].isin(remaining_keys).sum())
            return PostFixCheck(
                kind=PostconditionKind.VALUES_REPLACED,
                operation_index=index,
                target=operation.column,
                passed=remaining_count == 0,
                metrics={"remaining_source_value_count": remaining_count},
            )
        raise TypeError(f"unsupported remediation operation: {type(operation).__name__}")

    def _read(self, path: Path) -> pd.DataFrame:
        if path.suffix.lower() == ".csv":
            return pd.read_csv(path, nrows=self._max_rows)
        if path.suffix.lower() == ".json":
            return pd.read_json(path).head(self._max_rows)
        raise ValueError("remediation supports only CSV and JSON datasets")

    @staticmethod
    def _write(frame: pd.DataFrame, path: Path) -> None:
        path.write_bytes(RemediationExecutor._serialized_bytes(frame, path))

    @staticmethod
    def _serialized_bytes(frame: pd.DataFrame, path: Path) -> bytes:
        if path.suffix.lower() == ".csv":
            safe_frame = frame.copy()
            for column in safe_frame.select_dtypes(include=["object", "string"]).columns:
                safe_frame[column] = safe_frame[column].map(RemediationExecutor._escape_formula)
            return safe_frame.to_csv(index=False).encode("utf-8")
        return frame.to_json(orient="records", indent=2, date_format="iso").encode("utf-8")

    def _apply_operation(
        self,
        frame: pd.DataFrame,
        operation: RemediationOperation,
    ) -> pd.DataFrame:
        updated = frame.copy()
        if isinstance(operation, RenameColumn):
            self._require_columns(updated, [operation.from_name])
            if operation.to_name in updated.columns:
                raise ValueError("rename target already exists")
            return updated.rename(columns={operation.from_name: operation.to_name})
        if isinstance(operation, CastColumn):
            self._require_columns(updated, [operation.column])
            cast_errors: Literal["raise", "coerce"] = (
                "raise" if operation.invalid_policy == "reject" else "coerce"
            )
            if operation.target_type == "integer":
                converted = pd.to_numeric(updated[operation.column], errors=cast_errors)
                updated[operation.column] = converted.astype("Int64")
            elif operation.target_type == "float":
                converted = pd.to_numeric(updated[operation.column], errors=cast_errors)
                updated[operation.column] = converted.astype("Float64")
            elif operation.target_type == "boolean":
                updated[operation.column] = updated[operation.column].astype("boolean")
            else:
                updated[operation.column] = updated[operation.column].astype("string")
            return updated
        if isinstance(operation, FillMissing):
            self._require_columns(updated, [operation.column])
            if operation.strategy == "constant":
                fill_value = operation.value
            elif operation.strategy == "median":
                fill_value = updated[operation.column].median()
            else:
                modes = updated[operation.column].mode(dropna=True)
                if modes.empty:
                    raise ValueError("cannot compute a mode for an entirely null column")
                fill_value = modes.iloc[0]
            updated[operation.column] = updated[operation.column].fillna(fill_value)
            return updated
        if isinstance(operation, DropDuplicates):
            self._require_columns(updated, operation.keys)
            return updated.drop_duplicates(subset=operation.keys, keep=operation.keep)
        if isinstance(operation, ParseDatetime):
            self._require_columns(updated, [operation.column])
            datetime_errors: Literal["raise", "coerce"] = (
                "raise" if operation.on_error == "reject" else "coerce"
            )
            updated[operation.column] = self._parse_datetime_formats(
                updated[operation.column],
                operation.accepted_formats,
                errors=datetime_errors,
            )
            return updated
        if isinstance(operation, NormalizeString):
            self._require_columns(updated, operation.columns)
            for column in operation.columns:
                values = updated[column].astype("string")
                values = values.map(
                    lambda value: (
                        unicodedata.normalize(operation.unicode_form, value)
                        if value is not pd.NA
                        else value
                    )
                )
                if operation.trim:
                    values = values.str.strip()
                if operation.casefold:
                    values = values.str.casefold()
                updated[column] = values
            return updated
        if isinstance(operation, ReplaceValues):
            self._require_columns(updated, [operation.column])
            updated[operation.column] = updated[operation.column].replace(operation.mapping)
            return updated
        raise TypeError(f"unsupported remediation operation: {type(operation).__name__}")

    @staticmethod
    def _parse_datetime_formats(
        series: pd.Series[Any],
        formats: list[CanonicalDatetimeFormat],
        *,
        errors: Literal["raise", "coerce"],
    ) -> pd.Series[Any]:
        parsed = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns, UTC]")
        for format_name in formats:
            source = series
            if format_name == "rfc3339":
                eligible = series.astype("string").str.fullmatch(RFC3339_PATTERN, na=False)
                source = series.where(eligible)
            candidate = pd.to_datetime(
                source,
                errors="coerce",
                utc=True,
                format=PANDAS_DATETIME_FORMATS[format_name],
            )
            newly_matched = parsed.isna() & candidate.notna()
            parsed.loc[newly_matched] = candidate.loc[newly_matched]

        failed = series.notna() & parsed.isna()
        if errors == "raise" and bool(failed.any()):
            raise ValueError(
                f"{int(failed.sum())} values do not match the declared datetime formats"
            )
        return parsed

    @staticmethod
    def _require_columns(frame: pd.DataFrame, columns: list[str]) -> None:
        missing = [column for column in columns if column not in frame.columns]
        if missing:
            raise KeyError(f"unknown columns: {missing}")

    @staticmethod
    def _escape_formula(value: object) -> object:
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
            return f"'{value}"
        return value

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
