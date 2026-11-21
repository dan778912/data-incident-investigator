from __future__ import annotations

import hashlib
import shutil
import unicodedata
from pathlib import Path
from typing import Literal

import pandas as pd

from data_incident_investigator.domain.remediation import (
    ApprovalDecision,
    CastColumn,
    DropDuplicates,
    FillMissing,
    NormalizeString,
    ParseDatetime,
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
    ) -> None:
        self.output_path = output_path
        self.original_sha256 = original_sha256
        self.output_sha256 = output_sha256
        self.rows_before = rows_before
        self.rows_after = rows_after


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
        shutil.copy2(trusted_source_path, trusted_output_path)
        frame = self._read(trusted_output_path)
        rows_before = len(frame)
        for operation in plan.operations:
            frame = self._apply_operation(frame, operation)
        self._write(frame, trusted_output_path)

        source_hash_after = self._sha256(trusted_source_path)
        if source_hash_after != source_hash_before:
            raise RuntimeError("original artifact changed during remediation")
        return RemediationResult(
            output_path=trusted_output_path,
            original_sha256=source_hash_after,
            output_sha256=self._sha256(trusted_output_path),
            rows_before=rows_before,
            rows_after=len(frame),
        )

    def _read(self, path: Path) -> pd.DataFrame:
        if path.suffix.lower() == ".csv":
            return pd.read_csv(path, nrows=self._max_rows)
        if path.suffix.lower() == ".json":
            return pd.read_json(path).head(self._max_rows)
        raise ValueError("remediation supports only CSV and JSON datasets")

    @staticmethod
    def _write(frame: pd.DataFrame, path: Path) -> None:
        if path.suffix.lower() == ".csv":
            safe_frame = frame.copy()
            for column in safe_frame.select_dtypes(include=["object", "string"]).columns:
                safe_frame[column] = safe_frame[column].map(RemediationExecutor._escape_formula)
            safe_frame.to_csv(path, index=False)
        else:
            frame.to_json(path, orient="records", indent=2, date_format="iso")

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
                updated[operation.column] = pd.to_numeric(
                    updated[operation.column], errors=cast_errors
                )
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
            updated[operation.column] = pd.to_datetime(
                updated[operation.column], errors=datetime_errors, utc=True, format="mixed"
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
