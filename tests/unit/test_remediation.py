from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pandas as pd
import pytest
from pydantic import ValidationError

from data_incident_investigator.domain.remediation import (
    ApprovalDecision,
    CastColumn,
    DropDuplicates,
    FillMissing,
    NormalizeString,
    ParseDatetime,
    RemediationPlan,
    RenameColumn,
    ReplaceValues,
)
from data_incident_investigator.remediation.executor import RemediationExecutor
from data_incident_investigator.security.policy import PolicyGateway, PolicyViolation


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _approval(plan: RemediationPlan, *, approved: bool = True) -> ApprovalDecision:
    assert plan.plan_hash is not None
    return ApprovalDecision(
        plan_id=plan.plan_id,
        plan_hash=plan.plan_hash,
        source_sha256=plan.source_sha256,
        approved=approved,
    )


def test_executor_applies_typed_plan_to_working_copy_only(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    source.write_text(
        "legacy_id,name,status,amount,note\n"
        "1, Alpha ,done,10,=2+2\n"
        "1,alpha,done,,safe\n"
        "2,BETA,complete,30,safe\n",
        encoding="utf-8",
    )
    original = source.read_bytes()
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[
            RenameColumn(from_name="legacy_id", to_name="id"),
            FillMissing(column="amount", strategy="median"),
            NormalizeString(columns=["name"], trim=True, casefold=True),
            ReplaceValues(column="status", mapping={"done": "complete"}),
            DropDuplicates(keys=["id"], keep="last"),
        ],
        expected_effects=["schema and values conform"],
        required_post_checks=["check_duplicate_keys"],
        citation_ids=["runbook#current-contract"],
        rationale="Apply the documented safe transformations.",
    )
    output = tmp_path / "working" / "fixed.csv"

    result = RemediationExecutor(PolicyGateway()).apply(
        plan=plan,
        approval=_approval(plan),
        trusted_source_path=source,
        trusted_output_path=output,
    )

    frame = pd.read_csv(output)
    assert source.read_bytes() == original
    assert result.original_sha256 == _sha256(source)
    assert result.rows_before == 3 and result.rows_after == 2
    assert next(iter(frame.columns)) == "id"
    assert frame["amount"].isna().sum() == 0
    assert set(frame["status"]) == {"complete"}


def test_executor_casts_and_parses_datetime(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text(
        '[{"count":"1","when":"2026-11-21 10:00:00"},{"count":"2","when":"2026-11-21T11:00:00Z"}]',
        encoding="utf-8",
    )
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[
            CastColumn(column="count", target_type="integer"),
            ParseDatetime(column="when", accepted_formats=["mixed"], timezone="UTC"),
        ],
        expected_effects=["types conform"],
        required_post_checks=["check_type_conformance"],
        citation_ids=["schema#types"],
        rationale="Normalize the documented numeric and timestamp fields.",
    )
    output = tmp_path / "fixed.json"

    result = RemediationExecutor(PolicyGateway()).apply(
        plan=plan,
        approval=_approval(plan),
        trusted_source_path=source,
        trusted_output_path=output,
    )

    assert result.rows_after == 2
    assert "2026-11-21T10:00:00" in output.read_text(encoding="utf-8")


def test_executor_fails_closed_without_approval_or_matching_source(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    source.write_text("old_name\n1\n", encoding="utf-8")
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[RenameColumn(from_name="old_name", to_name="new_name")],
        expected_effects=["column renamed"],
        required_post_checks=["inspect_schema"],
        citation_ids=["schema#rename"],
        rationale="The current schema requires the new name.",
    )
    executor = RemediationExecutor(PolicyGateway())

    with pytest.raises(PolicyViolation, match="rejected"):
        executor.apply(
            plan=plan,
            approval=_approval(plan, approved=False),
            trusted_source_path=source,
            trusted_output_path=tmp_path / "rejected.csv",
        )

    source.write_text("old_name\n2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        executor.apply(
            plan=plan,
            approval=_approval(plan),
            trusted_source_path=source,
            trusted_output_path=tmp_path / "stale.csv",
        )


def test_fill_missing_constant_requires_value() -> None:
    with pytest.raises(ValidationError, match="requires a value"):
        FillMissing(column="amount", strategy="constant")
