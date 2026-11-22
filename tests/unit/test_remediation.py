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
    PostconditionKind,
    RemediationPlan,
    RenameColumn,
    ReplaceValues,
)
from data_incident_investigator.remediation.executor import (
    PostFixValidationError,
    RemediationExecutor,
)
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
    assert all(check.passed for check in result.checks)
    assert {check.kind for check in result.checks} >= {
        PostconditionKind.COLUMN_RENAMED,
        PostconditionKind.MISSING_VALUES_FILLED,
        PostconditionKind.STRINGS_NORMALIZED,
        PostconditionKind.VALUES_REPLACED,
        PostconditionKind.DUPLICATES_REMOVED,
        PostconditionKind.ORIGINAL_UNCHANGED,
        PostconditionKind.OUTPUT_HASH_MATCHES,
        PostconditionKind.OUTPUT_READABLE,
    }


def test_executor_casts_and_parses_datetime(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text(
        '[{"count":"1","when":"2026-11-21T10:00:00Z"},'
        '{"count":"2","when":"11/21/2026 11:00 AM UTC"}]',
        encoding="utf-8",
    )
    parse_datetime = ParseDatetime(
        column="when",
        accepted_formats=["MM/DD/YYYY hh:mm AM UTC", "rfc3339"],
        timezone="UTC",
    )
    assert parse_datetime.accepted_formats == ["rfc3339", "MM/DD/YYYY hh:mm AM UTC"]
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[
            CastColumn(column="count", target_type="integer"),
            parse_datetime,
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
    output_text = output.read_text(encoding="utf-8")
    assert "2026-11-21T10:00:00" in output_text
    assert "2026-11-21T11:00:00" in output_text


def test_datetime_operation_rejects_arbitrary_or_duplicate_format_tokens() -> None:
    with pytest.raises(ValidationError):
        ParseDatetime(column="when", accepted_formats=["%Y-%m-%dT%H:%M:%SZ"])
    with pytest.raises(ValidationError, match="unique"):
        ParseDatetime(column="when", accepted_formats=["rfc3339", "rfc3339"])
    with pytest.raises(ValidationError):
        ParseDatetime(column="when", accepted_formats=["rfc3339"], timezone="US/Pacific")


def test_string_normalization_uses_the_canonical_compatibility_form() -> None:
    assert NormalizeString(columns=["sku"]).unicode_form == "NFKC"
    with pytest.raises(ValidationError):
        NormalizeString(columns=["sku"], unicode_form="NFC")


def test_datetime_operation_rejects_value_outside_declared_formats(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text('[{"when":"2026-11-21 10:00:00"}]', encoding="utf-8")
    original = source.read_bytes()
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[ParseDatetime(column="when", accepted_formats=["rfc3339"])],
        expected_effects=["timestamps use the declared contract"],
        required_post_checks=["check_datetime_parse"],
        citation_ids=["runbook#datetime-contract"],
        rationale="Reject timestamps outside the declared format.",
    )
    output = tmp_path / "rejected.json"

    with pytest.raises(ValueError, match="declared datetime formats"):
        RemediationExecutor(PolicyGateway()).apply(
            plan=plan,
            approval=_approval(plan),
            trusted_source_path=source,
            trusted_output_path=output,
        )

    assert source.read_bytes() == original
    assert not output.exists()


def test_datetime_operation_coerces_value_outside_declared_formats(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text('[{"when":"2026-11-21 10:00:00"}]', encoding="utf-8")
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[
            ParseDatetime(
                column="when",
                accepted_formats=["rfc3339"],
                on_error="coerce_null",
            )
        ],
        expected_effects=["out-of-contract timestamps become null on the working copy"],
        required_post_checks=["check_datetime_parse"],
        citation_ids=["runbook#datetime-contract"],
        rationale="Coerce only values outside the declared format.",
    )
    output = tmp_path / "coerced.json"

    result = RemediationExecutor(PolicyGateway()).apply(
        plan=plan,
        approval=_approval(plan),
        trusted_source_path=source,
        trusted_output_path=output,
    )

    assert result.rows_after == 1
    assert '"when":null' in output.read_text(encoding="utf-8").replace(" ", "")
    assert all(check.passed for check in result.checks)


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


def test_executor_fails_closed_when_operation_postcondition_does_not_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.csv"
    source.write_text("legacy_id\n1\n", encoding="utf-8")
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[RenameColumn(from_name="legacy_id", to_name="id")],
        expected_effects=["column renamed"],
        required_post_checks=["inspect_schema"],
        citation_ids=["schema#rename"],
        rationale="The current schema requires the new name.",
    )
    output = tmp_path / "working.csv"
    executor = RemediationExecutor(PolicyGateway())
    monkeypatch.setattr(executor, "_apply_operation", lambda frame, _operation: frame.copy())

    with pytest.raises(PostFixValidationError) as exc_info:
        executor.apply(
            plan=plan,
            approval=_approval(plan),
            trusted_source_path=source,
            trusted_output_path=output,
        )

    assert exc_info.value.checks[-1].kind == PostconditionKind.COLUMN_RENAMED
    assert exc_info.value.checks[-1].passed is False
    assert not output.exists()
    assert source.read_text(encoding="utf-8") == "legacy_id\n1\n"


def test_executor_revalidates_each_operation_against_final_frame(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    source.write_text("a,value\n1,safe\n", encoding="utf-8")
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[
            RenameColumn(from_name="a", to_name="b"),
            RenameColumn(from_name="b", to_name="a"),
        ],
        expected_effects=["column renamed"],
        required_post_checks=["inspect_schema"],
        citation_ids=["schema#rename"],
        rationale="Exercise final-state validation for dependent operations.",
    )
    output = tmp_path / "working.csv"

    with pytest.raises(PostFixValidationError) as exc_info:
        RemediationExecutor(PolicyGateway()).apply(
            plan=plan,
            approval=_approval(plan),
            trusted_source_path=source,
            trusted_output_path=output,
        )

    first_check, second_check = exc_info.value.checks
    assert first_check.operation_index == 0
    assert first_check.kind == PostconditionKind.COLUMN_RENAMED
    assert first_check.passed is False
    assert second_check.operation_index == 1
    assert second_check.passed is True
    assert not output.exists()
    assert source.read_text(encoding="utf-8") == "a,value\n1,safe\n"


def test_executor_fails_closed_when_written_bytes_do_not_match_transformation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.csv"
    source.write_text("id,amount\n1,\n2,20\n", encoding="utf-8")
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[FillMissing(column="amount", strategy="constant", value=0)],
        expected_effects=["missing amounts filled"],
        required_post_checks=["check_missing_values"],
        citation_ids=["schema#amount"],
        rationale="The contract assigns zero to missing amounts.",
    )
    output = tmp_path / "working.csv"
    executor = RemediationExecutor(PolicyGateway())
    monkeypatch.setattr(executor, "_write", lambda _frame, _path: None)

    with pytest.raises(PostFixValidationError) as exc_info:
        executor.apply(
            plan=plan,
            approval=_approval(plan),
            trusted_source_path=source,
            trusted_output_path=output,
        )

    assert exc_info.value.checks[-1].kind == PostconditionKind.OUTPUT_HASH_MATCHES
    assert exc_info.value.checks[-1].passed is False
    assert not output.exists()


def test_executor_fails_closed_if_original_changes_during_remediation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.csv"
    source.write_text("legacy_id\n1\n", encoding="utf-8")
    plan = RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256=_sha256(source),
        operations=[RenameColumn(from_name="legacy_id", to_name="id")],
        expected_effects=["column renamed"],
        required_post_checks=["inspect_schema"],
        citation_ids=["schema#rename"],
        rationale="The current schema requires the new name.",
    )
    output = tmp_path / "working.csv"
    executor = RemediationExecutor(PolicyGateway())
    write = executor._write

    def write_then_mutate_original(frame: pd.DataFrame, path: Path) -> None:
        write(frame, path)
        source.write_text("legacy_id\n2\n", encoding="utf-8")

    monkeypatch.setattr(executor, "_write", write_then_mutate_original)

    with pytest.raises(PostFixValidationError) as exc_info:
        executor.apply(
            plan=plan,
            approval=_approval(plan),
            trusted_source_path=source,
            trusted_output_path=output,
        )

    assert exc_info.value.checks[-1].kind == PostconditionKind.ORIGINAL_UNCHANGED
    assert exc_info.value.checks[-1].passed is False
    assert not output.exists()
