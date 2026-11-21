from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from data_incident_investigator.domain.artifacts import ArtifactKind
from data_incident_investigator.domain.diagnostics import DiagnosticRequest, DiagnosticTool
from data_incident_investigator.domain.remediation import (
    ApprovalDecision,
    RemediationPlan,
    RenameColumn,
)
from data_incident_investigator.security.artifacts import (
    ArtifactStore,
    ArtifactValidationError,
)
from data_incident_investigator.security.paths import (
    CasePathResolver,
    PathBoundaryError,
    sanitize_filename,
)
from data_incident_investigator.security.policy import PolicyGateway, PolicyViolation
from data_incident_investigator.security.redaction import redact_secrets


def _plan() -> RemediationPlan:
    return RemediationPlan(
        source_artifact_id=uuid4(),
        source_sha256="a" * 64,
        operations=[RenameColumn(from_name="old_name", to_name="new_name")],
        expected_effects=["schema matches the current contract"],
        required_post_checks=["check_type_conformance"],
        citation_ids=["runbook-v2#rename"],
        rationale="The current schema contract documents the rename.",
    )


def test_sanitize_filename_discards_directories_and_unsafe_characters() -> None:
    assert sanitize_filename("../../bad<>name.csv") == "bad_name.csv"
    with pytest.raises(PathBoundaryError):
        sanitize_filename("..")


def test_case_path_resolver_confines_paths(tmp_path: Path) -> None:
    resolver = CasePathResolver(tmp_path)
    case_id = uuid4()
    artifact_id = uuid4()

    path = resolver.artifact_path(case_id, artifact_id, "sample.csv")

    assert path.is_relative_to(tmp_path.resolve())
    assert path.name == f"{artifact_id}.csv"
    with pytest.raises(PathBoundaryError):
        resolver.working_path(case_id, uuid4(), ".exe")


def test_artifact_store_writes_validated_immutable_original(tmp_path: Path) -> None:
    store = ArtifactStore(CasePathResolver(tmp_path), max_upload_bytes=1000)
    content = b"id,value\n1,alpha\n"

    artifact = store.save(
        case_id=uuid4(),
        filename="../../input.csv",
        content=content,
        kind=ArtifactKind.DATASET,
    )

    assert artifact.immutable is True
    assert artifact.original_filename == "input.csv"
    assert artifact.storage_path.read_bytes() == content
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert artifact.media_type == "text/csv"


@pytest.mark.parametrize(
    ("filename", "content", "kind"),
    [
        ("empty.csv", b"", ArtifactKind.DATASET),
        ("wrong.exe", b"abc", ArtifactKind.DATASET),
        ("bad.json", b"{nope", ArtifactKind.DATASET),
        ("binary.log", b"hello\x00world", ArtifactKind.LOG),
        ("report.csv", b"a\n1", ArtifactKind.REPORT),
    ],
)
def test_artifact_store_rejects_invalid_uploads(
    tmp_path: Path,
    filename: str,
    content: bytes,
    kind: ArtifactKind,
) -> None:
    store = ArtifactStore(CasePathResolver(tmp_path), max_upload_bytes=1000)
    with pytest.raises(ArtifactValidationError):
        store.save(case_id=uuid4(), filename=filename, content=content, kind=kind)


def test_artifact_store_rejects_oversized_and_non_utf8_content(tmp_path: Path) -> None:
    store = ArtifactStore(CasePathResolver(tmp_path), max_upload_bytes=4)
    with pytest.raises(ArtifactValidationError, match="upload limit"):
        store.save(
            case_id=uuid4(),
            filename="large.txt",
            content=b"12345",
            kind=ArtifactKind.LOG,
        )

    store = ArtifactStore(CasePathResolver(tmp_path), max_upload_bytes=100)
    with pytest.raises(ArtifactValidationError, match="UTF-8"):
        store.save(
            case_id=uuid4(),
            filename="bad.txt",
            content=b"\xff\xfe\xfd",
            kind=ArtifactKind.LOG,
        )


def test_redaction_removes_multiple_secret_shapes() -> None:
    text = (
        "key=sk-abcdefghijklmnopqrstuvwxyz123456 "
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz "
        "password=hunter2secret"
    )

    redacted, events = redact_secrets(text)

    assert "sk-" not in redacted
    assert "hunter2secret" not in redacted
    assert "Bearer abc" not in redacted
    assert {event.category for event in events} == {
        "openai_key",
        "bearer_token",
        "assigned_secret",
    }


def test_policy_validates_allowlisted_tool_arguments() -> None:
    gateway = PolicyGateway()
    request = DiagnosticRequest(
        tool=DiagnosticTool.CHECK_DUPLICATE_KEYS,
        artifact_id=uuid4(),
        arguments={"keys": ["customer_id"]},
        rationale="Replay events may have duplicated primary keys.",
    )
    parsed = gateway.validate_diagnostic_request(request)
    assert parsed.model_dump() == {"keys": ["customer_id"]}

    bad_request = request.model_copy(update={"arguments": {"keys": ["*"]}})
    with pytest.raises(PolicyViolation, match="invalid arguments"):
        gateway.validate_diagnostic_request(bad_request)

    unexpected_request = request.model_copy(
        update={"arguments": {"keys": ["customer_id"], "shell": "whoami"}}
    )
    with pytest.raises(PolicyViolation, match="extra_forbidden"):
        gateway.validate_diagnostic_request(unexpected_request)

    unbounded_profile = request.model_copy(
        update={
            "tool": DiagnosticTool.PROFILE_DATASET,
            "arguments": {"value_counts": True},
        }
    )
    with pytest.raises(PolicyViolation, match="requires one explicit column"):
        gateway.validate_diagnostic_request(unbounded_profile)


def test_approval_is_bound_to_plan_hash_source_hash_and_nonce() -> None:
    gateway = PolicyGateway()
    plan = _plan()
    assert plan.plan_hash is not None
    approval = ApprovalDecision(
        plan_id=plan.plan_id,
        plan_hash=plan.plan_hash,
        source_sha256=plan.source_sha256,
        approved=True,
    )

    gateway.authorize_plan(plan, approval)

    with pytest.raises(PolicyViolation, match="already been consumed"):
        gateway.authorize_plan(plan, approval)


def test_policy_rejects_rejected_or_stale_approval() -> None:
    plan = _plan()
    assert plan.plan_hash is not None
    rejected = ApprovalDecision(
        plan_id=plan.plan_id,
        plan_hash=plan.plan_hash,
        source_sha256=plan.source_sha256,
        approved=False,
    )
    with pytest.raises(PolicyViolation, match="rejected"):
        PolicyGateway().authorize_plan(plan, rejected)

    stale = rejected.model_copy(update={"approved": True, "plan_hash": "b" * 64})
    with pytest.raises(PolicyViolation, match="plan changed"):
        PolicyGateway().authorize_plan(plan, stale)


def test_remediation_models_reject_unsafe_columns_and_bad_hashes() -> None:
    with pytest.raises(ValidationError):
        RenameColumn(from_name="*", to_name="safe")

    plan = _plan()
    payload = plan.model_dump(mode="json")
    payload["plan_hash"] = "f" * 64
    with pytest.raises(ValidationError, match="plan hash"):
        RemediationPlan.model_validate(payload)
