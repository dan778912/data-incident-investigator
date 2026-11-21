from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from data_incident_investigator.diagnostics.engine import DiagnosticEngine
from data_incident_investigator.domain.diagnostics import DiagnosticRequest, DiagnosticTool
from data_incident_investigator.security.policy import PolicyGateway


@pytest.fixture
def artifact_id() -> UUID:
    return uuid4()


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    path = tmp_path / "incident.csv"
    path.write_text(
        "id,event_time,value,name\n"
        "1,2026-11-21T10:00:00Z,1, Alpha \n"
        "1,not-a-date,,alpha\n"
        "2,2026-11-21T11:00:00Z,3,beta\n",
        encoding="utf-8",
    )
    return path


def _request(
    tool: DiagnosticTool,
    artifact_id: UUID,
    arguments: dict[str, object],
) -> DiagnosticRequest:
    return DiagnosticRequest(
        tool=tool,
        artifact_id=artifact_id,
        arguments=arguments,
        rationale="Test the suspected data quality failure.",
    )


def test_profile_and_quality_diagnostics(dataset: Path, artifact_id: UUID) -> None:
    engine = DiagnosticEngine(PolicyGateway())

    profile = engine.run(_request(DiagnosticTool.PROFILE_DATASET, artifact_id, {}), dataset)
    nulls = engine.run(
        _request(
            DiagnosticTool.CHECK_NULL_RATIO,
            artifact_id,
            {"columns": ["value"], "threshold": 0.2},
        ),
        dataset,
    )
    duplicates = engine.run(
        _request(DiagnosticTool.CHECK_DUPLICATE_KEYS, artifact_id, {"keys": ["id"]}),
        dataset,
    )
    types = engine.run(
        _request(
            DiagnosticTool.CHECK_TYPE_CONFORMANCE,
            artifact_id,
            {"expected_types": {"value": "integer", "name": "string"}},
        ),
        dataset,
    )
    datetimes = engine.run(
        _request(
            DiagnosticTool.CHECK_DATETIME_PARSE,
            artifact_id,
            {"column": "event_time", "accepted_formats": []},
        ),
        dataset,
    )

    assert profile.success and profile.metrics["row_count"] == 3
    assert nulls.metrics["exceeding_threshold"]["value"] == pytest.approx(1 / 3)
    assert duplicates.metrics["duplicate_row_count"] == 2
    assert types.metrics["mismatches"]["value"]["actual"] == "float"
    assert datetimes.metrics["parse_failure_count"] == 1


def test_log_signature_diagnostic(tmp_path: Path, artifact_id: UUID) -> None:
    path = tmp_path / "pipeline.log"
    path.write_text("timeout contacting source\nERROR duplicate key\n", encoding="utf-8")
    engine = DiagnosticEngine(PolicyGateway())

    result = engine.run(
        _request(
            DiagnosticTool.INSPECT_LOG_SIGNATURES,
            artifact_id,
            {"signatures": ["timeout", "duplicate", "missing"]},
        ),
        path,
    )

    assert result.success is True
    assert result.metrics == {"timeout": 1, "duplicate": 1}


def test_diagnostic_failure_is_structured(dataset: Path, artifact_id: UUID) -> None:
    engine = DiagnosticEngine(PolicyGateway())
    result = engine.run(
        _request(
            DiagnosticTool.CHECK_DUPLICATE_KEYS,
            artifact_id,
            {"keys": ["missing_column"]},
        ),
        dataset,
    )
    assert result.success is False
    assert "failed safely" in result.summary


def test_dataset_tool_rejects_unsupported_trusted_artifact(
    tmp_path: Path,
    artifact_id: UUID,
) -> None:
    path = tmp_path / "input.txt"
    path.write_text("not a dataset", encoding="utf-8")
    engine = DiagnosticEngine(PolicyGateway())

    result = engine.run(_request(DiagnosticTool.PROFILE_DATASET, artifact_id, {}), path)

    assert result.success is False
    assert result.warnings == ["DiagnosticExecutionError"]
