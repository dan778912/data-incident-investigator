from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from data_incident_investigator.diagnostics.engine import DiagnosticEngine
from data_incident_investigator.domain.diagnostics import DiagnosticRequest, DiagnosticTool
from data_incident_investigator.security.policy import PolicyGateway, PolicyViolation


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
    assert datetimes.metrics["format_results"]["mixed"] == {
        "parse_success_count": 2,
        "parse_failure_count": 1,
    }


def test_datetime_diagnostic_honors_declared_canonical_formats(
    tmp_path: Path,
    artifact_id: UUID,
) -> None:
    dataset = tmp_path / "timestamps.csv"
    dataset.write_text(
        "id,created_at\n"
        "1,2026-11-21T10:00:00Z\n"
        "2,2026-11-20T23:50:00-08:00\n"
        "3,11/21/2026 10:05 AM UTC\n"
        "4,2026-11-21\n",
        encoding="utf-8",
    )
    engine = DiagnosticEngine(PolicyGateway())

    rfc3339 = engine.run(
        _request(
            DiagnosticTool.CHECK_DATETIME_PARSE,
            artifact_id,
            {"column": "created_at", "accepted_formats": ["rfc3339"]},
        ),
        dataset,
    )
    both = engine.run(
        _request(
            DiagnosticTool.CHECK_DATETIME_PARSE,
            artifact_id,
            {
                "column": "created_at",
                "accepted_formats": [
                    "MM/DD/YYYY hh:mm AM UTC",
                    "rfc3339",
                ],
            },
        ),
        dataset,
    )

    assert rfc3339.success is True
    assert rfc3339.metrics["accepted_formats"] == ["rfc3339"]
    assert rfc3339.metrics["parse_failure_count"] == 2
    assert rfc3339.metrics["format_results"]["rfc3339"] == {
        "parse_success_count": 2,
        "parse_failure_count": 2,
    }
    assert both.metrics["accepted_formats"] == [
        "rfc3339",
        "MM/DD/YYYY hh:mm AM UTC",
    ]
    assert both.metrics["parse_failure_count"] == 1
    assert both.metrics["parse_success_rate"] == pytest.approx(0.75)


def test_datetime_diagnostic_rejects_unknown_or_duplicate_formats(
    dataset: Path,
    artifact_id: UUID,
) -> None:
    engine = DiagnosticEngine(PolicyGateway())

    with pytest.raises(PolicyViolation, match="accepted_formats"):
        engine.run(
            _request(
                DiagnosticTool.CHECK_DATETIME_PARSE,
                artifact_id,
                {"column": "event_time", "accepted_formats": ["%Y-%m-%d"]},
            ),
            dataset,
        )
    with pytest.raises(PolicyViolation, match="unique"):
        engine.run(
            _request(
                DiagnosticTool.CHECK_DATETIME_PARSE,
                artifact_id,
                {"column": "event_time", "accepted_formats": ["rfc3339", "rfc3339"]},
            ),
            dataset,
        )


def test_raw_value_profile_and_explicit_null_markers(
    tmp_path: Path,
    artifact_id: UUID,
) -> None:
    dataset = tmp_path / "markers.csv"
    dataset.write_text(
        "id,priority_code\n1,N/A\n2,NULL\n3,\n4,P1\n",
        encoding="utf-8",
    )
    engine = DiagnosticEngine(PolicyGateway())

    profile = engine.run(
        _request(
            DiagnosticTool.PROFILE_DATASET,
            artifact_id,
            {
                "column": "priority_code",
                "keep_default_na": False,
                "value_counts": True,
            },
        ),
        dataset,
    )
    restricted_nulls = engine.run(
        _request(
            DiagnosticTool.CHECK_NULL_RATIO,
            artifact_id,
            {
                "column": "priority_code",
                "keep_default_na": False,
                "na_values": ["", "NULL"],
            },
        ),
        dataset,
    )
    expanded_nulls = engine.run(
        _request(
            DiagnosticTool.CHECK_NULL_RATIO,
            artifact_id,
            {
                "column": "priority_code",
                "keep_default_na": False,
                "na_values": ["", "NULL", "N/A"],
            },
        ),
        dataset,
    )

    assert profile.success is True
    assert profile.metrics["value_counts"]["priority_code"] == {
        "N/A": 1,
        "NULL": 1,
        "<EMPTY>": 1,
        "P1": 1,
    }
    assert restricted_nulls.metrics["null_ratios"]["priority_code"] == pytest.approx(0.5)
    assert expanded_nulls.metrics["null_ratios"]["priority_code"] == pytest.approx(0.75)


def test_log_signature_diagnostic(tmp_path: Path, artifact_id: UUID) -> None:
    path = tmp_path / "pipeline.log"
    path.write_text(
        "INFO load started\nERROR schema_validation missing=customer_id observed=customerId\n",
        encoding="utf-8",
    )
    engine = DiagnosticEngine(PolicyGateway())

    result = engine.run(
        _request(
            DiagnosticTool.INSPECT_LOG_SIGNATURES,
            artifact_id,
            {"signatures": ["missing=customer_id", "customerId", "timeout"]},
        ),
        path,
    )

    assert result.success is True
    assert result.metrics == {
        "signature_counts": {"missing=customer_id": 1, "customerId": 1},
        "matching_lines": [
            {
                "line_number": 2,
                "text": "ERROR schema_validation missing=customer_id observed=customerId",
            }
        ],
        "matching_lines_truncated": False,
    }
    assert result.warnings == []


def test_log_context_is_deduplicated_bounded_and_redacted(
    tmp_path: Path,
    artifact_id: UUID,
) -> None:
    path = tmp_path / "bounded.log"
    secret_line = "ERROR api_key=supersecretvalue missing=customer_id"
    unique_lines = [f"ERROR row={index} {'x' * 600}" for index in range(12)]
    path.write_text(
        "\n".join([secret_line, secret_line, *unique_lines]) + "\n",
        encoding="utf-8",
    )
    engine = DiagnosticEngine(PolicyGateway())

    result = engine.run(
        _request(
            DiagnosticTool.INSPECT_LOG_SIGNATURES,
            artifact_id,
            {"signatures": ["error", "missing=customer_id"]},
        ),
        path,
    )

    contexts = result.metrics["matching_lines"]
    assert result.metrics["signature_counts"] == {"error": 14, "missing=customer_id": 2}
    assert len(contexts) == 10
    assert len({item["text"] for item in contexts}) == 10
    assert all(len(item["text"]) <= 500 for item in contexts)
    assert result.metrics["matching_lines_truncated"] is True
    rendered = str(contexts)
    assert "supersecretvalue" not in rendered
    assert "[REDACTED:assigned_secret]" in rendered
    assert result.warnings == [
        "Matching log context was truncated to the safe line limit.",
        "Credential-like text was redacted from matching log context.",
    ]


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
