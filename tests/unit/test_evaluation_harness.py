"""Unit tests for the provider-agnostic evaluation harness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from data_incident_investigator.domain.remediation import RemediationOperation

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evals.harness import (  # noqa: E402
    CitationGrade,
    EvaluationError,
    JsonlTraceWriter,
    ManifestCase,
    ManifestValidationError,
    RetrievedSource,
    RevisionRecord,
    RunObservation,
    TraceEvent,
    TraceValidationError,
    TraceValidator,
    grade_suite,
    load_manifest,
    load_trace,
)

EVALS_ROOT = PROJECT_ROOT / "evals"


def test_loads_and_validates_frozen_twenty_case_manifest() -> None:
    cases = load_manifest(EVALS_ROOT / "manifest.jsonl")
    ready = {case.incident_id for case in cases if case.fixture_status == "ready"}
    i19 = next(case for case in cases if case.incident_id == "I19")

    assert len(cases) == 20
    assert len({case.incident_id for case in cases}) == 20
    assert ready == {f"I{index:02d}" for index in range(1, 21)}
    assert i19.minimum_retrieval_rounds == 2
    assert i19.required_source_ids == (
        "runbook.customer-schema.v1",
        "runbook.customer-schema.v2",
    )


def test_fixture_contracts_match_manifest_and_remediation_dsl() -> None:
    cases = load_manifest(EVALS_ROOT / "manifest.jsonl")
    operation_adapter = TypeAdapter(RemediationOperation)

    for case in cases:
        assert case.fixture_path is not None
        fixture = EVALS_ROOT / case.fixture_path
        ground_truth = json.loads(
            (fixture / "expected" / "ground_truth.json").read_text(encoding="utf-8")
        )
        assertions = json.loads(
            (fixture / "expected" / "assertions.json").read_text(encoding="utf-8")
        )
        evidence_ids = {item["evidence_id"] for item in ground_truth["required_evidence"]}
        assertion_ids = {item["assertion_id"] for item in assertions["assertions"]}
        patch_operations = ground_truth["expected_patch"]
        patch_operation_names = {item["op"] for item in patch_operations}
        runbook_source_ids = {
            line.split(":", 1)[1].strip()
            for path in (fixture / "runbooks").glob("*.md")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("source_id:")
        }

        assert set(ground_truth["root_cause_codes"]) == set(case.root_cause_codes)
        assert evidence_ids == set(case.required_evidence_ids)
        assert set(ground_truth["required_source_ids"]) == set(case.required_source_ids)
        assert runbook_source_ids == set(case.required_source_ids)
        assert assertion_ids == set(case.validation_assertion_ids)
        assert patch_operation_names == set(case.allowed_patch_operations)
        assert ground_truth["approval_decision"] == case.approval_scenario
        for operation in patch_operations:
            operation_adapter.validate_python(operation)


def test_manifest_rejects_duplicate_incident_ids(tmp_path: Path) -> None:
    first_line = (EVALS_ROOT / "manifest.jsonl").read_text(encoding="utf-8").splitlines()[0]
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(f"{first_line}\n{first_line}\n", encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="duplicate incident_id"):
        load_manifest(manifest, validate_fixture_paths=False)


def test_trace_writer_validates_jsonl_and_stream_order(tmp_path: Path) -> None:
    validator = TraceValidator(EVALS_ROOT / "schemas" / "trace.schema.json")
    trace_path = tmp_path / "run.jsonl"
    writer = JsonlTraceWriter(trace_path, validator)
    writer.write(_trace_event(sequence=0, event_type="run_started", phase="ingest"))
    writer.write(_trace_event(sequence=1, event_type="run_completed", phase="complete"))

    events = load_trace(trace_path, validator)

    assert [event["sequence"] for event in events] == [0, 1]
    assert events[-1]["event_type"] == "run_completed"
    with pytest.raises(TraceValidationError):
        validator.validate({"schema_version": "1.0"})


def test_grades_ready_fixtures_across_all_metric_groups() -> None:
    cases = load_manifest(EVALS_ROOT / "manifest.jsonl")
    ready_cases = [case for case in cases if case.incident_id in {"I04", "I18", "I19", "I20"}]
    observations = [
        _passing_observation(case, latency_ms=float(index * 100), cost=index / 100)
        for index, case in enumerate(ready_cases, start=1)
    ]

    summary = grade_suite(cases, observations)

    assert summary.run_count == 4
    assert summary.unique_fixture_count == 4
    assert summary.metrics["coverage"]["manifest_fixture_coverage"].value == pytest.approx(0.2)
    assert summary.metrics["coverage"]["ready_fixture_coverage"].value == pytest.approx(0.2)
    assert summary.metrics["diagnosis"]["cause_exact_set_accuracy"].value == pytest.approx(1.0)
    assert summary.metrics["diagnosis"]["cause_macro_f1"].value == pytest.approx(1.0)
    assert summary.metrics["repair"]["repair_postcondition_rate"].value == pytest.approx(1.0)
    assert summary.metrics["repair"]["patch_policy_compliance"].value == pytest.approx(1.0)
    assert summary.metrics["self_correction"]["revision_success_rate"].value == pytest.approx(1.0)
    assert summary.metrics["rag"]["required_source_recall"].value == pytest.approx(1.0)
    assert summary.metrics["rag"]["citation_precision"].value == pytest.approx(1.0)
    assert summary.metrics["rag"]["second_round_gain"].value == pytest.approx(0.5)
    assert summary.metrics["hitl"]["approval_enforcement_rate"].value == pytest.approx(1.0)
    assert summary.metrics["safety"]["prompt_injection_attack_success_rate"].value == 0.0
    assert summary.metrics["performance"]["latency_p50_ms"].value == 200.0
    assert summary.metrics["performance"]["latency_p95_ms"].value == 400.0
    assert summary.metrics["performance"][
        "estimated_cost_per_successful_incident_usd"
    ].value == pytest.approx(0.025)
    assert json.loads(summary.to_json())["run_count"] == 4
    assert "| diagnosis | cause_exact_set_accuracy |" in summary.to_markdown()


def test_grades_rejection_safety_and_rejects_unknown_fixture() -> None:
    cases = load_manifest(EVALS_ROOT / "manifest.jsonl")
    rejection = RunObservation(
        fixture_id="I17",
        predicted_cause_codes=frozenset({"truncated_csv_corruption"}),
        rejected_requests=1,
        rejected_unchanged=1,
    )
    summary = grade_suite(cases, [rejection])

    assert summary.metrics["hitl"]["rejected_resume_safety_rate"].value == 1.0
    with pytest.raises(EvaluationError, match="unknown fixtures"):
        grade_suite(cases, [RunObservation(fixture_id="I99")])


def test_observation_mapping_is_typed_and_validated() -> None:
    observation = RunObservation.from_mapping(
        {
            "fixture_id": "I19",
            "predicted_cause_codes": ["stale_runbook_schema_reference"],
            "retrieved_sources": [
                {"source_id": "runbook.customer-schema.v1", "first_seen_round": 1},
                {"source_id": "runbook.customer-schema.v2", "first_seen_round": 2},
            ],
            "citations": [{"source_id": "runbook.customer-schema.v2", "supported": True}],
            "revision_events": [
                {
                    "invalidated_hypothesis": "source_omitted_client_id",
                    "replacement_hypothesis": "stale_runbook_schema_reference",
                    "contradictory_evidence_present": True,
                }
            ],
            "retrieval_rounds": 2,
            "latency_ms": 125.5,
        }
    )

    assert observation.retrieved_sources[1].first_seen_round == 2
    assert observation.revision_events[0].is_valid is True
    with pytest.raises(ValueError, match="nonnegative integer"):
        RunObservation.from_mapping({"fixture_id": "I19", "input_tokens": -1})


def _trace_event(*, sequence: int, event_type: str, phase: str) -> TraceEvent:
    return {
        "schema_version": "1.0",
        "run_id": "run-eval-001",
        "fixture_id": "I04",
        "sequence": sequence,
        "timestamp": f"2026-11-21T12:00:0{sequence}Z",
        "event_type": event_type,
        "phase": phase,
        "actor": "test-harness",
        "status": "completed",
        "payload": {},
    }


def _passing_observation(case: ManifestCase, *, latency_ms: float, cost: float) -> RunObservation:
    sources = tuple(
        RetrievedSource(
            source_id=source_id,
            first_seen_round=2 if source_id == "runbook.customer-schema.v2" else 1,
        )
        for source_id in case.required_source_ids
    )
    assertions = max(1, len(case.validation_assertion_ids))
    return RunObservation(
        fixture_id=case.incident_id,
        predicted_cause_codes=frozenset(case.root_cause_codes),
        predicted_evidence_ids=frozenset(case.required_evidence_ids),
        retrieved_sources=sources,
        citations=tuple(CitationGrade(source.source_id, True) for source in sources),
        revision_events=(
            RevisionRecord(
                invalidated_hypothesis=case.initial_hypothesis_trap or "initial",
                replacement_hypothesis=case.root_cause_codes[0],
                contradictory_evidence_present=True,
            ),
        ),
        retrieval_rounds=case.minimum_retrieval_rounds,
        proposed_patch_operations=case.allowed_patch_operations,
        repair_attempted=True,
        postconditions_passed=assertions,
        postconditions_total=assertions,
        original_hash_unchanged=True,
        preapproval_mutation_attempts=1,
        blocked_preapproval_mutations=1,
        approved_requests=1,
        approved_applied_once=1,
        attacks_executed=1,
        successful_attacks=0,
        latency_ms=latency_ms,
        input_tokens=100,
        output_tokens=50,
        cached_tokens=20,
        estimated_cost_usd=cost,
    )
