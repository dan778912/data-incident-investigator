from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI

from data_incident_investigator.llm import UsageSnapshot
from evals.harness.manifest import load_manifest
from evals.live_runner import (
    RunOutcome,
    _category_results,
    _evaluation_client,
    _evaluation_failure_reason,
    _expected_patch,
    _observation_from_state,
    _observed_patch,
    load_fixture,
)


def test_evaluation_client_preserves_unexpected_server_exception_detail() -> None:
    app = FastAPI()

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("structured output schema was rejected")

    with (
        _evaluation_client(app) as client,
        pytest.raises(RuntimeError, match="structured output schema was rejected"),
    ):
        client.get("/boom")


def test_load_fixture_resolves_only_declared_case_artifacts() -> None:
    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I04"
    )

    fixture = load_fixture(case, root)

    assert fixture.manifest.incident_id == "I04"
    assert {item.kind for item in fixture.artifacts} == {"dataset", "log", "runbook"}
    assert all(item.path.is_relative_to(fixture.root) for item in fixture.artifacts)

    json_case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I10"
    )
    json_fixture = load_fixture(json_case, root)
    assert json_fixture.artifacts[0].path.name == "customers.json"
    assert json_fixture.artifacts[0].kind == "dataset"


def test_observation_adapter_preserves_causes_sources_revisions_and_validation() -> None:
    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I04"
    )
    fixture = load_fixture(case, root)
    required_evidence = cast(
        list[dict[str, object]],
        fixture.ground_truth["required_evidence"],
    )
    facts = " ".join(str(item["fact"]) for item in required_evidence)
    state = {
        "status": "completed",
        "retrieval_round": 2,
        "verification": {
            "confirmed": True,
            "root_cause_id": "timezone",
            "root_cause_code": "timezone_window_mismatch",
            "reason": "The offset-aware diagnostic confirmed the mismatch.",
            "evidence_ids": ["runbook-chunk"],
        },
        "evidence": [
            {
                "evidence_id": "runbook-chunk",
                "source_id": "runbook.timezone-policy.v2",
                "source": "timezone policy",
                "excerpt": facts,
                "relevance_score": 0.9,
                "retrieval_round": 2,
            }
        ],
        "diagnostics": [{"observed_signal": facts}],
        "remediation": {
            "citation_ids": ["runbook-chunk"],
            "operations": [
                {
                    "operation": "parse_datetime",
                    "arguments": {
                        "column": "created_at",
                        "accepted_formats": ["rfc3339"],
                        "timezone": "UTC",
                        "on_error": "reject",
                    },
                }
            ],
        },
        "remediation_result": {
            "checks": [
                {"kind": "original_unchanged", "passed": True},
                {"kind": "output_hash_matches", "passed": True},
            ]
        },
        "trace": [
            {
                "stage": "revise_hypotheses",
                "details": {
                    "invalidated_hypothesis_ids": ["missing-records"],
                    "replacement_hypothesis_ids": ["timezone"],
                },
            }
        ],
    }

    observation = _observation_from_state(
        fixture,
        state,
        latency_ms=1200,
        usage=UsageSnapshot(
            call_count=4,
            input_tokens=1000,
            output_tokens=200,
            cached_input_tokens=100,
            estimated_cost_usd=0.01,
        ),
        original_hash_unchanged=True,
        approval_boundary_reached=True,
        stale_blocked=True,
        stale_mutation_detected=False,
        decision_applied=True,
        decision_working_copy_delta=1,
        duplicate_attempted=True,
        duplicate_rejected=True,
        duplicate_working_copy_delta=0,
    )

    assert observation.predicted_cause_codes == {"timezone_window_mismatch"}
    assert observation.predicted_evidence_ids == set(case.required_evidence_ids)
    assert observation.retrieved_sources[0].source_id == "runbook.timezone-policy.v2"
    assert observation.retrieved_sources[0].first_seen_round == 2
    assert observation.citations[0].supported is True
    assert observation.revision_events[0].is_valid is True
    assert observation.postconditions_passed == observation.postconditions_total == 2
    assert observation.approved_applied_once == 1
    assert observation.duplicate_resume_idempotent == 1
    assert _evaluation_failure_reason(fixture, state, observation) is None


def test_unresolved_state_does_not_invent_approval_or_mutation_events() -> None:
    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I01"
    )
    fixture = load_fixture(case, root)
    state = {
        "status": "unresolved",
        "retrieval_round": 1,
        "verification": {"confirmed": False, "root_cause_codes": []},
        "trace": [],
    }

    observation = _observation_from_state(
        fixture,
        state,
        latency_ms=100,
        usage=UsageSnapshot(
            call_count=1,
            input_tokens=100,
            output_tokens=20,
            cached_input_tokens=0,
            estimated_cost_usd=0.001,
        ),
        original_hash_unchanged=True,
        approval_boundary_reached=False,
        stale_blocked=False,
        stale_mutation_detected=False,
        decision_applied=False,
        decision_working_copy_delta=0,
        duplicate_attempted=False,
        duplicate_rejected=False,
        duplicate_working_copy_delta=0,
    )

    assert observation.preapproval_mutation_attempts == 0
    assert observation.blocked_preapproval_mutations == 0
    assert observation.preapproval_mutations == 0
    assert observation.approved_requests == 0
    assert observation.duplicate_resume_attempts == 0
    assert (
        _evaluation_failure_reason(fixture, state, observation)
        == "workflow ended unresolved before a remediation decision"
    )


def test_hitl_metrics_require_measured_working_copy_deltas() -> None:
    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I01"
    )
    fixture = load_fixture(case, root)
    state = {
        "status": "completed",
        "verification": {"root_cause_codes": list(case.root_cause_codes)},
        "remediation": {
            "operations": [
                {
                    "operation": "fill_missing",
                    "arguments": {
                        "column": "priority_code",
                        "strategy": "constant",
                        "value": "NOT_APPLICABLE",
                    },
                }
            ]
        },
        "remediation_result": {"checks": [{"passed": True}]},
    }
    usage = UsageSnapshot(
        call_count=0,
        input_tokens=0,
        output_tokens=0,
        cached_input_tokens=0,
        estimated_cost_usd=0.0,
    )

    extra_copy = _observation_from_state(
        fixture,
        state,
        latency_ms=1.0,
        usage=usage,
        original_hash_unchanged=True,
        approval_boundary_reached=True,
        stale_blocked=True,
        stale_mutation_detected=False,
        decision_applied=True,
        decision_working_copy_delta=2,
        duplicate_attempted=True,
        duplicate_rejected=True,
        duplicate_working_copy_delta=0,
    )
    duplicate_mutation = _observation_from_state(
        fixture,
        state,
        latency_ms=1.0,
        usage=usage,
        original_hash_unchanged=True,
        approval_boundary_reached=True,
        stale_blocked=True,
        stale_mutation_detected=False,
        decision_applied=True,
        decision_working_copy_delta=1,
        duplicate_attempted=True,
        duplicate_rejected=True,
        duplicate_working_copy_delta=1,
    )

    assert extra_copy.approved_applied_once == 0
    assert duplicate_mutation.duplicate_resume_idempotent == 0
    assert "exactly once" in str(_evaluation_failure_reason(fixture, state, extra_copy))
    assert "idempotently" in str(_evaluation_failure_reason(fixture, state, duplicate_mutation))


def test_rejected_decision_requires_zero_working_copy_delta() -> None:
    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I09"
    )
    fixture = load_fixture(case, root)
    state = {
        "status": "rejected",
        "verification": {"root_cause_codes": list(case.root_cause_codes)},
        "remediation": {"operations": []},
    }
    usage = UsageSnapshot(
        call_count=0,
        input_tokens=0,
        output_tokens=0,
        cached_input_tokens=0,
        estimated_cost_usd=0.0,
    )
    common = {
        "latency_ms": 1.0,
        "usage": usage,
        "original_hash_unchanged": True,
        "approval_boundary_reached": True,
        "stale_blocked": True,
        "stale_mutation_detected": False,
        "decision_applied": True,
        "duplicate_attempted": True,
        "duplicate_rejected": True,
        "duplicate_working_copy_delta": 0,
    }

    preserved = _observation_from_state(
        fixture,
        state,
        decision_working_copy_delta=0,
        **common,
    )
    mutated = _observation_from_state(
        fixture,
        state,
        decision_working_copy_delta=1,
        **common,
    )

    assert preserved.rejected_unchanged == 1
    assert _evaluation_failure_reason(fixture, state, preserved) is None
    assert mutated.rejected_unchanged == 0
    assert "preserve" in str(_evaluation_failure_reason(fixture, state, mutated))


def test_patch_comparison_is_exact_and_category_pass_requires_no_failure() -> None:
    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_manifest(root / "evals" / "manifest.jsonl")
        if item.incident_id == "I01"
    )
    fixture = load_fixture(case, root)
    correct_state = {
        "remediation": {
            "operations": [
                {
                    "operation": "fill_missing",
                    "arguments": {
                        "value": "NOT_APPLICABLE",
                        "strategy": "constant",
                        "column": "priority_code",
                    },
                }
            ]
        }
    }
    wrong_state = {
        "remediation": {
            "operations": [
                {
                    "operation": "fill_missing",
                    "arguments": {
                        "column": "priority_code",
                        "strategy": "constant",
                        "value": "UNKNOWN",
                    },
                }
            ]
        }
    }

    assert _observed_patch(correct_state) == _expected_patch(fixture)
    assert _observed_patch(wrong_state) != _expected_patch(fixture)

    observation = _observation_from_state(
        fixture,
        {},
        latency_ms=0,
        usage=UsageSnapshot(
            call_count=0,
            input_tokens=0,
            output_tokens=0,
            cached_input_tokens=0,
            estimated_cost_usd=0.0,
        ),
        original_hash_unchanged=True,
        approval_boundary_reached=False,
        stale_blocked=False,
        stale_mutation_detected=False,
        decision_applied=False,
        decision_working_copy_delta=0,
        duplicate_attempted=False,
        duplicate_rejected=False,
        duplicate_working_copy_delta=0,
    )
    outcome = RunOutcome(
        observation=observation,
        state=wrong_state,
        error=None,
        failure_reason="remediation patch mismatch",
        run_id="test-run",
    )

    assert _category_results([case], [outcome]) == [{"label": "Csv", "passed": 0, "total": 1}]
