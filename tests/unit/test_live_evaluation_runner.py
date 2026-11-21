from __future__ import annotations

from pathlib import Path

from data_incident_investigator.llm import UsageSnapshot
from evals.harness.manifest import load_manifest
from evals.live_runner import _observation_from_state, load_fixture


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
    facts = " ".join(str(item["fact"]) for item in fixture.ground_truth["required_evidence"])
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
            "operations": [{"operation": "parse_datetime", "arguments": {}}],
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
        stale_blocked=True,
        duplicate_blocked=True,
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
