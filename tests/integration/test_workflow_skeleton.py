"""Integration tests for bounded planning, approval binding, and replay safety."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from data_incident_investigator.services import SQLiteApprovalLedger, build_demo_services
from data_incident_investigator.services.fake import FixedClock
from data_incident_investigator.workflow import (
    ApprovalBindingMismatchError,
    ApprovalDecision,
    ApprovalExpiredError,
    ApprovalReplayError,
    build_investigation_graph,
)
from data_incident_investigator.workflow.services import WorkflowServices
from data_incident_investigator.workflow.state import (
    ApprovalDecisionRecord,
    ApprovalRecord,
    ApprovalRequestRecord,
    DiagnosticRecord,
    EvidenceRecord,
    HypothesisRecord,
    RemediationRecord,
    RemediationResult,
    VerificationRecord,
)

DEMO_SECRET = b"integration-test-approval-key-32-bytes"


def initial_input(case_id: str) -> dict[str, object]:
    return {
        "case_id": case_id,
        "incident_summary": "Orders dropped by 38 percent after a pipeline deployment.",
        "artifact_ids": ["orders-before.csv", "orders-after.csv", "pipeline.log"],
    }


def approval_request(pending: dict[str, object]) -> ApprovalRequestRecord:
    interrupts = pending["__interrupt__"]
    interrupt_value = interrupts[0].value  # type: ignore[index, union-attr]
    return cast(ApprovalRequestRecord, interrupt_value["approval_request"])


def decision_for(
    request: ApprovalRequestRecord,
    *,
    approved: bool,
    note: str | None,
) -> ApprovalDecisionRecord:
    return {
        **request,
        "approved": approved,
        "note": note,
    }


def test_refines_evidence_replans_and_applies_only_after_bound_approval() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)
    graph = build_investigation_graph(bundle.workflow, checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "case-approve"}}

    pending = graph.invoke(initial_input("case-approve"), config)

    assert pending["status"] == "awaiting_approval"
    assert len(bundle.retrieval.queries) == 2
    assert bundle.retrieval.queries[0] != bundle.retrieval.queries[1]
    assert pending["retrieval_round"] == 2
    assert pending["plan_revision"] == 1
    assert bundle.diagnostics.actions == ["measure_null_rate", "compare_join_key_types"]
    assert "schema-type-drift" in bundle.reasoning.revision_evidence_ids
    assert "schema-type-drift" in bundle.reasoning.verification_evidence_ids
    assert bundle.reasoning.revision_diagnostic_ids == ["null-spike"]
    assert bundle.remediation.apply_calls == 0

    request = approval_request(pending)
    assert len(request["proposal_hash"]) == 64
    assert len(request["plan_hash"]) == 64
    assert len(request["source_hash"]) == 64
    assert request["expires_at"] > request["issued_at"]
    approval_interrupt = pending["__interrupt__"][0]
    assert approval_interrupt.response_schema == ApprovalDecision.model_json_schema()

    completed = graph.invoke(
        Command(resume=decision_for(request, approved=True, note="Patch and sources reviewed.")),
        config,
    )

    assert completed["status"] == "completed"
    assert completed["approval"]["approved"] is True
    assert completed["approval"]["proposal_hash"] == request["proposal_hash"]
    assert completed["remediation_result"]["applied"] is True
    assert bundle.remediation.apply_calls == 1
    assert bundle.remediation.approvals == [completed["approval"]]
    json.dumps(completed, allow_nan=False)


def test_configured_retrieval_limit_is_enforced_by_compiled_graph() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)
    graph = build_investigation_graph(
        bundle.workflow,
        checkpointer=InMemorySaver(),
        max_retrieval_rounds=1,
        max_plan_revisions=2,
    )

    pending = graph.invoke(
        initial_input("case-configured-retrieval-limit"),
        {"configurable": {"thread_id": "case-configured-retrieval-limit"}},
    )

    assert pending["status"] == "awaiting_approval"
    assert pending["retrieval_round"] == 1
    assert pending["max_retrieval_rounds"] == 1
    assert bundle.retrieval.queries == ["orders join row loss null customer_id"]
    assert "refine_query" not in {item["stage"] for item in pending["trace"]}


def test_configured_plan_revision_limit_stops_unconfirmed_workflow() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)

    class RejectingDiagnosticService:
        def run(
            self,
            *,
            hypotheses: list[HypothesisRecord],
            artifact_ids: list[str],
        ) -> list[DiagnosticRecord]:
            hypothesis = hypotheses[0]
            return [
                {
                    "hypothesis_id": hypothesis["hypothesis_id"],
                    "action": hypothesis["diagnostic_action"],
                    "observed_signal": "configured test contradiction",
                    "supports_hypothesis": False,
                }
            ]

    services = WorkflowServices(
        retrieval=bundle.retrieval,
        reasoning=bundle.reasoning,
        diagnostics=RejectingDiagnosticService(),
        remediation=bundle.remediation,
        approval=bundle.approval,
    )
    graph = build_investigation_graph(
        services,
        checkpointer=InMemorySaver(),
        max_retrieval_rounds=3,
        max_plan_revisions=1,
    )

    completed = graph.invoke(
        initial_input("case-configured-revision-limit"),
        {"configurable": {"thread_id": "case-configured-revision-limit"}},
    )

    assert completed["status"] == "unresolved"
    assert completed["plan_revision"] == 1
    assert completed["max_plan_revisions"] == 1
    assert "__interrupt__" not in completed
    assert bundle.remediation.apply_calls == 0


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("max_retrieval_rounds", 0, ValueError),
        ("max_retrieval_rounds", True, TypeError),
        ("max_plan_revisions", 6, ValueError),
    ],
)
def test_graph_rejects_invalid_direct_loop_limits(
    field: str,
    value: object,
    error: type[Exception],
) -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)
    limits = {"max_retrieval_rounds": 3, "max_plan_revisions": 2, field: value}

    with pytest.raises(error):
        build_investigation_graph(
            bundle.workflow,
            checkpointer=InMemorySaver(),
            max_retrieval_rounds=cast(int, limits["max_retrieval_rounds"]),
            max_plan_revisions=cast(int, limits["max_plan_revisions"]),
        )


def test_rejection_consumes_approval_without_calling_apply() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)
    graph = build_investigation_graph(bundle.workflow, checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "case-reject"}}

    pending = graph.invoke(initial_input("case-reject"), config)
    request = approval_request(pending)
    rejected = graph.invoke(
        Command(resume=decision_for(request, approved=False, note="Investigate upstream first.")),
        config,
    )

    assert rejected["status"] == "rejected"
    assert rejected["approval"]["approved"] is False
    assert "remediation_result" not in rejected
    assert bundle.remediation.apply_calls == 0


def test_approved_manual_escalation_finishes_without_mutation() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)

    class ManualEscalationService:
        apply_calls = 0

        def propose(
            self,
            *,
            incident_summary: str,
            verification: VerificationRecord,
            evidence: list[EvidenceRecord],
            diagnostics: list[DiagnosticRecord],
        ) -> RemediationRecord:
            return {
                "proposal_id": "manual-source-replacement",
                "disposition": "manual_escalation",
                "title": "Replace the corrupt upstream source",
                "explanation": "Missing source bytes cannot be reconstructed safely.",
                "operations": [],
                "citation_ids": [evidence[0]["evidence_id"]],
            }

        def apply(
            self,
            *,
            case_id: str,
            proposal: RemediationRecord,
            approval: ApprovalRecord,
        ) -> RemediationResult:
            self.apply_calls += 1
            raise AssertionError("manual escalation must never invoke remediation apply")

    remediation = ManualEscalationService()
    services = WorkflowServices(
        retrieval=bundle.retrieval,
        reasoning=bundle.reasoning,
        diagnostics=bundle.diagnostics,
        remediation=remediation,
        approval=bundle.approval,
    )
    graph = build_investigation_graph(services, checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "case-manual-escalation"}}

    pending = graph.invoke(initial_input("case-manual-escalation"), config)
    request = approval_request(pending)
    completed = graph.invoke(
        Command(resume=decision_for(request, approved=True, note="Escalate to the source owner.")),
        config,
    )

    assert completed["status"] == "unresolved"
    assert completed["remediation"]["disposition"] == "manual_escalation"
    assert remediation.apply_calls == 0
    assert "remediation_result" not in completed


def test_mismatched_binding_is_rejected_before_apply() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)
    graph = build_investigation_graph(bundle.workflow, checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "case-mismatch"}}
    pending = graph.invoke(initial_input("case-mismatch"), config)
    request = approval_request(pending)
    tampered = decision_for(request, approved=True, note="Looks fine.")
    tampered["proposal_hash"] = "0" * 64

    with pytest.raises(ApprovalBindingMismatchError, match="changed signed field"):
        graph.invoke(Command(resume=tampered), config)

    assert bundle.remediation.apply_calls == 0


def test_stale_approval_is_rejected_before_apply() -> None:
    clock = FixedClock()
    bundle = build_demo_services(secret_key=DEMO_SECRET, clock=clock, ttl_seconds=30)
    graph = build_investigation_graph(bundle.workflow, checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "case-expired"}}
    pending = graph.invoke(initial_input("case-expired"), config)
    request = approval_request(pending)
    clock.advance(31)

    with pytest.raises(ApprovalExpiredError, match="expired"):
        graph.invoke(
            Command(resume=decision_for(request, approved=True, note="Too late.")),
            config,
        )

    assert bundle.remediation.apply_calls == 0


def test_consumed_approval_cannot_be_replayed() -> None:
    bundle = build_demo_services(secret_key=DEMO_SECRET)
    graph = build_investigation_graph(bundle.workflow, checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "case-replay"}}
    pending = graph.invoke(initial_input("case-replay"), config)
    request = approval_request(pending)
    decision = decision_for(request, approved=True, note="One use only.")

    completed = graph.invoke(Command(resume=decision), config)
    assert completed["status"] == "completed"
    assert bundle.remediation.apply_calls == 1

    with pytest.raises(ApprovalReplayError, match="already consumed"):
        bundle.approval.validate_and_consume(
            request=request,
            decision=decision,
            current_proposal_hash=request["proposal_hash"],
            current_plan_hash=request["plan_hash"],
            current_source_hash=request["source_hash"],
        )

    assert bundle.remediation.apply_calls == 1


def test_file_checkpoint_and_nonce_ledger_resume_after_restart(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "workflow-checkpoints.sqlite3"
    ledger_path = tmp_path / "approval-ledger.sqlite3"
    clock = FixedClock()
    first_bundle = build_demo_services(
        secret_key=DEMO_SECRET,
        clock=clock,
        ledger=SQLiteApprovalLedger(ledger_path),
    )
    config = {"configurable": {"thread_id": "case-restart"}}

    with SqliteSaver.from_conn_string(str(checkpoint_path)) as saver:
        graph = build_investigation_graph(first_bundle.workflow, checkpointer=saver)
        pending = graph.invoke(initial_input("case-restart"), config)
        request = approval_request(pending)

    restarted_bundle = build_demo_services(
        secret_key=DEMO_SECRET,
        clock=clock,
        ledger=SQLiteApprovalLedger(ledger_path),
    )
    with SqliteSaver.from_conn_string(str(checkpoint_path)) as saver:
        restarted_graph = build_investigation_graph(
            restarted_bundle.workflow,
            checkpointer=saver,
        )
        completed = restarted_graph.invoke(
            Command(resume=decision_for(request, approved=True, note="Resumed after restart.")),
            config,
        )

    assert completed["status"] == "completed"
    assert completed["approval"]["note"] == "Resumed after restart."
    assert restarted_bundle.remediation.apply_calls == 1

    replay_bundle = build_demo_services(
        secret_key=DEMO_SECRET,
        clock=clock,
        ledger=SQLiteApprovalLedger(ledger_path),
    )
    with pytest.raises(ApprovalReplayError):
        replay_bundle.approval.validate_and_consume(
            request=request,
            decision=decision_for(request, approved=True, note="Replay."),
            current_proposal_hash=request["proposal_hash"],
            current_plan_hash=request["plan_hash"],
            current_source_hash=request["source_hash"],
        )
