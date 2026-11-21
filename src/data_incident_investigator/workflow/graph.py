"""LangGraph workflow for a bounded, approval-gated investigation."""

from __future__ import annotations

import json
from typing import Any, Literal, cast

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt
from pydantic import BaseModel, ConfigDict, Field

from .security import canonical_sha256
from .services import WorkflowServices
from .state import (
    ApprovalDecisionRecord,
    InvestigationInput,
    InvestigationState,
    JSONValue,
    TraceEvent,
)

MAX_RETRIEVAL_ROUNDS = 3
MAX_PLAN_REVISIONS = 2


class WorkflowStateError(RuntimeError):
    """Raised when a service attempts to put unsafe or invalid data into state."""


class ApprovalDecision(BaseModel):
    """Validated response expected when the approval interrupt is resumed."""

    model_config = ConfigDict(extra="forbid", strict=True)

    approved: bool
    note: str | None = Field(default=None, max_length=500)
    binding_version: Literal["v1"]
    case_id: str = Field(min_length=1, max_length=128)
    proposal_hash: str = Field(min_length=64, max_length=64)
    plan_hash: str = Field(min_length=64, max_length=64)
    source_hash: str = Field(min_length=64, max_length=64)
    nonce: str = Field(min_length=16, max_length=256)
    issued_at: int
    expires_at: int
    binding_mac: str = Field(min_length=64, max_length=64)


def _json_clone[T](value: T, *, label: str) -> T:
    """Reject non-JSON values and detach state from mutable service objects."""

    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
        return cast(T, json.loads(encoded))
    except (TypeError, ValueError) as exc:
        raise WorkflowStateError(f"{label} must contain only strict JSON values") from exc


def _event(stage: str, message: str, **details: object) -> TraceEvent:
    safe_details = cast(
        dict[str, JSONValue],
        _json_clone(details, label=f"trace details for {stage}"),
    )
    return {"stage": stage, "message": message, "details": safe_details}


def _require_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowStateError(f"{label} must be a non-empty string")
    return value.strip()


def _approval_hashes(state: InvestigationState) -> tuple[str, str, str]:
    """Hash the exact proposal, diagnostic plan, and source context."""

    proposal_hash = canonical_sha256(state["remediation"])
    plan_hash = canonical_sha256(
        {
            "hypotheses": state["hypotheses"],
            "diagnostics": state.get("diagnostics", []),
            "verification": state["verification"],
            "plan_revision": state["plan_revision"],
        }
    )
    source_hash = canonical_sha256(
        {
            "artifact_ids": state["artifact_ids"],
            "evidence": state.get("evidence", []),
        }
    )
    return proposal_hash, plan_hash, source_hash


def build_investigation_graph(
    services: WorkflowServices,
    *,
    checkpointer: BaseCheckpointSaver[Any],
) -> CompiledStateGraph[InvestigationState, None, InvestigationInput, InvestigationState]:
    """Build and compile the bounded workflow with required durable checkpointing.

    A checkpointer is mandatory because the approval node uses ``interrupt()``.
    Production code should inject a file-backed or server-backed implementation;
    tests may inject ``InMemorySaver``.
    """

    def initialize(state: InvestigationState) -> dict[str, object]:
        case_id = _require_text(state.get("case_id"), label="case_id")
        summary = _require_text(state.get("incident_summary"), label="incident_summary")
        artifact_ids = state.get("artifact_ids")
        if not isinstance(artifact_ids, list) or not artifact_ids:
            raise WorkflowStateError("artifact_ids must contain at least one artifact identifier")
        if any(not isinstance(item, str) or not item.strip() for item in artifact_ids):
            raise WorkflowStateError("artifact_ids must contain only non-empty strings")

        return {
            "case_id": case_id,
            "incident_summary": summary,
            "artifact_ids": [item.strip() for item in artifact_ids],
            "retrieval_round": 0,
            "max_retrieval_rounds": MAX_RETRIEVAL_ROUNDS,
            "plan_revision": 0,
            "max_plan_revisions": MAX_PLAN_REVISIONS,
            "status": "retrieving",
            "trace": [
                _event(
                    "initialize",
                    "Accepted validated incident identifiers.",
                    artifact_count=len(artifact_ids),
                )
            ],
        }

    def draft_query(state: InvestigationState) -> dict[str, object]:
        query = services.reasoning.initial_query(
            incident_summary=state["incident_summary"],
            artifact_ids=state["artifact_ids"],
        )
        query = _require_text(query, label="initial retrieval query")
        return {
            "retrieval_query": query,
            "trace": [_event("draft_query", "Created the initial evidence query.")],
        }

    def retrieve_evidence(state: InvestigationState) -> dict[str, object]:
        round_number = state.get("retrieval_round", 0) + 1
        if round_number > MAX_RETRIEVAL_ROUNDS:
            raise WorkflowStateError("retrieval loop exceeded its hard limit")
        records = services.retrieval.search(
            query=state["retrieval_query"],
            artifact_ids=state["artifact_ids"],
        )
        evidence = _json_clone(records, label="retrieved evidence")
        return {
            "retrieval_round": round_number,
            "evidence": evidence,
            "trace": [
                _event(
                    "retrieve_evidence",
                    "Retrieved evidence for the current query.",
                    retrieval_round=round_number,
                    returned_count=len(evidence),
                )
            ],
        }

    def assess_evidence(state: InvestigationState) -> dict[str, object]:
        assessment = services.reasoning.assess_evidence(
            query=state["retrieval_query"],
            evidence=state.get("evidence", []),
            retrieval_round=state["retrieval_round"],
        )
        safe = _json_clone(assessment, label="evidence assessment")
        if not isinstance(safe.get("sufficient"), bool):
            raise WorkflowStateError("evidence assessment must contain a boolean sufficient field")
        _require_text(safe.get("reason"), label="evidence assessment reason")
        return {
            "retrieval_assessment": safe,
            "trace": [
                _event(
                    "assess_evidence",
                    safe["reason"],
                    sufficient=safe["sufficient"],
                    retrieval_round=state["retrieval_round"],
                )
            ],
        }

    def route_after_evidence(
        state: InvestigationState,
    ) -> Literal["refine_query", "form_hypotheses"]:
        assessment = state["retrieval_assessment"]
        if assessment["sufficient"]:
            return "form_hypotheses"
        if state["retrieval_round"] >= state["max_retrieval_rounds"]:
            return "form_hypotheses"
        return "refine_query"

    def refine_query(state: InvestigationState) -> dict[str, object]:
        query = services.reasoning.refine_query(
            incident_summary=state["incident_summary"],
            previous_query=state["retrieval_query"],
            evidence=state.get("evidence", []),
            retrieval_round=state["retrieval_round"],
        )
        query = _require_text(query, label="refined retrieval query")
        if query == state["retrieval_query"]:
            raise WorkflowStateError("refined retrieval query must differ from the previous query")
        return {
            "retrieval_query": query,
            "trace": [
                _event(
                    "refine_query",
                    "Refined the query after insufficient evidence.",
                    retrieval_round=state["retrieval_round"],
                )
            ],
        }

    def form_hypotheses(state: InvestigationState) -> dict[str, object]:
        records = services.reasoning.form_hypotheses(
            incident_summary=state["incident_summary"],
            evidence=state.get("evidence", []),
        )
        hypotheses = _json_clone(records, label="initial hypotheses")
        if not hypotheses:
            raise WorkflowStateError("reasoning service returned no falsifiable hypotheses")
        return {
            "hypotheses": hypotheses,
            "status": "diagnosing",
            "trace": [
                _event(
                    "form_hypotheses",
                    "Formed falsifiable hypotheses from retrieved evidence.",
                    hypothesis_count=len(hypotheses),
                    retrieval_limit_reached=(
                        not state["retrieval_assessment"]["sufficient"]
                        and state["retrieval_round"] >= state["max_retrieval_rounds"]
                    ),
                )
            ],
        }

    def run_diagnostics(state: InvestigationState) -> dict[str, object]:
        records = services.diagnostics.run(
            hypotheses=state["hypotheses"],
            artifact_ids=state["artifact_ids"],
        )
        diagnostics = _json_clone(records, label="diagnostic results")
        if not diagnostics:
            raise WorkflowStateError("diagnostic service returned no results")
        return {
            "diagnostics": diagnostics,
            "trace": [
                _event(
                    "run_diagnostics",
                    "Executed allowlisted read-only diagnostics.",
                    result_count=len(diagnostics),
                    plan_revision=state["plan_revision"],
                )
            ],
        }

    def verify_hypotheses(state: InvestigationState) -> dict[str, object]:
        verdict = services.reasoning.verify_hypotheses(
            hypotheses=state["hypotheses"],
            diagnostics=state.get("diagnostics", []),
            revision=state["plan_revision"],
        )
        verification = _json_clone(verdict, label="verification verdict")
        if not isinstance(verification.get("confirmed"), bool):
            raise WorkflowStateError("verification must contain a boolean confirmed field")
        _require_text(verification.get("reason"), label="verification reason")
        if verification["confirmed"] and not verification.get("root_cause_id"):
            raise WorkflowStateError("confirmed verification requires a root_cause_id")
        return {
            "verification": verification,
            "trace": [
                _event(
                    "verify_hypotheses",
                    verification["reason"],
                    confirmed=verification["confirmed"],
                    plan_revision=state["plan_revision"],
                )
            ],
        }

    def route_after_verification(
        state: InvestigationState,
    ) -> Literal["propose_remediation", "revise_hypotheses", "finalize_unresolved"]:
        if state["verification"]["confirmed"]:
            return "propose_remediation"
        if state["plan_revision"] >= state["max_plan_revisions"]:
            return "finalize_unresolved"
        return "revise_hypotheses"

    def revise_hypotheses(state: InvestigationState) -> dict[str, object]:
        revision = state["plan_revision"] + 1
        if revision > MAX_PLAN_REVISIONS:
            raise WorkflowStateError("hypothesis revision loop exceeded its hard limit")
        records = services.reasoning.revise_hypotheses(
            incident_summary=state["incident_summary"],
            hypotheses=state["hypotheses"],
            evidence=state.get("evidence", []),
            diagnostics=state.get("diagnostics", []),
            revision=revision,
        )
        hypotheses = _json_clone(records, label="revised hypotheses")
        if not hypotheses:
            raise WorkflowStateError("reasoning service returned no revised hypotheses")
        return {
            "hypotheses": hypotheses,
            "plan_revision": revision,
            "trace": [
                _event(
                    "revise_hypotheses",
                    "Revised the diagnostic plan after a failed verification.",
                    plan_revision=revision,
                    evidence_count=len(state.get("evidence", [])),
                )
            ],
        }

    def propose_remediation(state: InvestigationState) -> dict[str, object]:
        record = services.remediation.propose(
            incident_summary=state["incident_summary"],
            verification=state["verification"],
            evidence=state.get("evidence", []),
            diagnostics=state.get("diagnostics", []),
        )
        proposal = _json_clone(record, label="remediation proposal")
        if not proposal.get("operations"):
            raise WorkflowStateError("remediation proposal must contain an allowlisted operation")
        return {
            "remediation": proposal,
            "trace": [
                _event(
                    "propose_remediation",
                    "Prepared a constrained remediation proposal for human review.",
                    proposal_id=proposal["proposal_id"],
                    operation_count=len(proposal["operations"]),
                )
            ],
        }

    def prepare_approval(state: InvestigationState) -> dict[str, object]:
        proposal_hash, plan_hash, source_hash = _approval_hashes(state)
        request = services.approval.issue(
            case_id=state["case_id"],
            proposal_hash=proposal_hash,
            plan_hash=plan_hash,
            source_hash=source_hash,
        )
        safe_request = _json_clone(request, label="approval request")
        return {
            "approval_request": safe_request,
            "status": "awaiting_approval",
            "trace": [
                _event(
                    "prepare_approval",
                    "Bound the proposal, plan, and sources to an expiring one-time approval.",
                    proposal_hash=proposal_hash,
                    plan_hash=plan_hash,
                    source_hash=source_hash,
                    nonce=safe_request["nonce"],
                    expires_at=safe_request["expires_at"],
                )
            ],
        }

    def approval_gate(state: InvestigationState) -> dict[str, object]:
        proposal = state["remediation"]
        request = state["approval_request"]
        # This payload construction is pure. All externally visible side effects
        # occur in apply_remediation, after the durable interrupt is resumed.
        response = interrupt(
            {
                "kind": "remediation_approval",
                "case_id": state["case_id"],
                "proposal": proposal,
                "approval_request": request,
            },
            response_schema=ApprovalDecision,
        )
        decision = ApprovalDecision.model_validate(response)
        decision_record = cast(ApprovalDecisionRecord, decision.model_dump(mode="json"))
        proposal_hash, plan_hash, source_hash = _approval_hashes(state)
        approval = services.approval.validate_and_consume(
            request=request,
            decision=decision_record,
            current_proposal_hash=proposal_hash,
            current_plan_hash=plan_hash,
            current_source_hash=source_hash,
        )
        safe_approval = _json_clone(approval, label="validated approval record")
        return {
            "approval": safe_approval,
            "status": "approved" if decision.approved else "rejected",
            "trace": [
                _event(
                    "approval_gate",
                    "Human approved the remediation."
                    if decision.approved
                    else "Human rejected the remediation.",
                    approved=decision.approved,
                )
            ],
        }

    def route_after_approval(
        state: InvestigationState,
    ) -> Literal["apply_remediation", "finalize_rejected"]:
        return "apply_remediation" if state["approval"]["approved"] else "finalize_rejected"

    def apply_remediation(state: InvestigationState) -> dict[str, object]:
        record = services.remediation.apply(
            case_id=state["case_id"],
            proposal=state["remediation"],
            approval=state["approval"],
        )
        result = _json_clone(record, label="remediation result")
        if result.get("applied") is not True:
            raise WorkflowStateError("approved remediation did not report a successful application")
        return {
            "remediation_result": result,
            "status": "completed",
            "trace": [
                _event(
                    "apply_remediation",
                    "Applied the approved remediation to a working copy.",
                    output_artifact_id=result.get("output_artifact_id"),
                )
            ],
        }

    def finalize_rejected(state: InvestigationState) -> dict[str, object]:
        return {
            "status": "rejected",
            "trace": [
                _event(
                    "finalize_rejected",
                    "Closed the investigation without modifying an artifact.",
                )
            ],
        }

    def finalize_unresolved(state: InvestigationState) -> dict[str, object]:
        return {
            "status": "unresolved",
            "trace": [
                _event(
                    "finalize_unresolved",
                    "Stopped safely after reaching the hypothesis revision limit.",
                    plan_revision=state["plan_revision"],
                )
            ],
        }

    builder: StateGraph[
        InvestigationState,
        None,
        InvestigationInput,
        InvestigationState,
    ] = StateGraph(InvestigationState, input_schema=InvestigationInput)
    builder.add_node("initialize", initialize)
    builder.add_node("draft_query", draft_query)
    builder.add_node("retrieve_evidence", retrieve_evidence)
    builder.add_node("assess_evidence", assess_evidence)
    builder.add_node("refine_query", refine_query)
    builder.add_node("form_hypotheses", form_hypotheses)
    builder.add_node("run_diagnostics", run_diagnostics)
    builder.add_node("verify_hypotheses", verify_hypotheses)
    builder.add_node("revise_hypotheses", revise_hypotheses)
    builder.add_node("propose_remediation", propose_remediation)
    builder.add_node("prepare_approval", prepare_approval)
    builder.add_node("approval_gate", approval_gate)
    builder.add_node("apply_remediation", apply_remediation)
    builder.add_node("finalize_rejected", finalize_rejected)
    builder.add_node("finalize_unresolved", finalize_unresolved)

    builder.add_edge(START, "initialize")
    builder.add_edge("initialize", "draft_query")
    builder.add_edge("draft_query", "retrieve_evidence")
    builder.add_edge("retrieve_evidence", "assess_evidence")
    builder.add_conditional_edges(
        "assess_evidence",
        route_after_evidence,
        {
            "refine_query": "refine_query",
            "form_hypotheses": "form_hypotheses",
        },
    )
    builder.add_edge("refine_query", "retrieve_evidence")
    builder.add_edge("form_hypotheses", "run_diagnostics")
    builder.add_edge("run_diagnostics", "verify_hypotheses")
    builder.add_conditional_edges(
        "verify_hypotheses",
        route_after_verification,
        {
            "propose_remediation": "propose_remediation",
            "revise_hypotheses": "revise_hypotheses",
            "finalize_unresolved": "finalize_unresolved",
        },
    )
    builder.add_edge("revise_hypotheses", "run_diagnostics")
    builder.add_edge("propose_remediation", "prepare_approval")
    builder.add_edge("prepare_approval", "approval_gate")
    builder.add_conditional_edges(
        "approval_gate",
        route_after_approval,
        {
            "apply_remediation": "apply_remediation",
            "finalize_rejected": "finalize_rejected",
        },
    )
    builder.add_edge("apply_remediation", END)
    builder.add_edge("finalize_rejected", END)
    builder.add_edge("finalize_unresolved", END)

    return builder.compile(checkpointer=checkpointer)
