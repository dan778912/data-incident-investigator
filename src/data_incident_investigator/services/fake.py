"""Deterministic end-to-end services for local demos and tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from data_incident_investigator.workflow.services import WorkflowServices
from data_incident_investigator.workflow.state import (
    ApprovalRecord,
    DiagnosticRecord,
    EvidenceAssessment,
    EvidenceRecord,
    HypothesisRecord,
    RemediationRecord,
    RemediationResult,
    VerificationRecord,
)

from .approval import ApprovalLedger, Clock, HMACApprovalBindingService


@dataclass(slots=True)
class FixedClock:
    """Controllable epoch clock for expiry tests."""

    current: int = 1_800_000_000

    def now_epoch_seconds(self) -> int:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += seconds


@dataclass(slots=True)
class SequentialNonceFactory:
    """Stable nonce generator; never use this implementation in production."""

    sequence: int = 0

    def create(self) -> str:
        self.sequence += 1
        return f"demo-approval-nonce-{self.sequence:08d}"


@dataclass(slots=True)
class InMemoryApprovalLedger:
    """Atomic-enough single-process ledger for deterministic tests."""

    reserved: dict[str, int] = field(default_factory=dict)
    consumed: set[str] = field(default_factory=set)

    def reserve(self, *, nonce: str, expires_at: int) -> None:
        if nonce in self.reserved:
            raise ValueError("approval nonce collision")
        self.reserved[nonce] = expires_at

    def consume(self, *, nonce: str, consumed_at: int) -> bool:
        expiry = self.reserved.get(nonce)
        if expiry is None or nonce in self.consumed or consumed_at > expiry:
            return False
        self.consumed.add(nonce)
        return True


@dataclass(slots=True)
class DemoRetrievalService:
    queries: list[str] = field(default_factory=list)

    def search(self, *, query: str, artifact_ids: list[str]) -> list[EvidenceRecord]:
        self.queries.append(query)
        if "schema type drift" not in query:
            return [
                {
                    "evidence_id": "runbook-overview",
                    "source": "runbooks/join_failures.md",
                    "excerpt": "Check null rates before investigating join-key compatibility.",
                    "relevance_score": 0.62,
                }
            ]
        return [
            {
                "evidence_id": "schema-type-drift",
                "source": "schemas/orders_v2.json",
                "excerpt": "customer_id changed from integer to string in schema version 2.",
                "relevance_score": 0.98,
            }
        ]


@dataclass(slots=True)
class DemoReasoningService:
    revision_evidence_ids: list[str] = field(default_factory=list)
    revision_diagnostic_ids: list[str] = field(default_factory=list)

    def initial_query(self, *, incident_summary: str, artifact_ids: list[str]) -> str:
        return "orders join row loss null customer_id"

    def refine_query(
        self,
        *,
        incident_summary: str,
        previous_query: str,
        evidence: list[EvidenceRecord],
        retrieval_round: int,
    ) -> str:
        return "orders customer_id schema type drift join compatibility"

    def assess_evidence(
        self,
        *,
        query: str,
        evidence: list[EvidenceRecord],
        retrieval_round: int,
    ) -> EvidenceAssessment:
        sufficient = any(item["evidence_id"] == "schema-type-drift" for item in evidence)
        return {
            "sufficient": sufficient,
            "reason": "Schema-change evidence found." if sufficient else "Need schema history.",
        }

    def form_hypotheses(
        self,
        *,
        incident_summary: str,
        evidence: list[EvidenceRecord],
    ) -> list[HypothesisRecord]:
        return [
            {
                "hypothesis_id": "null-spike",
                "statement": "A null spike removed joinable customer identifiers.",
                "diagnostic_action": "measure_null_rate",
                "expected_signal": "customer_id null rate exceeds 20 percent",
            }
        ]

    def revise_hypotheses(
        self,
        *,
        incident_summary: str,
        hypotheses: list[HypothesisRecord],
        evidence: list[EvidenceRecord],
        diagnostics: list[DiagnosticRecord],
        revision: int,
    ) -> list[HypothesisRecord]:
        self.revision_evidence_ids = [item["evidence_id"] for item in evidence]
        self.revision_diagnostic_ids = [item["hypothesis_id"] for item in diagnostics]
        return [
            {
                "hypothesis_id": "type-drift",
                "statement": "A customer_id type drift caused the join mismatch.",
                "diagnostic_action": "compare_join_key_types",
                "expected_signal": "left and right customer_id dtypes differ",
            }
        ]

    def verify_hypotheses(
        self,
        *,
        hypotheses: list[HypothesisRecord],
        diagnostics: list[DiagnosticRecord],
        revision: int,
    ) -> VerificationRecord:
        current_id = hypotheses[0]["hypothesis_id"]
        current_results = [item for item in diagnostics if item["hypothesis_id"] == current_id]
        confirmed = bool(current_results and current_results[-1]["supports_hypothesis"])
        return {
            "confirmed": confirmed,
            "root_cause_id": current_id if confirmed else None,
            "reason": "Type mismatch reproduced." if confirmed else "Null rate remained normal.",
        }


@dataclass(slots=True)
class DemoDiagnosticService:
    actions: list[str] = field(default_factory=list)

    def run(
        self,
        *,
        hypotheses: list[HypothesisRecord],
        artifact_ids: list[str],
    ) -> list[DiagnosticRecord]:
        hypothesis = hypotheses[0]
        self.actions.append(hypothesis["diagnostic_action"])
        is_type_drift = hypothesis["hypothesis_id"] == "type-drift"
        return [
            {
                "hypothesis_id": hypothesis["hypothesis_id"],
                "action": hypothesis["diagnostic_action"],
                "observed_signal": "integer versus string"
                if is_type_drift
                else "null rate 0.2 percent",
                "supports_hypothesis": is_type_drift,
            }
        ]


@dataclass(slots=True)
class DemoRemediationService:
    apply_calls: int = 0
    approvals: list[ApprovalRecord] = field(default_factory=list)

    def propose(
        self,
        *,
        incident_summary: str,
        verification: VerificationRecord,
        evidence: list[EvidenceRecord],
        diagnostics: list[DiagnosticRecord],
    ) -> RemediationRecord:
        return {
            "proposal_id": "cast-customer-id",
            "title": "Normalize customer_id before joining",
            "explanation": "Cast the right-side join key to integer in a working copy.",
            "operations": [
                {
                    "operation": "cast_column",
                    "arguments": {"column": "customer_id", "target_type": "integer"},
                }
            ],
        }

    def apply(
        self,
        *,
        case_id: str,
        proposal: RemediationRecord,
        approval: ApprovalRecord,
    ) -> RemediationResult:
        if not approval["approved"]:
            raise RuntimeError("rejected approval cannot authorize remediation")
        if approval["proposal_hash"] == "" or approval["nonce"] == "":
            raise RuntimeError("remediation requires a bound approval record")
        self.apply_calls += 1
        self.approvals.append(approval)
        return {
            "applied": True,
            "message": "Created a remediated working copy.",
            "output_artifact_id": f"{case_id}-remediated",
            "original_sha256": "0" * 64,
            "output_sha256": "1" * 64,
            "validation_passed": True,
            "checks": [
                {
                    "kind": "column_cast",
                    "operation_index": 0,
                    "target": "customer_id",
                    "passed": True,
                    "metrics": {
                        "target_type": "integer",
                        "actual_dtype": "Int64",
                    },
                },
                {
                    "kind": "original_unchanged",
                    "operation_index": None,
                    "target": case_id,
                    "passed": True,
                    "metrics": {"simulated": True},
                },
                {
                    "kind": "output_hash_matches",
                    "operation_index": None,
                    "target": f"{case_id}-remediated",
                    "passed": True,
                    "metrics": {"simulated": True},
                },
            ],
        }


@dataclass(frozen=True, slots=True)
class DemoServiceBundle:
    workflow: WorkflowServices
    retrieval: DemoRetrievalService
    reasoning: DemoReasoningService
    diagnostics: DemoDiagnosticService
    remediation: DemoRemediationService
    approval: HMACApprovalBindingService
    clock: Clock
    ledger: ApprovalLedger


def build_demo_services(
    *,
    secret_key: bytes = b"demo-only-approval-key-32-bytes!!",
    clock: Clock | None = None,
    ledger: ApprovalLedger | None = None,
    ttl_seconds: int = 300,
) -> DemoServiceBundle:
    """Construct deterministic services showing both required workflow loops."""

    demo_clock = clock or FixedClock()
    demo_ledger = ledger or InMemoryApprovalLedger()
    retrieval = DemoRetrievalService()
    reasoning = DemoReasoningService()
    diagnostics = DemoDiagnosticService()
    remediation = DemoRemediationService()
    approval = HMACApprovalBindingService(
        secret_key=secret_key,
        ledger=demo_ledger,
        clock=demo_clock,
        nonce_factory=SequentialNonceFactory(),
        ttl_seconds=ttl_seconds,
    )
    workflow = WorkflowServices(
        retrieval=retrieval,
        reasoning=reasoning,
        diagnostics=diagnostics,
        remediation=remediation,
        approval=approval,
    )
    return DemoServiceBundle(
        workflow=workflow,
        retrieval=retrieval,
        reasoning=reasoning,
        diagnostics=diagnostics,
        remediation=remediation,
        approval=approval,
        clock=demo_clock,
        ledger=demo_ledger,
    )
