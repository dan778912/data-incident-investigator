"""Dependency-injection contracts for workflow implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .state import (
    ApprovalDecisionRecord,
    ApprovalRecord,
    ApprovalRequestRecord,
    DiagnosticRecord,
    EvidenceAssessment,
    EvidenceRecord,
    HypothesisRecord,
    RemediationRecord,
    RemediationResult,
    VerificationRecord,
)


class RetrievalService(Protocol):
    """Search validated runbooks and artifact metadata for supporting evidence."""

    def search(self, *, query: str, artifact_ids: list[str]) -> list[EvidenceRecord]: ...


class ReasoningService(Protocol):
    """LLM-backed reasoning operations used by explicit graph nodes."""

    def initial_query(self, *, incident_summary: str, artifact_ids: list[str]) -> str: ...

    def refine_query(
        self,
        *,
        incident_summary: str,
        previous_query: str,
        evidence: list[EvidenceRecord],
        retrieval_round: int,
    ) -> str: ...

    def assess_evidence(
        self,
        *,
        query: str,
        evidence: list[EvidenceRecord],
        retrieval_round: int,
    ) -> EvidenceAssessment: ...

    def form_hypotheses(
        self,
        *,
        incident_summary: str,
        evidence: list[EvidenceRecord],
    ) -> list[HypothesisRecord]: ...

    def revise_hypotheses(
        self,
        *,
        incident_summary: str,
        hypotheses: list[HypothesisRecord],
        evidence: list[EvidenceRecord],
        diagnostics: list[DiagnosticRecord],
        revision: int,
    ) -> list[HypothesisRecord]: ...

    def verify_hypotheses(
        self,
        *,
        hypotheses: list[HypothesisRecord],
        evidence: list[EvidenceRecord],
        diagnostics: list[DiagnosticRecord],
        revision: int,
    ) -> VerificationRecord: ...


class DiagnosticService(Protocol):
    """Run allowlisted, read-only checks against validated artifacts."""

    def run(
        self,
        *,
        hypotheses: list[HypothesisRecord],
        artifact_ids: list[str],
    ) -> list[DiagnosticRecord]: ...


class RemediationService(Protocol):
    """Propose and apply operations from the constrained remediation DSL."""

    def propose(
        self,
        *,
        incident_summary: str,
        verification: VerificationRecord,
        evidence: list[EvidenceRecord],
        diagnostics: list[DiagnosticRecord],
    ) -> RemediationRecord: ...

    def apply(
        self,
        *,
        case_id: str,
        proposal: RemediationRecord,
        approval: ApprovalRecord,
    ) -> RemediationResult: ...


class ApprovalBindingService(Protocol):
    """Issue and atomically consume cryptographically bound approvals."""

    def issue(
        self,
        *,
        case_id: str,
        proposal_hash: str,
        plan_hash: str,
        source_hash: str,
    ) -> ApprovalRequestRecord: ...

    def validate_and_consume(
        self,
        *,
        request: ApprovalRequestRecord,
        decision: ApprovalDecisionRecord,
        current_proposal_hash: str,
        current_plan_hash: str,
        current_source_hash: str,
    ) -> ApprovalRecord: ...


@dataclass(frozen=True, slots=True)
class WorkflowServices:
    """Concrete services injected into a compiled workflow."""

    retrieval: RetrievalService
    reasoning: ReasoningService
    diagnostics: DiagnosticService
    remediation: RemediationService
    approval: ApprovalBindingService
