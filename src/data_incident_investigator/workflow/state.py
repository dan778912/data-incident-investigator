"""JSON-safe state contracts for the investigation workflow."""

from __future__ import annotations

from operator import add
from typing import Annotated, Literal, NotRequired, Required, TypedDict

type JSONScalar = str | int | float | bool | None
type JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class InvestigationInput(TypedDict):
    """Only fields accepted from an API caller when starting an investigation."""

    case_id: str
    incident_summary: str
    artifact_ids: list[str]


class EvidenceRecord(TypedDict):
    """A cited, untrusted excerpt returned by the retrieval service."""

    evidence_id: str
    source: str
    excerpt: str
    relevance_score: float


class EvidenceAssessment(TypedDict):
    """The reasoner's determination about retrieval completeness."""

    sufficient: bool
    reason: str


class HypothesisRecord(TypedDict):
    """A falsifiable root-cause hypothesis and its diagnostic check."""

    hypothesis_id: str
    statement: str
    diagnostic_action: str
    expected_signal: str


class DiagnosticRecord(TypedDict):
    """A result produced by an allowlisted diagnostic implementation."""

    hypothesis_id: str
    action: str
    observed_signal: str
    supports_hypothesis: bool


class VerificationRecord(TypedDict):
    """The reasoner's verdict after comparing hypotheses with observations."""

    confirmed: bool
    root_cause_id: str | None
    reason: str


class PatchOperation(TypedDict):
    """One operation in the non-executable remediation DSL."""

    operation: Literal[
        "rename_column",
        "cast_column",
        "fill_missing",
        "drop_duplicates",
        "parse_datetime",
        "normalize_string",
        "replace_values",
    ]
    arguments: dict[str, JSONValue]


class RemediationRecord(TypedDict):
    """A remediation proposal that is safe to show at an approval boundary."""

    proposal_id: str
    title: str
    explanation: str
    operations: list[PatchOperation]
    source_artifact_id: NotRequired[str]
    source_sha256: NotRequired[str]
    expected_effects: NotRequired[list[str]]
    required_post_checks: NotRequired[list[str]]
    citation_ids: NotRequired[list[str]]
    plan_hash: NotRequired[str]


class ApprovalRequestRecord(TypedDict):
    """Signed, single-use context shown at the approval boundary."""

    binding_version: Literal["v1"]
    case_id: str
    proposal_hash: str
    plan_hash: str
    source_hash: str
    nonce: str
    issued_at: int
    expires_at: int
    binding_mac: str


class ApprovalDecisionRecord(ApprovalRequestRecord):
    """Human decision plus an exact echo of the signed approval context."""

    approved: bool
    note: str | None


class ApprovalRecord(ApprovalDecisionRecord):
    """A verified and atomically consumed approval decision."""

    decided_at: int


class RemediationResult(TypedDict):
    """The result of applying a proposal to a working copy."""

    applied: bool
    message: str
    output_artifact_id: str | None


class TraceEvent(TypedDict):
    """A deterministic workflow event suitable for evaluation evidence."""

    stage: str
    message: str
    details: dict[str, JSONValue]


class InvestigationState(TypedDict, total=False):
    """Checkpointed graph state.

    Uploaded bytes, dataframes, credentials, and executable objects are kept out
    of this schema. Nodes retain only validated identifiers and JSON-safe records.
    """

    case_id: Required[str]
    incident_summary: Required[str]
    artifact_ids: Required[list[str]]
    retrieval_query: str
    retrieval_round: int
    max_retrieval_rounds: int
    retrieval_assessment: EvidenceAssessment
    evidence: Annotated[list[EvidenceRecord], add]
    hypotheses: list[HypothesisRecord]
    plan_revision: int
    max_plan_revisions: int
    diagnostics: Annotated[list[DiagnosticRecord], add]
    verification: VerificationRecord
    remediation: RemediationRecord
    approval_request: ApprovalRequestRecord
    approval: ApprovalRecord
    remediation_result: RemediationResult
    status: Literal[
        "retrieving",
        "diagnosing",
        "awaiting_approval",
        "approved",
        "completed",
        "rejected",
        "unresolved",
    ]
    trace: Annotated[list[TraceEvent], add]
