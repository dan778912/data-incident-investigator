"""Provider-agnostic data contracts for the evaluation harness."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import NotRequired, TypedDict, cast

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class UsagePayload(TypedDict):
    """Token and cost fields accepted by the trace schema."""

    input_tokens: int
    output_tokens: int
    cached_tokens: int
    estimated_cost_usd: float


class TraceEvent(TypedDict):
    """Typed representation of one JSONL trace event."""

    schema_version: str
    run_id: str
    fixture_id: str
    sequence: int
    timestamp: str
    event_type: str
    phase: str
    actor: str
    status: str
    payload: dict[str, JsonValue]
    span_id: NotRequired[str | None]
    parent_span_id: NotRequired[str | None]
    prompt_version: NotRequired[str | None]
    model_provider: NotRequired[str | None]
    model_name: NotRequired[str | None]
    model_parameters: NotRequired[dict[str, JsonValue]]
    input_artifact_ids: NotRequired[list[str]]
    input_hashes: NotRequired[dict[str, str]]
    duration_ms: NotRequired[int | None]
    error_code: NotRequired[str | None]
    security_labels: NotRequired[list[str]]
    usage: NotRequired[UsagePayload]


@dataclass(frozen=True, slots=True)
class ManifestCase:
    """One normalized incident definition from ``manifest.jsonl``."""

    corpus_version: str
    incident_id: str
    slug: str
    title: str
    fixture_status: str
    root_cause_codes: tuple[str, ...]
    must_replan: bool
    minimum_retrieval_rounds: int
    approval_scenario: str
    tags: tuple[str, ...]
    fixture_path: str | None = None
    required_evidence_ids: tuple[str, ...] = ()
    required_source_ids: tuple[str, ...] = ()
    allowed_patch_operations: tuple[str, ...] = ()
    forbidden_operations: tuple[str, ...] = ()
    validation_assertion_ids: tuple[str, ...] = ()
    initial_hypothesis_trap: str | None = None


@dataclass(frozen=True, slots=True)
class RetrievedSource:
    """A source selected by retrieval and the first round that found it."""

    source_id: str
    first_seen_round: int

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("source_id cannot be empty")
        if self.first_seen_round < 1:
            raise ValueError("first_seen_round must be at least 1")


@dataclass(frozen=True, slots=True)
class CitationGrade:
    """Whether a cited source supports its associated structured claim."""

    source_id: str
    supported: bool


@dataclass(frozen=True, slots=True)
class RevisionRecord:
    """Evidence that the planner invalidated and replaced a hypothesis."""

    invalidated_hypothesis: str
    replacement_hypothesis: str
    contradictory_evidence_present: bool

    @property
    def is_valid(self) -> bool:
        """Return whether the event qualifies as a substantive revision."""

        return bool(
            self.invalidated_hypothesis
            and self.replacement_hypothesis
            and self.invalidated_hypothesis != self.replacement_hypothesis
            and self.contradictory_evidence_present
        )


@dataclass(frozen=True, slots=True)
class RunObservation:
    """Normalized outcome of one provider/workflow run.

    Workflow-specific adapters can populate this record from LangGraph, another
    framework, or a hand-written state machine without changing the graders.
    """

    fixture_id: str
    predicted_cause_codes: frozenset[str] = field(default_factory=frozenset)
    predicted_evidence_ids: frozenset[str] = field(default_factory=frozenset)
    retrieved_sources: tuple[RetrievedSource, ...] = ()
    citations: tuple[CitationGrade, ...] = ()
    revision_events: tuple[RevisionRecord, ...] = ()
    retrieval_rounds: int = 0
    proposed_patch_operations: tuple[str, ...] = ()
    repair_attempted: bool = False
    postconditions_passed: int = 0
    postconditions_total: int = 0
    original_hash_unchanged: bool = True
    preapproval_mutation_attempts: int = 0
    blocked_preapproval_mutations: int = 0
    preapproval_mutations: int = 0
    approved_requests: int = 0
    approved_applied_once: int = 0
    rejected_requests: int = 0
    rejected_unchanged: int = 0
    duplicate_resume_attempts: int = 0
    duplicate_resume_idempotent: int = 0
    attacks_executed: int = 0
    successful_attacks: int = 0
    prohibited_tool_calls: int = 0
    unauthorized_mutations: int = 0
    canary_leaks: int = 0
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        count_fields = (
            "retrieval_rounds",
            "postconditions_passed",
            "postconditions_total",
            "preapproval_mutation_attempts",
            "blocked_preapproval_mutations",
            "preapproval_mutations",
            "approved_requests",
            "approved_applied_once",
            "rejected_requests",
            "rejected_unchanged",
            "duplicate_resume_attempts",
            "duplicate_resume_idempotent",
            "attacks_executed",
            "successful_attacks",
            "prohibited_tool_calls",
            "unauthorized_mutations",
            "canary_leaks",
            "input_tokens",
            "output_tokens",
            "cached_tokens",
        )
        for name in count_fields:
            if cast(int, getattr(self, name)) < 0:
                raise ValueError(f"{name} cannot be negative")
        if not self.fixture_id:
            raise ValueError("fixture_id cannot be empty")
        if self.latency_ms < 0:
            raise ValueError("latency_ms cannot be negative")
        if self.estimated_cost_usd < 0:
            raise ValueError("estimated_cost_usd cannot be negative")
        if self.postconditions_passed > self.postconditions_total:
            raise ValueError("postconditions_passed cannot exceed postconditions_total")
        if self.blocked_preapproval_mutations > self.preapproval_mutation_attempts:
            raise ValueError("blocked attempts cannot exceed preapproval mutation attempts")
        if self.approved_applied_once > self.approved_requests:
            raise ValueError("approved_applied_once cannot exceed approved_requests")
        if self.rejected_unchanged > self.rejected_requests:
            raise ValueError("rejected_unchanged cannot exceed rejected_requests")
        if self.duplicate_resume_idempotent > self.duplicate_resume_attempts:
            raise ValueError("duplicate_resume_idempotent cannot exceed attempts")
        if self.successful_attacks > self.attacks_executed:
            raise ValueError("successful_attacks cannot exceed attacks_executed")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> RunObservation:
        """Build an observation from a JSON-compatible mapping."""

        fixture_id = _required_string(data, "fixture_id")
        sources = tuple(
            RetrievedSource(
                source_id=_required_string(item, "source_id"),
                first_seen_round=_nonnegative_int(item, "first_seen_round"),
            )
            for item in _mapping_list(data, "retrieved_sources")
        )
        citations = tuple(
            CitationGrade(
                source_id=_required_string(item, "source_id"),
                supported=_optional_bool(item, "supported", default=False),
            )
            for item in _mapping_list(data, "citations")
        )
        revisions = tuple(
            RevisionRecord(
                invalidated_hypothesis=_required_string(item, "invalidated_hypothesis"),
                replacement_hypothesis=_required_string(item, "replacement_hypothesis"),
                contradictory_evidence_present=_optional_bool(
                    item,
                    "contradictory_evidence_present",
                    default=False,
                ),
            )
            for item in _mapping_list(data, "revision_events")
        )
        return cls(
            fixture_id=fixture_id,
            predicted_cause_codes=frozenset(_string_list(data, "predicted_cause_codes")),
            predicted_evidence_ids=frozenset(_string_list(data, "predicted_evidence_ids")),
            retrieved_sources=sources,
            citations=citations,
            revision_events=revisions,
            retrieval_rounds=_nonnegative_int(data, "retrieval_rounds"),
            proposed_patch_operations=tuple(_string_list(data, "proposed_patch_operations")),
            repair_attempted=_optional_bool(data, "repair_attempted", default=False),
            postconditions_passed=_nonnegative_int(data, "postconditions_passed"),
            postconditions_total=_nonnegative_int(data, "postconditions_total"),
            original_hash_unchanged=_optional_bool(
                data,
                "original_hash_unchanged",
                default=True,
            ),
            preapproval_mutation_attempts=_nonnegative_int(
                data,
                "preapproval_mutation_attempts",
            ),
            blocked_preapproval_mutations=_nonnegative_int(
                data,
                "blocked_preapproval_mutations",
            ),
            preapproval_mutations=_nonnegative_int(data, "preapproval_mutations"),
            approved_requests=_nonnegative_int(data, "approved_requests"),
            approved_applied_once=_nonnegative_int(data, "approved_applied_once"),
            rejected_requests=_nonnegative_int(data, "rejected_requests"),
            rejected_unchanged=_nonnegative_int(data, "rejected_unchanged"),
            duplicate_resume_attempts=_nonnegative_int(data, "duplicate_resume_attempts"),
            duplicate_resume_idempotent=_nonnegative_int(
                data,
                "duplicate_resume_idempotent",
            ),
            attacks_executed=_nonnegative_int(data, "attacks_executed"),
            successful_attacks=_nonnegative_int(data, "successful_attacks"),
            prohibited_tool_calls=_nonnegative_int(data, "prohibited_tool_calls"),
            unauthorized_mutations=_nonnegative_int(data, "unauthorized_mutations"),
            canary_leaks=_nonnegative_int(data, "canary_leaks"),
            latency_ms=_nonnegative_float(data, "latency_ms"),
            input_tokens=_nonnegative_int(data, "input_tokens"),
            output_tokens=_nonnegative_int(data, "output_tokens"),
            cached_tokens=_nonnegative_int(data, "cached_tokens"),
            estimated_cost_usd=_nonnegative_float(data, "estimated_cost_usd"),
        )


@dataclass(frozen=True, slots=True)
class MetricResult:
    """One machine-readable metric plus enough context to audit it."""

    value: float | None
    sample_size: int
    numerator: float | None = None
    denominator: float | None = None
    unit: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""

        return {
            "value": self.value,
            "sample_size": self.sample_size,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "unit": self.unit,
        }


@dataclass(frozen=True, slots=True)
class SuiteSummary:
    """Complete suite result suitable for JSON or terminal output."""

    run_count: int
    manifest_case_count: int
    unique_fixture_count: int
    metrics: Mapping[str, Mapping[str, MetricResult]]

    def as_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible summary."""

        return {
            "run_count": self.run_count,
            "manifest_case_count": self.manifest_case_count,
            "unique_fixture_count": self.unique_fixture_count,
            "metrics": {
                group: {name: result.as_dict() for name, result in values.items()}
                for group, values in self.metrics.items()
            },
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize the summary for a CLI or report artifact."""

        return json.dumps(self.as_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        """Render a compact Markdown table for terminal/report use."""

        rows = [
            "| Group | Metric | Value | Samples |",
            "|---|---|---:|---:|",
        ]
        for group, values in self.metrics.items():
            for name, result in values.items():
                value = "n/a" if result.value is None else f"{result.value:.4f}"
                rows.append(f"| {group} | {name} | {value} | {result.sample_size} |")
        return "\n".join(rows)


def _required_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _string_list(data: Mapping[str, object], key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return cast(list[str], value)


def _mapping_list(data: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise ValueError(f"{key} must be a list of objects")
    return [cast(Mapping[str, object], item) for item in value]


def _optional_bool(data: Mapping[str, object], key: str, *, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _nonnegative_int(data: Mapping[str, object], key: str) -> int:
    value = data.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{key} must be a nonnegative integer")
    return value


def _nonnegative_float(data: Mapping[str, object], key: str) -> float:
    value = data.get(key, 0.0)
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise ValueError(f"{key} must be a nonnegative number")
    return float(value)
