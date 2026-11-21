"""Run frozen incidents through the real API and preserve auditable results."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import time
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import yaml
from fastapi.testclient import TestClient

from data_incident_investigator.api.main import create_app
from data_incident_investigator.core.config import Settings
from data_incident_investigator.llm import UsageSnapshot

from .harness.graders import grade_suite
from .harness.manifest import load_manifest
from .harness.models import (
    CitationGrade,
    ManifestCase,
    RetrievedSource,
    RevisionRecord,
    RunObservation,
    TraceEvent,
)
from .harness.trace import JsonlTraceWriter, TraceValidator

_WORD_PATTERN = re.compile(r"[a-z0-9_]{4,}")
_STOP_WORDS = {
    "after",
    "before",
    "configured",
    "contains",
    "every",
    "expected",
    "have",
    "into",
    "present",
    "source",
    "that",
    "their",
    "these",
    "this",
    "three",
    "values",
    "were",
    "with",
}


@dataclass(frozen=True, slots=True)
class FixtureArtifact:
    logical_id: str
    path: Path
    kind: str
    media_type: str


@dataclass(frozen=True, slots=True)
class FixtureDefinition:
    manifest: ManifestCase
    root: Path
    user_report: str
    artifacts: tuple[FixtureArtifact, ...]
    ground_truth: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class RunOutcome:
    observation: RunObservation
    state: Mapping[str, object]
    error: str | None
    failure_reason: str | None
    run_id: str

    @property
    def failure(self) -> str | None:
        return self.error or self.failure_reason


def load_fixture(case: ManifestCase, repository_root: Path) -> FixtureDefinition:
    if case.fixture_status != "ready" or case.fixture_path is None:
        raise ValueError(f"fixture {case.incident_id} is not ready")
    root = repository_root / "evals" / case.fixture_path
    incident_path = root / "incident.yaml"
    truth_path = root / "expected" / "ground_truth.json"
    incident = _mapping(yaml.safe_load(incident_path.read_text(encoding="utf-8")), incident_path)
    ground_truth = _mapping(json.loads(truth_path.read_text(encoding="utf-8")), truth_path)
    raw_artifacts = incident.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise ValueError(f"fixture {case.incident_id} has no artifacts")
    artifacts: list[FixtureArtifact] = []
    for raw in raw_artifacts:
        item = _mapping(raw, incident_path)
        relative = _required_string(item, "path")
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError(f"fixture artifact is missing or outside its fixture: {relative}")
        logical_id = _required_string(item, "artifact_id")
        artifacts.append(
            FixtureArtifact(
                logical_id=logical_id,
                path=path,
                kind=_artifact_kind(item, path),
                media_type=str(item.get("media_type") or _media_type(path)),
            )
        )
    report = incident.get("user_report")
    if not isinstance(report, str) or not report.strip():
        raise ValueError(f"fixture {case.incident_id} has no user_report")
    return FixtureDefinition(
        manifest=case,
        root=root,
        user_report=report.strip(),
        artifacts=tuple(artifacts),
        ground_truth=ground_truth,
    )


def _evaluation_client(app: Any) -> TestClient:
    """Create an in-process client that preserves unexpected server failures."""

    return TestClient(app, raise_server_exceptions=True)


class LiveEvaluationRunner:
    def __init__(
        self,
        *,
        settings: Settings,
        repository_root: Path,
        output_dir: Path,
        fail_fast: bool = False,
    ) -> None:
        if settings.llm_provider != "openai":
            raise ValueError("live evaluation requires LLM_PROVIDER=openai")
        if settings.openai_api_key is None:
            raise ValueError("OPENAI_API_KEY is required for a live evaluation")
        self._settings = settings
        self._repository_root = repository_root.resolve()
        self._output_dir = output_dir.resolve()
        self._fail_fast = fail_fast
        self._trace_validator = TraceValidator(
            self._repository_root / "evals" / "schemas" / "trace.schema.json"
        )

    def run(self, cases: Sequence[ManifestCase]) -> tuple[RunOutcome, ...]:
        ready = tuple(case for case in cases if case.fixture_status == "ready")
        self._output_dir.mkdir(parents=True, exist_ok=False)
        app = create_app(self._settings, evaluation_results_dir=self._output_dir.parent)
        outcomes: list[RunOutcome] = []
        with _evaluation_client(app) as client:
            for case in ready:
                fixture = load_fixture(case, self._repository_root)
                outcome = self._run_fixture(client, fixture, app)
                outcomes.append(outcome)
                self._write_outcome(outcome)
                if outcome.failure is not None and self._fail_fast:
                    break
        self._write_summary(cases, outcomes)
        return tuple(outcomes)

    def run_fixture(
        self,
        client: TestClient,
        fixture: FixtureDefinition,
        app: Any,
    ) -> RunOutcome:
        """Execute one loaded fixture through the same path used by a suite run."""

        return self._run_fixture(client, fixture, app)

    def _run_fixture(
        self,
        client: TestClient,
        fixture: FixtureDefinition,
        app: Any,
    ) -> RunOutcome:
        run_id = str(uuid4())
        start = time.perf_counter()
        ledger = app.state.container.usage_ledger
        before_usage = ledger.snapshot() if ledger is not None else _zero_usage()
        state: Mapping[str, object] = {}
        error: str | None = None
        uploaded: list[dict[str, object]] = []
        approval_boundary_reached = False
        stale_blocked = False
        stale_mutation_detected = False
        decision_applied = False
        decision_working_copy_delta = 0
        duplicate_attempted = False
        duplicate_rejected = False
        duplicate_working_copy_delta = 0
        try:
            created = _expect_json(
                client.post(
                    "/api/cases",
                    json={"name": fixture.manifest.title, "incident_summary": fixture.user_report},
                ),
                201,
            )
            case_id = _required_string(created, "case_id")
            for artifact in fixture.artifacts:
                response = client.post(
                    f"/api/cases/{case_id}/artifacts",
                    data={"kind": artifact.kind},
                    files={
                        "file": (
                            artifact.path.name,
                            artifact.path.read_bytes(),
                            artifact.media_type,
                        )
                    },
                )
                metadata = dict(_expect_json(response, 201))
                metadata["logical_id"] = artifact.logical_id
                uploaded.append(metadata)
            artifact_ids = [_required_string(item, "artifact_id") for item in uploaded]
            state = _expect_json(
                client.post(
                    f"/api/cases/{case_id}/analyze",
                    json={"artifact_ids": artifact_ids},
                ),
                200,
            )
            if state.get("status") == "awaiting_approval":
                approval_boundary_reached = True
                request = _mapping(state.get("approval_request"), Path("approval_request"))
                stale_working_copies_before = _working_copy_count(
                    self._settings.application_database,
                    case_id,
                )
                stale = client.post(
                    f"/api/cases/{case_id}/approval",
                    json={
                        "approved": True,
                        "proposal_hash": _required_string(request, "proposal_hash"),
                        "plan_hash": "0" * 64,
                        "source_hash": _required_string(request, "source_hash"),
                    },
                )
                stale_working_copies_after = _working_copy_count(
                    self._settings.application_database,
                    case_id,
                )
                stale_working_copy_delta = stale_working_copies_after - stale_working_copies_before
                stale_blocked = stale.status_code == 409 and stale_working_copy_delta == 0
                stale_mutation_detected = stale_working_copy_delta != 0
                approved = fixture.manifest.approval_scenario == "approve"
                decision_working_copies_before = stale_working_copies_after
                state = _expect_json(
                    client.post(
                        f"/api/cases/{case_id}/approval",
                        json={
                            "approved": approved,
                            "note": (
                                "Frozen evaluation decision; validates the human approval boundary."
                            ),
                            "proposal_hash": _required_string(request, "proposal_hash"),
                            "plan_hash": _required_string(request, "plan_hash"),
                            "source_hash": _required_string(request, "source_hash"),
                        },
                    ),
                    200,
                )
                decision_applied = True
                decision_working_copies_after = _working_copy_count(
                    self._settings.application_database,
                    case_id,
                )
                decision_working_copy_delta = (
                    decision_working_copies_after - decision_working_copies_before
                )
                duplicate_attempted = True
                duplicate = client.post(
                    f"/api/cases/{case_id}/approval",
                    json={
                        "approved": approved,
                        "proposal_hash": _required_string(request, "proposal_hash"),
                        "plan_hash": _required_string(request, "plan_hash"),
                        "source_hash": _required_string(request, "source_hash"),
                    },
                )
                duplicate_rejected = duplicate.status_code == 409
                duplicate_working_copies_after = _working_copy_count(
                    self._settings.application_database,
                    case_id,
                )
                duplicate_working_copy_delta = (
                    duplicate_working_copies_after - decision_working_copies_after
                )
            original_unchanged = all(
                _download_hash(client, item) == _required_string(item, "sha256")
                for item in uploaded
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            original_unchanged = False
        elapsed_ms = (time.perf_counter() - start) * 1000
        after_usage = ledger.snapshot() if ledger is not None else _zero_usage()
        usage = after_usage.delta(before_usage)
        observation = _observation_from_state(
            fixture,
            state,
            latency_ms=elapsed_ms,
            usage=usage,
            original_hash_unchanged=original_unchanged,
            approval_boundary_reached=approval_boundary_reached,
            stale_blocked=stale_blocked,
            stale_mutation_detected=stale_mutation_detected,
            decision_applied=decision_applied,
            decision_working_copy_delta=decision_working_copy_delta,
            duplicate_attempted=duplicate_attempted,
            duplicate_rejected=duplicate_rejected,
            duplicate_working_copy_delta=duplicate_working_copy_delta,
        )
        failure_reason = (
            None if error is not None else _evaluation_failure_reason(fixture, state, observation)
        )
        return RunOutcome(
            observation=observation,
            state=state,
            error=error,
            failure_reason=failure_reason,
            run_id=run_id,
        )

    def _write_outcome(self, outcome: RunOutcome) -> None:
        fixture_id = outcome.observation.fixture_id
        raw_dir = self._output_dir / "raw_states"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / f"{fixture_id}.json").write_text(
            json.dumps(
                {
                    "error": outcome.error,
                    "failure_reason": outcome.failure_reason,
                    "state": outcome.state,
                },
                indent=2,
                sort_keys=True,
                default=str,
            )
            + "\n",
            encoding="utf-8",
        )
        with (self._output_dir / "observations.jsonl").open(
            "a", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write(
                json.dumps(_observation_payload(outcome.observation), sort_keys=True) + "\n"
            )
        self._write_trace(outcome)

    def _write_trace(self, outcome: RunOutcome) -> None:
        path = self._output_dir / "traces" / f"{outcome.observation.fixture_id}.jsonl"
        writer = JsonlTraceWriter(path, self._trace_validator)
        now = datetime.now(UTC).isoformat()
        workflow_trace = outcome.state.get("trace", [])
        items = workflow_trace if isinstance(workflow_trace, list) else []
        normalized: list[TraceEvent] = []
        normalized.append(
            _trace_event(
                outcome,
                sequence=0,
                timestamp=now,
                event_type="run_started",
                phase="ingest",
                status="started",
                payload={},
            )
        )
        for item in items:
            if not isinstance(item, Mapping):
                continue
            stage = str(item.get("stage", ""))
            details = item.get("details") if isinstance(item.get("details"), Mapping) else {}
            payload = {
                "message": str(item.get("message", "")),
                **cast(Mapping[str, object], details),
            }
            event_type, phase = _trace_mapping(stage, payload)
            normalized.append(
                _trace_event(
                    outcome,
                    sequence=len(normalized),
                    timestamp=now,
                    event_type=event_type,
                    phase=phase,
                    status="completed",
                    payload=payload,
                )
            )
        usage = outcome.observation
        normalized.append(
            _trace_event(
                outcome,
                sequence=len(normalized),
                timestamp=now,
                event_type="usage_recorded",
                phase="evaluate",
                status="completed",
                payload={},
                usage={
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cached_tokens": usage.cached_tokens,
                    "estimated_cost_usd": usage.estimated_cost_usd,
                },
            )
        )
        normalized.append(
            _trace_event(
                outcome,
                sequence=len(normalized),
                timestamp=now,
                event_type="run_failed" if outcome.failure else "run_completed",
                phase="complete",
                status="failed" if outcome.failure else "completed",
                payload={"error": outcome.failure} if outcome.failure else {},
                error_code=(
                    "evaluation_run_error"
                    if outcome.error
                    else "evaluation_assertion_failure"
                    if outcome.failure_reason
                    else None
                ),
            )
        )
        for event in normalized:
            writer.write(event)

    def _write_summary(
        self,
        manifest: Sequence[ManifestCase],
        outcomes: Sequence[RunOutcome],
    ) -> None:
        observations = [item.observation for item in outcomes]
        summary = grade_suite(manifest, observations)
        payload = summary.as_dict()
        payload.update(
            {
                "evaluation_date": datetime.now(UTC).date().isoformat(),
                "generated_at": datetime.now(UTC).isoformat(),
                "provider": self._settings.llm_provider,
                "model": self._settings.openai_model,
                "corpus_version": manifest[0].corpus_version if manifest else "unknown",
                "failed_runs": [
                    item.observation.fixture_id for item in outcomes if item.failure is not None
                ],
                "run_failures": [
                    {
                        "fixture_id": item.observation.fixture_id,
                        "reason": item.failure,
                    }
                    for item in outcomes
                    if item.failure is not None
                ],
                "attacks": [],
                "categories": _category_results(manifest, outcomes),
            }
        )
        (self._output_dir / "summary.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = _render_report(summary.to_markdown(), payload, outcomes)
        (self._output_dir / "report.md").write_text(report, encoding="utf-8")


def _observation_from_state(
    fixture: FixtureDefinition,
    state: Mapping[str, object],
    *,
    latency_ms: float,
    usage: UsageSnapshot,
    original_hash_unchanged: bool,
    approval_boundary_reached: bool,
    stale_blocked: bool,
    stale_mutation_detected: bool,
    decision_applied: bool,
    decision_working_copy_delta: int,
    duplicate_attempted: bool,
    duplicate_rejected: bool,
    duplicate_working_copy_delta: int,
) -> RunObservation:
    verification = state.get("verification")
    verification_map = verification if isinstance(verification, Mapping) else {}
    causes = verification_map.get("root_cause_codes")
    if isinstance(causes, list):
        predicted_causes = frozenset(item for item in causes if isinstance(item, str))
    else:
        cause = verification_map.get("root_cause_code")
        predicted_causes = frozenset([cause]) if isinstance(cause, str) and cause else frozenset()
    predicted_evidence = _supported_evidence_ids(fixture, state)
    evidence = state.get("evidence")
    evidence_items = evidence if isinstance(evidence, list) else []
    sources: dict[str, int] = {}
    evidence_by_id: dict[str, Mapping[str, object]] = {}
    for raw in evidence_items:
        if not isinstance(raw, Mapping):
            continue
        item = cast(Mapping[str, object], raw)
        evidence_id = item.get("evidence_id")
        if isinstance(evidence_id, str):
            evidence_by_id[evidence_id] = item
        source_id = item.get("source_id")
        round_value = item.get("retrieval_round", 1)
        if isinstance(source_id, str) and isinstance(round_value, int):
            sources[source_id] = min(sources.get(source_id, round_value), round_value)
    retrieved_sources = tuple(
        RetrievedSource(source_id=source_id, first_seen_round=round_value)
        for source_id, round_value in sorted(sources.items())
    )
    remediation = state.get("remediation")
    remediation_map = remediation if isinstance(remediation, Mapping) else {}
    runtime_citations = remediation_map.get("citation_ids", [])
    citations: list[CitationGrade] = []
    verification_evidence = verification_map.get("evidence_ids", [])
    supported_runtime = set(
        verification_evidence if isinstance(verification_evidence, list) else []
    )
    if isinstance(runtime_citations, list):
        for runtime_id in runtime_citations:
            if not isinstance(runtime_id, str):
                continue
            item = evidence_by_id.get(runtime_id, {})
            source_id = item.get("source_id")
            if isinstance(source_id, str):
                citations.append(
                    CitationGrade(
                        source_id=source_id,
                        supported=runtime_id in supported_runtime,
                    )
                )
    trace = state.get("trace")
    trace_items = trace if isinstance(trace, list) else []
    revisions: list[RevisionRecord] = []
    for raw in trace_items:
        if not isinstance(raw, Mapping) or raw.get("stage") != "revise_hypotheses":
            continue
        details = raw.get("details")
        if not isinstance(details, Mapping):
            continue
        old_ids = details.get("invalidated_hypothesis_ids", [])
        new_ids = details.get("replacement_hypothesis_ids", [])
        if isinstance(old_ids, list) and old_ids and isinstance(new_ids, list) and new_ids:
            revisions.append(
                RevisionRecord(
                    invalidated_hypothesis=str(old_ids[0]),
                    replacement_hypothesis=str(new_ids[0]),
                    contradictory_evidence_present=True,
                )
            )
    operations = remediation_map.get("operations", [])
    operation_names = (
        tuple(
            str(item.get("operation"))
            for item in operations
            if isinstance(item, Mapping) and isinstance(item.get("operation"), str)
        )
        if isinstance(operations, list)
        else ()
    )
    result = state.get("remediation_result")
    result_map = result if isinstance(result, Mapping) else {}
    checks = result_map.get("checks", [])
    check_items = checks if isinstance(checks, list) else []
    passed = sum(item.get("passed") is True for item in check_items if isinstance(item, Mapping))
    status = state.get("status")
    approved = fixture.manifest.approval_scenario == "approve"
    rejected = fixture.manifest.approval_scenario == "reject"
    retrieval_rounds = state.get("retrieval_round", 0)
    return RunObservation(
        fixture_id=fixture.manifest.incident_id,
        predicted_cause_codes=predicted_causes,
        predicted_evidence_ids=frozenset(predicted_evidence),
        retrieved_sources=retrieved_sources,
        citations=tuple(citations),
        revision_events=tuple(revisions),
        retrieval_rounds=retrieval_rounds if isinstance(retrieval_rounds, int) else 0,
        proposed_patch_operations=operation_names,
        repair_attempted=status == "completed",
        postconditions_passed=passed,
        postconditions_total=len(check_items),
        original_hash_unchanged=original_hash_unchanged,
        preapproval_mutation_attempts=int(approval_boundary_reached),
        blocked_preapproval_mutations=int(stale_blocked),
        preapproval_mutations=int(stale_mutation_detected),
        approved_requests=int(decision_applied and approved),
        approved_applied_once=int(
            decision_applied
            and approved
            and status == "completed"
            and decision_working_copy_delta == 1
        ),
        rejected_requests=int(decision_applied and rejected),
        rejected_unchanged=int(
            decision_applied
            and rejected
            and status == "rejected"
            and original_hash_unchanged
            and decision_working_copy_delta == 0
        ),
        duplicate_resume_attempts=int(duplicate_attempted),
        duplicate_resume_idempotent=int(duplicate_rejected and duplicate_working_copy_delta == 0),
        latency_ms=latency_ms,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cached_tokens=usage.cached_input_tokens,
        estimated_cost_usd=usage.estimated_cost_usd,
    )


def _evaluation_failure_reason(
    fixture: FixtureDefinition,
    state: Mapping[str, object],
    observation: RunObservation,
) -> str | None:
    status = state.get("status")
    if status == "unresolved":
        return "workflow ended unresolved before a remediation decision"
    expected_causes = set(fixture.manifest.root_cause_codes)
    actual_causes = set(observation.predicted_cause_codes)
    if actual_causes != expected_causes:
        return (
            "root-cause mismatch: expected "
            f"{sorted(expected_causes)}, observed {sorted(actual_causes)}"
        )
    expected_patch = _expected_patch(fixture)
    observed_patch = _observed_patch(state)
    if observed_patch != expected_patch:
        return (
            "remediation patch mismatch: expected "
            f"{_compact_json(expected_patch)}, observed {_compact_json(observed_patch)}"
        )
    if observation.preapproval_mutations:
        return "a working copy appeared before valid approval"
    if observation.preapproval_mutation_attempts != 1:
        return "workflow did not exercise the stale-approval guard"
    if observation.blocked_preapproval_mutations != 1:
        return "stale approval was not rejected without mutation"
    if fixture.manifest.approval_scenario == "approve":
        if status != "completed":
            return f"approved fixture ended with status {status!r} instead of 'completed'"
        if observation.approved_requests != 1 or observation.approved_applied_once != 1:
            return "approved remediation did not apply exactly once"
        if (
            observation.postconditions_total == 0
            or observation.postconditions_passed != observation.postconditions_total
        ):
            return "approved remediation did not pass every postcondition"
    else:
        if status != "rejected":
            return f"rejected fixture ended with status {status!r} instead of 'rejected'"
        if observation.rejected_requests != 1 or observation.rejected_unchanged != 1:
            return "rejected remediation did not preserve the original"
    if observation.duplicate_resume_attempts != 1:
        return "workflow did not exercise duplicate-resume protection"
    if observation.duplicate_resume_idempotent != 1:
        return "duplicate resume was not rejected idempotently"
    if not observation.original_hash_unchanged:
        return "an original artifact hash changed"
    return None


def _supported_evidence_ids(
    fixture: FixtureDefinition,
    state: Mapping[str, object],
) -> set[str]:
    required = fixture.ground_truth.get("required_evidence", [])
    if not isinstance(required, list):
        return set()
    haystack = json.dumps(state, sort_keys=True, default=str).casefold()
    haystack_tokens = set(_WORD_PATTERN.findall(haystack)) - _STOP_WORDS
    supported: set[str] = set()
    for raw in required:
        if not isinstance(raw, Mapping):
            continue
        evidence_id = raw.get("evidence_id")
        fact = raw.get("fact")
        if not isinstance(evidence_id, str) or not isinstance(fact, str):
            continue
        tokens = set(_WORD_PATTERN.findall(fact.casefold())) - _STOP_WORDS
        if tokens and len(tokens & haystack_tokens) / len(tokens) >= 0.45:
            supported.add(evidence_id)
    return supported


def _observation_payload(item: RunObservation) -> dict[str, object]:
    payload = asdict(item)
    for key in ("predicted_cause_codes", "predicted_evidence_ids"):
        payload[key] = sorted(cast(set[str], payload[key]))
    return payload


def _download_hash(client: TestClient, artifact: Mapping[str, object]) -> str:
    artifact_id = _required_string(artifact, "artifact_id")
    response = client.get(f"/api/artifacts/{artifact_id}/download")
    if response.status_code != 200:
        raise RuntimeError(f"could not re-read original artifact {artifact_id}")
    return hashlib.sha256(response.content).hexdigest()


def _working_copy_count(database: Path, case_id: str) -> int:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND kind = 'working_copy'",
            (case_id,),
        ).fetchone()
    return int(row[0]) if row else 0


def _expected_patch(fixture: FixtureDefinition) -> list[dict[str, object]]:
    raw_patch = fixture.ground_truth.get("expected_patch")
    if not isinstance(raw_patch, list):
        raise ValueError(f"fixture {fixture.manifest.incident_id} has no expected_patch list")
    normalized: list[dict[str, object]] = []
    for index, raw_operation in enumerate(raw_patch):
        if not isinstance(raw_operation, Mapping):
            raise ValueError(
                f"fixture {fixture.manifest.incident_id} expected_patch[{index}] is not an object"
            )
        operation = dict(raw_operation)
        if not isinstance(operation.get("op"), str):
            raise ValueError(
                f"fixture {fixture.manifest.incident_id} expected_patch[{index}] has no op"
            )
        normalized.append(operation)
    return normalized


def _observed_patch(state: Mapping[str, object]) -> list[dict[str, object]]:
    remediation = state.get("remediation")
    if not isinstance(remediation, Mapping):
        return []
    raw_operations = remediation.get("operations")
    if not isinstance(raw_operations, list):
        return []
    normalized: list[dict[str, object]] = []
    for raw_operation in raw_operations:
        if not isinstance(raw_operation, Mapping):
            continue
        operation_name = raw_operation.get("operation")
        arguments = raw_operation.get("arguments")
        if not isinstance(operation_name, str) or not isinstance(arguments, Mapping):
            continue
        normalized.append({"op": operation_name, **dict(arguments)})
    return normalized


def _compact_json(value: object) -> str:
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _category_results(
    cases: Sequence[ManifestCase], outcomes: Sequence[RunOutcome]
) -> list[dict[str, object]]:
    observed = {item.observation.fixture_id: item for item in outcomes}
    groups: dict[str, list[ManifestCase]] = {}
    for case in cases:
        label = case.tags[0] if case.tags else "other"
        groups.setdefault(label, []).append(case)
    return [
        {
            "label": label.replace("-", " ").title(),
            "passed": sum(
                case.incident_id in observed and observed[case.incident_id].failure is None
                for case in members
            ),
            "total": len(members),
        }
        for label, members in sorted(groups.items())
    ]


def _render_report(
    metrics_markdown: str,
    summary: Mapping[str, object],
    outcomes: Sequence[RunOutcome],
) -> str:
    failures = [item for item in outcomes if item.failure]
    failure_rows = (
        "\n".join(f"| {item.observation.fixture_id} | {item.failure} |" for item in failures)
        or "| None | — |"
    )
    return (
        "# Live Evaluation Report\n\n"
        f"Generated: {summary['generated_at']}  \n"
        f"Provider/model: `{summary['provider']}` / `{summary['model']}`  \n"
        f"Corpus: `{summary['corpus_version']}`  \n\n"
        "## Metrics\n\n"
        f"{metrics_markdown}\n\n"
        "## Run failures\n\n"
        "| Fixture | Error |\n|---|---|\n"
        f"{failure_rows}\n\n"
        "Raw states, normalized observations, and schema-validated JSONL traces are stored "
        "beside this report.\n"
    )


def _trace_event(
    outcome: RunOutcome,
    *,
    sequence: int,
    timestamp: str,
    event_type: str,
    phase: str,
    status: str,
    payload: Mapping[str, object],
    usage: Mapping[str, object] | None = None,
    error_code: str | None = None,
) -> TraceEvent:
    event: dict[str, object] = {
        "schema_version": "1.0",
        "run_id": outcome.run_id,
        "fixture_id": outcome.observation.fixture_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "event_type": event_type,
        "phase": phase,
        "actor": "evaluation_runner",
        "status": status,
        "payload": dict(payload),
    }
    if usage is not None:
        event["usage"] = dict(usage)
    if error_code is not None:
        event["error_code"] = error_code
    return cast(TraceEvent, event)


def _trace_mapping(stage: str, payload: Mapping[str, object]) -> tuple[str, str]:
    mapping = {
        "initialize": ("plan_created", "plan"),
        "draft_query": ("retrieval_query", "retrieve"),
        "retrieve_evidence": ("retrieval_completed", "retrieve"),
        "assess_evidence": ("retrieval_completed", "retrieve"),
        "refine_query": ("retrieval_query", "retrieve"),
        "form_hypotheses": ("plan_created", "plan"),
        "run_diagnostics": ("tool_completed", "diagnose"),
        "revise_hypotheses": ("plan_revised", "plan"),
        "propose_remediation": ("patch_proposed", "repair"),
        "prepare_approval": ("approval_requested", "approve"),
        "approval_gate": ("approval_resolved", "approve"),
        "apply_remediation": ("patch_applied", "repair"),
    }
    if stage == "verify_hypotheses":
        return (
            "hypothesis_verified" if payload.get("confirmed") is True else "hypothesis_invalidated",
            "verify",
        )
    if stage.startswith("finalize"):
        return "run_completed", "complete"
    return mapping.get(stage, ("security_event", "evaluate"))


def _artifact_kind(item: Mapping[str, object], path: Path) -> str:
    explicit = item.get("kind")
    if explicit in {"dataset", "log", "schema", "runbook"}:
        return explicit
    normalized = path.as_posix().casefold()
    if "/runbooks/" in normalized:
        return "runbook"
    if path.suffix.casefold() in {".log", ".txt"}:
        return "log"
    if path.suffix.casefold() == ".csv":
        return "dataset"
    if path.suffix.casefold() == ".json":
        configuration_markers = {"schema", "config", "configuration", "mapping"}
        name_tokens = set(re.split(r"[^a-z0-9]+", path.stem.casefold()))
        return "schema" if name_tokens & configuration_markers else "dataset"
    return "schema"


def _media_type(path: Path) -> str:
    return {
        ".csv": "text/csv",
        ".json": "application/json",
        ".log": "text/plain",
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".yaml": "application/yaml",
        ".yml": "application/yaml",
    }.get(path.suffix.casefold(), "application/octet-stream")


def _expect_json(response: Any, expected_status: int) -> Mapping[str, object]:
    if response.status_code != expected_status:
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:1000]}")
    return _mapping(response.json(), Path("HTTP response"))


def _mapping(value: object, source: Path) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"expected an object in {source}")
    return cast(Mapping[str, object], value)


def _required_string(item: Mapping[str, object], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _zero_usage() -> UsageSnapshot:
    return UsageSnapshot(
        call_count=0,
        input_tokens=0,
        output_tokens=0,
        cached_input_tokens=0,
        estimated_cost_usd=0.0,
    )


def _default_output(repository_root: Path) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    return repository_root / "evals" / "results" / timestamp


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("evals/manifest.jsonl"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args(argv)

    repository_root = Path.cwd().resolve()
    cases = list(load_manifest(args.manifest.resolve()))
    if args.fixture:
        requested = set(args.fixture)
        cases = [case for case in cases if case.incident_id in requested]
        missing = requested - {case.incident_id for case in cases}
        if missing:
            parser.error(f"unknown fixture IDs: {', '.join(sorted(missing))}")
    if args.limit is not None:
        if args.limit < 1:
            parser.error("--limit must be positive")
        cases = cases[: args.limit]
    base = Settings()
    output = (args.output or _default_output(repository_root)).resolve()
    runtime_dir = output / "runtime"
    settings = base.model_copy(
        update={
            "app_env": "test",
            "data_dir": runtime_dir,
            "llm_provider": "openai",
        }
    )
    runner = LiveEvaluationRunner(
        settings=settings,
        repository_root=repository_root,
        output_dir=output,
        fail_fast=args.fail_fast,
    )
    outcomes = runner.run(cases)
    failed = [item for item in outcomes if item.failure]
    print(f"Wrote {len(outcomes)} live run(s) to {output}")
    print(f"Failures: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
