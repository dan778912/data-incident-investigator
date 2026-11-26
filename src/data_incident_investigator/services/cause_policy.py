"""Deterministic root-cause taxonomy guard for model-authored findings."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from data_incident_investigator.domain.causes import RootCauseCode
from data_incident_investigator.workflow.state import (
    DiagnosticRecord,
    EvidenceRecord,
    HypothesisRecord,
)


@dataclass(frozen=True, slots=True)
class ProposedCause:
    hypothesis_id: str
    cause_code: RootCauseCode


@dataclass(frozen=True, slots=True)
class CanonicalCause:
    cause_code: RootCauseCode
    hypothesis_ids: tuple[str, ...]
    rule_id: str


@dataclass(frozen=True, slots=True)
class CauseResolution:
    confirmed: bool
    causes: tuple[CanonicalCause, ...]
    corrected: bool
    reason: str


class CauseCodePolicy(Protocol):
    def resolve(
        self,
        *,
        model_confirmed: bool,
        model_findings: Sequence[ProposedCause],
        hypotheses: Sequence[HypothesisRecord],
        evidence: Sequence[EvidenceRecord],
        diagnostics: Sequence[DiagnosticRecord],
    ) -> CauseResolution: ...


_LOCAL_TERMS: dict[RootCauseCode, tuple[str, ...]] = {
    RootCauseCode.NULL_MARKER_NORMALIZATION: ("null", "missing", "n/a", "marker"),
    RootCauseCode.SCHEMA_COLUMN_RENAMED: ("rename", "missing column", "column name"),
    RootCauseCode.NUMERIC_CURRENCY_TYPE_DRIFT: ("currency", "symbol", "numeric", "amount"),
    RootCauseCode.TIMEZONE_WINDOW_MISMATCH: ("timezone", "utc", "window", "offset"),
    RootCauseCode.MIXED_DATETIME_FORMATS: ("datetime", "timestamp", "format", "parse"),
    RootCauseCode.UPSTREAM_REPLAY_DUPLICATES: ("replay", "event_id", "event_version"),
    RootCauseCode.JOIN_CARDINALITY_EXPLOSION: ("join", "cardinality", "many-to-many"),
    RootCauseCode.JOIN_KEY_NORMALIZATION: ("join", "whitespace", "case", "normalize", "sku"),
    RootCauseCode.READER_ENCODING_DELIMITER: ("delimiter", "encoding", "reader"),
    RootCauseCode.JSON_PATH_SCHEMA_DRIFT: ("json", "path", "nested", "dotted"),
    RootCauseCode.NUMERIC_LOCALE_MISMATCH: ("locale", "decimal", "thousands", "numeric"),
    RootCauseCode.MONETARY_UNIT_SCALE_MISMATCH: ("cents", "dollars", "scale", "minor units"),
    RootCauseCode.FILTER_CONFIGURATION_REGRESSION: ("filter", "threshold", "configuration"),
    RootCauseCode.WATERMARK_LATE_ARRIVALS: ("watermark", "late", "lateness"),
    RootCauseCode.INNER_JOIN_ROW_LOSS: ("inner join", "unmatched", "row loss"),
    RootCauseCode.CATEGORICAL_VOCABULARY_DRIFT: ("category", "enum", "vocabulary", "status"),
    RootCauseCode.TRUNCATED_CSV_CORRUPTION: ("truncated", "unclosed", "eof", "corrupt"),
    RootCauseCode.DUPLICATE_KEYS_AFTER_REPLAY: (
        "replay",
        "business key",
        "order_id",
        "event_version",
    ),
    RootCauseCode.STALE_RUNBOOK_SCHEMA_REFERENCE: (
        "superseded",
        "runbook",
        "mapping",
        "current contract",
    ),
}


class DeterministicCauseCodePolicy:
    """Canonicalize taxonomy labels from bounded observable signals."""

    def resolve(
        self,
        *,
        model_confirmed: bool,
        model_findings: Sequence[ProposedCause],
        hypotheses: Sequence[HypothesisRecord],
        evidence: Sequence[EvidenceRecord],
        diagnostics: Sequence[DiagnosticRecord],
    ) -> CauseResolution:
        if not model_confirmed:
            return CauseResolution(
                confirmed=False,
                causes=(),
                corrected=False,
                reason="The model did not confirm a root cause; taxonomy policy cannot promote it.",
            )

        evidence_text = _evidence_text(evidence)
        diagnostic_text = _diagnostic_text(diagnostics)
        structured_datetime_observed, observed_mixed_datetime = _datetime_format_observation(
            diagnostics
        )
        inferred = _infer_codes(
            evidence_text,
            diagnostic_text,
            structured_datetime_observed=structured_datetime_observed,
            observed_mixed_datetime=observed_mixed_datetime,
        )
        if not inferred:
            return CauseResolution(
                confirmed=False,
                causes=(),
                corrected=bool(model_findings),
                reason="No root-cause taxonomy rule was unambiguously supported.",
            )

        proposed_by_hypothesis = {
            finding.hypothesis_id: finding.cause_code for finding in model_findings
        }
        diagnostics_by_hypothesis: dict[str, list[DiagnosticRecord]] = {}
        for diagnostic in diagnostics:
            diagnostics_by_hypothesis.setdefault(diagnostic["hypothesis_id"], []).append(diagnostic)

        available = list(hypotheses)
        canonical: list[CanonicalCause] = []
        used_ids: set[str] = set()
        for code, rule_id in inferred:
            ranked = sorted(
                available,
                key=lambda item: _hypothesis_score(
                    item,
                    code=code,
                    proposed=proposed_by_hypothesis.get(item["hypothesis_id"]),
                    diagnostics=diagnostics_by_hypothesis.get(item["hypothesis_id"], []),
                ),
                reverse=True,
            )
            selected = next(
                (item for item in ranked if item["hypothesis_id"] not in used_ids),
                ranked[0] if ranked else None,
            )
            if selected is None:
                return CauseResolution(
                    confirmed=False,
                    causes=(),
                    corrected=True,
                    reason=f"Taxonomy rule {rule_id} had no current supporting hypothesis.",
                )
            hypothesis_id = selected["hypothesis_id"]
            used_ids.add(hypothesis_id)
            canonical.append(
                CanonicalCause(
                    cause_code=code,
                    hypothesis_ids=(hypothesis_id,),
                    rule_id=rule_id,
                )
            )

        model_codes = tuple(dict.fromkeys(item.cause_code for item in model_findings))
        canonical_codes = tuple(item.cause_code for item in canonical)
        corrected = model_codes != canonical_codes
        return CauseResolution(
            confirmed=True,
            causes=tuple(canonical),
            corrected=corrected,
            reason=(
                "Deterministic taxonomy guard selected "
                f"{', '.join(code.value for code in canonical_codes)} from observable signals."
            ),
        )


def _evidence_text(evidence: Sequence[EvidenceRecord]) -> str:
    parts: list[str] = []
    for evidence_item in evidence:
        parts.extend(
            (
                evidence_item.get("source_id", ""),
                evidence_item["source"],
                evidence_item["excerpt"],
            )
        )
    return "\n".join(parts).lower()[:250_000]


def _diagnostic_text(diagnostics: Sequence[DiagnosticRecord]) -> str:
    # Only observed tool output can corroborate evidence; model-authored actions cannot.
    return "\n".join(item["observed_signal"] for item in diagnostics).lower()[:100_000]


def _datetime_format_observation(
    diagnostics: Sequence[DiagnosticRecord],
) -> tuple[bool, bool]:
    """Return whether structured datetime evidence exists and proves multiple used formats."""

    structured = False
    mixed = False
    for diagnostic in diagnostics:
        try:
            observed = json.loads(diagnostic["observed_signal"])
        except (json.JSONDecodeError, TypeError):
            continue
        metrics = observed.get("metrics") if isinstance(observed, dict) else None
        format_results = metrics.get("format_results") if isinstance(metrics, dict) else None
        if not isinstance(format_results, dict):
            continue
        structured = True
        matching_formats = sum(
            1
            for result in format_results.values()
            if isinstance(result, dict) and int(result.get("parse_success_count", 0)) > 0
        )
        mixed = mixed or matching_formats > 1
    return structured, mixed


def _infer_codes(
    evidence_text: str,
    diagnostic_text: str,
    *,
    structured_datetime_observed: bool,
    observed_mixed_datetime: bool,
) -> list[tuple[RootCauseCode, str]]:
    text = f"{evidence_text}\n{diagnostic_text}"
    # Dominant fail-closed and contract-version cases first.
    if _any(text, "unclosed quote", "unexpected eof", "truncated csv", "quarantine_required"):
        return [(RootCauseCode.TRUNCATED_CSV_CORRUPTION, "truncated_csv")]
    # A unit migration may legitimately mention both a superseded and current contract. Resolve
    # the explicit scale mechanism before considering a stale consumer mapping.
    if _any(
        text,
        "minor units",
        "integer cents",
        "hundredfold",
        "one hundred times",
        "100x",
        "divide by 100",
    ) and _any(text, "cents", "dollars", "dollar total"):
        return [(RootCauseCode.MONETARY_UNIT_SCALE_MISMATCH, "monetary_scale")]
    if _all(text, "superseded", "current") and _any(
        text,
        "configured_customer_key",
        "missing_required_source_column",
        "consumer mapping",
        "stale mapping",
        "still requests the old",
        "still uses the old",
    ):
        return [(RootCauseCode.STALE_RUNBOOK_SCHEMA_REFERENCE, "superseded_contract")]
    if _any(text, "comma decimal", "decimal comma", "thousands separator", "numeric locale"):
        return [(RootCauseCode.NUMERIC_LOCALE_MISMATCH, "numeric_locale")]
    if _any(text, "delimiter", "encoding mismatch", "reader_mismatch", "utf-8") and _any(
        text, "semicolon", "decode", "parsed column", "reader"
    ):
        return [(RootCauseCode.READER_ENCODING_DELIMITER, "reader_configuration")]
    if (
        "watermark" in evidence_text
        and _any(evidence_text, "allowed lateness", "permits events up to", "15 minutes late")
        and _any(text, "late_dropped_rows", "late_drop", "dropped specifically as late")
    ):
        return [(RootCauseCode.WATERMARK_LATE_ARRIVALS, "late_watermark")]
    if _any(
        text,
        "configured filter",
        "filter threshold",
        "score_threshold",
        "minimum_quality_score",
    ) and _any(text, "row", "output", "eligible", "collapse"):
        return [(RootCauseCode.FILTER_CONFIGURATION_REGRESSION, "filter_regression")]
    if (
        _all(text, "inner join", "unmatched") or _all(text, "join_type=inner", "unmatched")
    ) and _any(text, "row", "left_rows", "actual", "lost", "dropped"):
        return [(RootCauseCode.INNER_JOIN_ROW_LOSS, "inner_join_loss")]
    if "join" in text and _any(text, "many-to-many", "cardinality", "row explosion"):
        return [(RootCauseCode.JOIN_CARDINALITY_EXPLOSION, "join_cardinality")]
    if "join" in text and _any(text, "whitespace", "casefold", "case-fold", "trim", "unicode"):
        return [(RootCauseCode.JOIN_KEY_NORMALIZATION, "join_key_normalization")]
    if "json" in text and _any(text, "nested", "dotted path", "json path", "address.zip"):
        return [(RootCauseCode.JSON_PATH_SCHEMA_DRIFT, "json_path")]
    if _any(text, "categorical", "vocabulary", "enum rejection", "unknown status"):
        return [(RootCauseCode.CATEGORICAL_VOCABULARY_DRIFT, "categorical_vocabulary")]

    replay = "replay" in text and _any(text, "duplicate", "unique_key")
    recovered = _any(text, "retry=1 status=success", "retry status=success", "recovered transport")
    if replay and recovered and _any(text, "event_version", "updated_at", "business key"):
        return [(RootCauseCode.DUPLICATE_KEYS_AFTER_REPLAY, "recovered_replay_conflict")]
    if replay:
        return [(RootCauseCode.UPSTREAM_REPLAY_DUPLICATES, "upstream_replay")]

    results: list[tuple[RootCauseCode, str]] = []
    schema_rename = (
        _any(text, "missing_required_column", "missing required column")
        and _any(text, "rename_column", "renamed", "input_columns")
    ) or (
        _any(evidence_text, "rename_column", "renamed")
        and _any(evidence_text, "canonical", "current required name", "source schema")
        and _any(diagnostic_text, "unknown columns", "missing_required_column")
        and _any(diagnostic_text, '"columns"', "input_columns", "profiled")
    )
    timezone = _any(text, "timezone", "utc window", "window_start", "window_end") and _any(
        text, "offset", "inside", "outside", "drop"
    )
    datetime_evidence = _any(
        evidence_text,
        "mixed datetime",
        "mixed timestamp",
        "created_at",
        "event_time",
        "timestamp format",
    )
    legacy_mixed_datetime = (
        not structured_datetime_observed
        and _any(
            diagnostic_text,
            "mixed datetime",
            "mixed timestamp",
            "mm/dd/yyyy",
            '"parse_failure_count": 1',
        )
        and _any(diagnostic_text, "rfc3339", "datetime", "timestamp", "created_at")
    )
    mixed_datetime = datetime_evidence and (observed_mixed_datetime or legacy_mixed_datetime)
    null_markers = _any(text, "null marker", "default_null", "keep_default_na", "n/a") and _any(
        text, "null", "missing"
    )
    currency_type = (
        _any(text, "currency symbol", "amount_type", "non-numeric")
        and _any(text, "amount", "numeric", "float")
    ) or (
        _any(evidence_text, "prefix values with `$`", "prefix values with $", "dollar value")
        and "$" in diagnostic_text
        and _any(diagnostic_text, '"actual": "string"', '"actual":"string"', "actual=string")
        and _any(diagnostic_text, '"expected": "float"', '"expected":"float"', "expected=float")
    )

    if schema_rename:
        results.append((RootCauseCode.SCHEMA_COLUMN_RENAMED, "schema_rename"))
    if timezone:
        results.append((RootCauseCode.TIMEZONE_WINDOW_MISMATCH, "timezone_window"))
    elif mixed_datetime:
        results.append((RootCauseCode.MIXED_DATETIME_FORMATS, "mixed_datetime"))
    if null_markers:
        results.append((RootCauseCode.NULL_MARKER_NORMALIZATION, "null_markers"))
    if currency_type:
        results.append((RootCauseCode.NUMERIC_CURRENCY_TYPE_DRIFT, "currency_type"))
    return results


def _hypothesis_score(
    hypothesis: HypothesisRecord,
    *,
    code: RootCauseCode,
    proposed: RootCauseCode | None,
    diagnostics: Sequence[DiagnosticRecord],
) -> int:
    text = " ".join(
        (
            hypothesis["statement"],
            hypothesis["expected_signal"],
            hypothesis["diagnostic_action"],
            *(item["observed_signal"] for item in diagnostics),
        )
    ).lower()
    score = sum(2 for term in _LOCAL_TERMS[code] if term in text)
    if proposed == code:
        score += 1
    if any(item["supports_hypothesis"] for item in diagnostics):
        score += 1
    return score


def _any(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)


def _all(text: str, *needles: str) -> bool:
    return all(needle in text for needle in needles)
