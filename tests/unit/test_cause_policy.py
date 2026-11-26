"""Regression tests for deterministic root-cause taxonomy canonicalization."""

from __future__ import annotations

import json

from data_incident_investigator.domain.causes import RootCauseCode
from data_incident_investigator.services.cause_policy import (
    DeterministicCauseCodePolicy,
    ProposedCause,
)
from data_incident_investigator.workflow.state import (
    DiagnosticRecord,
    EvidenceRecord,
    HypothesisRecord,
)


def _hypothesis(
    hypothesis_id: str,
    statement: str,
    *,
    expected_signal: str = "The bounded diagnostic confirms the stated mechanism.",
    diagnostic_action: str = "profile_dataset",
) -> HypothesisRecord:
    return {
        "hypothesis_id": hypothesis_id,
        "statement": statement,
        "diagnostic_action": diagnostic_action,
        "expected_signal": expected_signal,
    }


def _evidence(excerpt: str, *, evidence_id: str = "evidence-1") -> EvidenceRecord:
    return {
        "evidence_id": evidence_id,
        "source": "runbook.md",
        "excerpt": excerpt,
        "relevance_score": 0.99,
    }


def _diagnostic(
    hypothesis_id: str,
    observed_signal: str,
    *,
    supports_hypothesis: bool = True,
) -> DiagnosticRecord:
    return {
        "hypothesis_id": hypothesis_id,
        "action": "bounded_diagnostic",
        "observed_signal": observed_signal,
        "supports_hypothesis": supports_hypothesis,
    }


def _resolve(
    *,
    model_confirmed: bool,
    model_findings: list[ProposedCause],
    hypotheses: list[HypothesisRecord],
    evidence: list[EvidenceRecord],
    diagnostics: list[DiagnosticRecord],
):
    return DeterministicCauseCodePolicy().resolve(
        model_confirmed=model_confirmed,
        model_findings=model_findings,
        hypotheses=hypotheses,
        evidence=evidence,
        diagnostics=diagnostics,
    )


def test_join_key_signals_correct_a_wrong_model_taxonomy_label() -> None:
    hypothesis = _hypothesis(
        "hypothesis-join",
        "The join misses SKU keys because whitespace and case differences are not normalized.",
        expected_signal="Trim and case-fold normalization restores join coverage.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.MIXED_DATETIME_FORMATS,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The join contract requires SKU trim and casefold normalization; source keys "
                "contain leading whitespace and case differences."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "Join comparison found whitespace and case-fold mismatches in existing SKU keys.",
            )
        ],
    )

    assert resolution.confirmed is True
    assert resolution.corrected is True
    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.JOIN_KEY_NORMALIZATION
    ]
    assert resolution.causes[0].hypothesis_ids == (hypothesis["hypothesis_id"],)
    assert resolution.causes[0].rule_id == "join_key_normalization"


def test_superseded_contract_dominates_schema_rename_and_json_path_signals() -> None:
    hypothesis = _hypothesis(
        "hypothesis-contract",
        "A consumer mapping still uses a field from the superseded runbook schema.",
        expected_signal=(
            "The current contract and source agree while the consumer mapping is stale."
        ),
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.SCHEMA_COLUMN_RENAMED,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The old runbook is superseded. The current contract uses customer.id, and the "
                "source conforms. The consumer mapping still requests the old missing required "
                "column and documents a rename_column operation for the nested JSON dotted path."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "Source columns match the current contract; configured consumer mapping is stale.",
            )
        ],
    )

    assert resolution.confirmed is True
    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.STALE_RUNBOOK_SCHEMA_REFERENCE
    ]
    assert resolution.causes[0].rule_id == "superseded_contract"


def test_independent_schema_and_datetime_signals_yield_two_canonical_causes() -> None:
    schema_hypothesis = _hypothesis(
        "hypothesis-schema",
        "The input column was renamed and the required canonical column is missing.",
        expected_signal="Input columns contain the documented alternate column name.",
    )
    datetime_hypothesis = _hypothesis(
        "hypothesis-datetime",
        "The created_at values use mixed timestamp formats.",
        expected_signal="Strict RFC3339 parsing fails only the MM/DD/YYYY values.",
        diagnostic_action="check_datetime_parseability",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=schema_hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.SCHEMA_COLUMN_RENAMED,
            ),
            ProposedCause(
                hypothesis_id=datetime_hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.TIMEZONE_WINDOW_MISMATCH,
            ),
        ],
        hypotheses=[schema_hypothesis, datetime_hypothesis],
        evidence=[
            _evidence(
                "Validation reports missing_required_column for created_at; the current contract "
                "allows rename_column from customer_created_at. The created_at feed contains mixed "
                "datetime formats: RFC3339 and MM/DD/YYYY.",
                evidence_id="evidence-contract",
            )
        ],
        diagnostics=[
            _diagnostic(
                schema_hypothesis["hypothesis_id"],
                'input_columns=["customer_created_at"] and created_at is absent',
            ),
            _diagnostic(
                datetime_hypothesis["hypothesis_id"],
                'strict RFC3339 parse returned {"parse_failure_count": 1} for MM/DD/YYYY',
            ),
        ],
    )

    assert resolution.confirmed is True
    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.SCHEMA_COLUMN_RENAMED,
        RootCauseCode.MIXED_DATETIME_FORMATS,
    ]
    assert [cause.hypothesis_ids for cause in resolution.causes] == [
        (schema_hypothesis["hypothesis_id"],),
        (datetime_hypothesis["hypothesis_id"],),
    ]


def test_wrong_datetime_subset_does_not_invent_a_mixed_format_cause() -> None:
    hypothesis = _hypothesis(
        "hypothesis-datetime",
        "The created_at values may use mixed timestamp formats.",
        diagnostic_action="check_datetime_parse",
    )
    wrong_subset = json.dumps(
        {
            "metrics": {
                "accepted_formats": ["MM/DD/YYYY hh:mm AM UTC"],
                "format_results": {
                    "MM/DD/YYYY hh:mm AM UTC": {
                        "parse_failure_count": 1,
                        "parse_success_count": 0,
                    }
                },
                "parse_failure_count": 1,
            }
        }
    )
    canonical_coverage = json.dumps(
        {
            "metrics": {
                "accepted_formats": ["rfc3339", "MM/DD/YYYY hh:mm AM UTC"],
                "format_results": {
                    "rfc3339": {
                        "parse_failure_count": 0,
                        "parse_success_count": 1,
                    },
                    "MM/DD/YYYY hh:mm AM UTC": {
                        "parse_failure_count": 1,
                        "parse_success_count": 0,
                    },
                },
                "parse_failure_count": 0,
            }
        }
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.MIXED_DATETIME_FORMATS,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The created_at contract explains how mixed timestamp formats are handled, but "
                "this source may contain only RFC3339 values."
            )
        ],
        diagnostics=[
            _diagnostic(hypothesis["hypothesis_id"], wrong_subset),
            _diagnostic(
                hypothesis["hypothesis_id"],
                canonical_coverage,
                supports_hypothesis=False,
            ),
        ],
    )

    assert resolution.confirmed is False
    assert resolution.causes == ()


def test_recovered_retry_conflict_dominates_generic_upstream_replay() -> None:
    hypothesis = _hypothesis(
        "hypothesis-replay",
        "A recovered retry was replayed and produced conflicting versions of a business key.",
        expected_signal="event_version and updated_at identify the surviving order_id row.",
        diagnostic_action="check_duplicate_keys",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.UPSTREAM_REPLAY_DUPLICATES,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The transport timeout was followed by retry=1 status=success. A later replay "
                "created duplicate business key order_id values; use event_version then updated_at "
                "to select the surviving row."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "Duplicate order_id rows have different event_version values after replay.",
            )
        ],
    )

    assert resolution.confirmed is True
    assert resolution.corrected is True
    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.DUPLICATE_KEYS_AFTER_REPLAY
    ]
    assert resolution.causes[0].rule_id == "recovered_replay_conflict"


def test_policy_never_promotes_an_unconfirmed_model_verdict() -> None:
    hypothesis = _hypothesis(
        "hypothesis-join",
        "Whitespace differences prevent a join from matching existing keys.",
    )

    resolution = _resolve(
        model_confirmed=False,
        model_findings=[],
        hypotheses=[hypothesis],
        evidence=[_evidence("Join keys contain whitespace and require trim normalization.")],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "The join succeeds after trimming whitespace.",
            )
        ],
    )

    assert resolution.confirmed is False
    assert resolution.causes == ()
    assert resolution.corrected is False
    assert "cannot promote" in resolution.reason


def test_datetime_like_diagnostic_cannot_create_a_cause_without_datetime_evidence() -> None:
    hypothesis = _hypothesis(
        "hypothesis-unrelated",
        "A generic source inconsistency may explain the incident.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.MIXED_DATETIME_FORMATS,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[_evidence("The source record count is lower than expected.")],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                'A nonsensical probe returned RFC3339 datetime {"parse_failure_count": 1} for '
                "created_at.",
            )
        ],
    )

    assert resolution.confirmed is False
    assert resolution.causes == ()
    assert resolution.corrected is True
    assert "No root-cause taxonomy rule" in resolution.reason


def test_current_contract_rename_accepts_unknown_canonical_column_diagnostic() -> None:
    hypothesis = _hypothesis(
        "hypothesis-rename",
        "The source emits customerId while the canonical downstream name is customer_id.",
        expected_signal="Profiling confirms customerId exists and customer_id is absent.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.SCHEMA_COLUMN_RENAMED,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "status: current. Source schema v2 emits customerId; the canonical downstream "
                "name remains customer_id. Consumers may use rename_column."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                'unknown columns: ["customer_id"]; profile metrics include '
                '"columns": ["customerId", "email"]',
            )
        ],
    )

    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.SCHEMA_COLUMN_RENAMED
    ]


def test_currency_symbols_and_structured_type_mismatch_resolve_currency_drift() -> None:
    hypothesis = _hypothesis(
        "hypothesis-currency",
        "Dollar formatting leaves amount_usd as text.",
        diagnostic_action="check_type_conformance",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.NULL_MARKER_NORMALIZATION,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence("amount_usd is a numeric dollar value; a source may prefix values with `$`.")
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                'value_counts={"$12.50": 1}; mismatch={"actual": "string", "expected": "float"}',
            )
        ],
    )

    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.NUMERIC_CURRENCY_TYPE_DRIFT
    ]


def test_explicit_unit_scale_dominates_generic_contract_version_language() -> None:
    hypothesis = _hypothesis(
        "hypothesis-scale",
        "Integer cents were interpreted as decimal dollars.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.MONETARY_UNIT_SCALE_MISMATCH,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The superseded contract used dollars. The current contract encodes integer "
                "cents and consumers must divide by 100."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "Observed integer amount values produce a one hundred times larger total.",
            )
        ],
    )

    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.MONETARY_UNIT_SCALE_MISMATCH
    ]


def test_structured_inner_join_signal_resolves_row_loss() -> None:
    hypothesis = _hypothesis(
        "hypothesis-inner-join",
        "An unmatched customer key is removed by the inner join.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.INNER_JOIN_ROW_LOSS,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[_evidence("The customer enrichment is configured as an inner join.")],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "join_type=inner unmatched_customer_ids=cus-1504 left_rows=4 actual=3",
            )
        ],
    )

    assert [cause.cause_code for cause in resolution.causes] == [RootCauseCode.INNER_JOIN_ROW_LOSS]


def test_watermark_runbook_without_observed_late_drop_remains_unconfirmed() -> None:
    hypothesis = _hypothesis(
        "hypothesis-watermark",
        "A five-minute watermark may have rejected late events.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.WATERMARK_LATE_ARRIVALS,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The current watermark policy permits events up to 15 minutes late and must be "
                "changed outside the patch DSL."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "Matched 0 configured signatures across 0 bounded log lines.",
                supports_hypothesis=False,
            )
        ],
    )

    assert resolution.confirmed is False
    assert resolution.causes == ()


def test_deployed_minimum_quality_score_resolves_filter_regression() -> None:
    hypothesis = _hypothesis(
        "hypothesis-filter",
        "The deployed minimum_quality_score changed from 0.75 to 0.95.",
        expected_signal="The stricter filter reduces three eligible rows to one output row.",
    )

    resolution = _resolve(
        model_confirmed=True,
        model_findings=[
            ProposedCause(
                hypothesis_id=hypothesis["hypothesis_id"],
                cause_code=RootCauseCode.FILTER_CONFIGURATION_REGRESSION,
            )
        ],
        hypotheses=[hypothesis],
        evidence=[
            _evidence(
                "The current contract says quality_score >= 0.75 is eligible; deployed config "
                "contains minimum_quality_score=0.95."
            )
        ],
        diagnostics=[
            _diagnostic(
                hypothesis["hypothesis_id"],
                "input_rows=3 validation=output_count expected=3 actual=1",
            )
        ],
    )

    assert [cause.cause_code for cause in resolution.causes] == [
        RootCauseCode.FILTER_CONFIGURATION_REGRESSION
    ]
