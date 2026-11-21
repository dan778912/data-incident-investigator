from __future__ import annotations

import json
from pathlib import Path

import pytest

from data_incident_investigator.evaluation import EvaluationReadError, LatestEvaluationReader


def test_missing_results_return_explicit_zero_sample_state(tmp_path: Path) -> None:
    view = LatestEvaluationReader(tmp_path / "missing").read()
    payload = view.model_dump(by_alias=True)

    assert payload["runDate"] == "Not yet run"
    assert payload["sampleSize"] == 0
    assert all(metric["value"] == "Not run" for metric in payload["metrics"])
    assert payload["attacks"] == []
    assert payload["categories"] == []


def test_real_summary_maps_metrics_without_inventing_attack_results(tmp_path: Path) -> None:
    summary_path = tmp_path / "2026-11-21" / "summary.json"
    _write_summary(summary_path)

    payload = LatestEvaluationReader(tmp_path).read().model_dump(by_alias=True)

    assert payload["runDate"] == "November 21, 2026"
    assert payload["sampleSize"] == 4
    assert payload["metrics"][0] == {
        "label": "Root-cause accuracy",
        "value": "75.0%",
        "detail": "3 of 4 incidents correctly classified",
        "score": 75.0,
        "tone": "warn",
    }
    assert payload["metrics"][3]["value"] == "1.5 sec"
    assert payload["metrics"][3]["detail"] == "p95: 2.5 sec across 4 completed runs"
    assert payload["attacks"] == []
    assert payload["categories"] == [{"label": "Datetime", "passed": 3, "total": 4}]


def test_only_explicit_executed_attacks_are_returned(tmp_path: Path) -> None:
    summary_path = tmp_path / "2026-11-21" / "summary.json"
    _write_summary(
        summary_path,
        attacks=[
            {
                "id": "ATK-LOG-001",
                "surface": "Pipeline log",
                "attack": "Request environment exfiltration.",
                "outcome": "The policy gateway rejected the request.",
                "status": "blocked",
            }
        ],
    )

    attacks = LatestEvaluationReader(tmp_path).read().model_dump(by_alias=True)["attacks"]

    assert attacks == [
        {
            "id": "ATK-LOG-001",
            "surface": "Pipeline log",
            "attack": "Request environment exfiltration.",
            "outcome": "The policy gateway rejected the request.",
            "status": "blocked",
        }
    ]


def test_present_but_invalid_summary_fails_closed(tmp_path: Path) -> None:
    summary_path = tmp_path / "latest" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text('{"run_count": 4, "metrics": []}', encoding="utf-8")

    with pytest.raises(EvaluationReadError, match="metrics must be an object"):
        LatestEvaluationReader(tmp_path).read()


def _write_summary(
    path: Path,
    *,
    attacks: list[dict[str, object]] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "run_count": 4,
        "manifest_case_count": 20,
        "unique_fixture_count": 4,
        "evaluation_date": "2026-11-21",
        "metrics": {
            "diagnosis": {
                "cause_exact_set_accuracy": _metric(0.75, 3, 4, 4),
            },
            "repair": {
                "repair_postcondition_rate": _metric(0.5, 1, 2, 2),
            },
            "rag": {
                "citation_precision": _metric(0.8, 8, 10, 10),
            },
            "performance": {
                "latency_p50_ms": _metric(1_500, None, None, 4),
                "latency_p95_ms": _metric(2_500, None, None, 4),
            },
            "safety": {
                "prompt_injection_attack_success_rate": _metric(0, 0, 4, 4),
            },
        },
        "categories": [{"label": "Datetime", "passed": 3, "total": 4}],
    }
    if attacks is not None:
        payload["attacks"] = attacks
    path.write_text(json.dumps(payload), encoding="utf-8")


def _metric(
    value: float,
    numerator: int | None,
    denominator: int | None,
    sample_size: int,
) -> dict[str, object]:
    return {
        "value": value,
        "numerator": numerator,
        "denominator": denominator,
        "sample_size": sample_size,
        "unit": None,
    }
