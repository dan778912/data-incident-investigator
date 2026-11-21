from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from data_incident_investigator.api.main import create_app
from data_incident_investigator.core.config import Settings


def test_latest_evaluation_endpoint_is_honest_before_a_suite_run(tmp_path: Path) -> None:
    results_dir = tmp_path / "evaluation-results"
    settings = Settings(data_dir=tmp_path / "data", app_env="test", llm_provider="fake")

    with TestClient(create_app(settings, evaluation_results_dir=results_dir)) as client:
        response = client.get("/api/evaluations/latest")

    assert response.status_code == 200
    assert response.json() == {
        "runDate": "Not yet run",
        "sampleSize": 0,
        "metrics": [
            {
                "label": "Root-cause accuracy",
                "value": "Not run",
                "detail": "No incidents have been evaluated.",
                "score": 0.0,
                "tone": "neutral",
            },
            {
                "label": "Remediation success",
                "value": "Not run",
                "detail": "No repairs have been evaluated.",
                "score": 0.0,
                "tone": "neutral",
            },
            {
                "label": "Citation precision",
                "value": "Not run",
                "detail": "No citations have been evaluated.",
                "score": 0.0,
                "tone": "neutral",
            },
            {
                "label": "Median latency",
                "value": "Not run",
                "detail": "No completed runs are available.",
                "score": 0.0,
                "tone": "neutral",
            },
        ],
        "attacks": [],
        "categories": [],
    }


def test_latest_evaluation_endpoint_returns_real_generated_summary(tmp_path: Path) -> None:
    results_dir = tmp_path / "evaluation-results"
    summary_path = results_dir / "2026-11-21" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "run_count": 2,
                "metrics": {
                    "diagnosis": {
                        "cause_exact_set_accuracy": {
                            "value": 1.0,
                            "numerator": 2,
                            "denominator": 2,
                            "sample_size": 2,
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(data_dir=tmp_path / "data", app_env="test", llm_provider="fake")

    with TestClient(create_app(settings, evaluation_results_dir=results_dir)) as client:
        response = client.get("/api/evaluations/latest")

    assert response.status_code == 200
    payload = response.json()
    assert payload["runDate"] == "November 21, 2026"
    assert payload["sampleSize"] == 2
    assert payload["metrics"][0]["value"] == "100.0%"
    assert payload["metrics"][1]["value"] == "Not run"
    assert payload["attacks"] == []


def test_latest_evaluation_endpoint_rejects_malformed_summary(tmp_path: Path) -> None:
    results_dir = tmp_path / "evaluation-results"
    summary_path = results_dir / "latest" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text('{"run_count": 2, "metrics": []}', encoding="utf-8")
    settings = Settings(data_dir=tmp_path / "data", app_env="test", llm_provider="fake")

    with TestClient(create_app(settings, evaluation_results_dir=results_dir)) as client:
        response = client.get("/api/evaluations/latest")

    assert response.status_code == 500
    assert response.json() == {"detail": "the latest evaluation summary is invalid"}
