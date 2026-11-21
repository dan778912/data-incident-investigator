from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from data_incident_investigator.api.main import create_app
from data_incident_investigator.core.config import Settings


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(data_dir=tmp_path, app_env="test", max_upload_bytes=1000)
    return TestClient(create_app(settings))


def test_health_readiness_and_case_lifecycle(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert client.get("/api/ready").json() == {"status": "ready"}

        created = client.post(
            "/api/cases",
            json={
                "name": "Timestamp rejection",
                "incident_summary": "Events disappeared after a timezone configuration change.",
            },
        )
        assert created.status_code == 201
        case = created.json()

        assert client.get(f"/api/cases/{case['case_id']}").json() == case
        assert client.get("/api/cases").json() == [case]
        assert client.get(f"/api/cases/{uuid4()}").status_code == 404


def test_upload_validates_artifact_and_hides_storage_path(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        case_id = client.post(
            "/api/cases",
            json={"name": "Schema drift", "incident_summary": "The customer key changed."},
        ).json()["case_id"]

        response = client.post(
            f"/api/cases/{case_id}/artifacts",
            data={"kind": "dataset"},
            files={"file": ("customers.csv", b"customerId,name\n1,Ada\n", "text/csv")},
        )

        assert response.status_code == 201
        artifact = response.json()
        assert "storage_path" not in artifact
        assert artifact["immutable"] is True
        assert client.get(f"/api/artifacts/{artifact['artifact_id']}").json() == artifact
        downloaded = client.get(f"/api/artifacts/{artifact['artifact_id']}/download")
        assert downloaded.status_code == 200
        assert downloaded.content == b"customerId,name\n1,Ada\n"
        assert "customers.csv" in downloaded.headers["content-disposition"]


def test_upload_rejects_invalid_and_unknown_cases(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        case_id = client.post(
            "/api/cases",
            json={"name": "Bad input", "incident_summary": "The dataset cannot be read."},
        ).json()["case_id"]

        invalid = client.post(
            f"/api/cases/{case_id}/artifacts",
            data={"kind": "dataset"},
            files={"file": ("payload.exe", b"unsafe", "application/octet-stream")},
        )
        missing = client.post(
            f"/api/cases/{uuid4()}/artifacts",
            data={"kind": "dataset"},
            files={"file": ("data.csv", b"id\n1\n", "text/csv")},
        )

        assert invalid.status_code == 422
        assert missing.status_code == 404
        assert client.get(f"/api/artifacts/{uuid4()}").status_code == 404


def test_investigation_refines_replans_and_requires_bound_approval(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        case_id = client.post(
            "/api/cases",
            json={
                "name": "Join row loss",
                "incident_summary": "Orders dropped after a customer schema deployment.",
            },
        ).json()["case_id"]
        artifact_id = client.post(
            f"/api/cases/{case_id}/artifacts",
            data={"kind": "dataset"},
            files={"file": ("orders.csv", b"customer_id,total\n1,10\n", "text/csv")},
        ).json()["artifact_id"]

        started = client.post(
            f"/api/cases/{case_id}/analyze",
            json={"artifact_ids": [artifact_id]},
        )

        assert started.status_code == 200
        investigation = started.json()
        assert investigation["status"] == "awaiting_approval"
        assert investigation["retrieval_round"] == 2
        assert investigation["plan_revision"] == 1
        assert {event["stage"] for event in investigation["trace"]} >= {
            "refine_query",
            "revise_hypotheses",
            "prepare_approval",
        }
        request = investigation["approval_request"]
        assert len(request["plan_hash"]) == 64
        assert client.get(f"/api/cases/{case_id}/investigation").json() == investigation

        stale = client.post(
            f"/api/cases/{case_id}/approval",
            json={
                "approved": True,
                "proposal_hash": request["proposal_hash"],
                "plan_hash": "0" * 64,
                "source_hash": request["source_hash"],
            },
        )
        assert stale.status_code == 409

        approved = client.post(
            f"/api/cases/{case_id}/approval",
            json={
                "approved": True,
                "note": "Reviewed the typed cast operation.",
                "proposal_hash": request["proposal_hash"],
                "plan_hash": request["plan_hash"],
                "source_hash": request["source_hash"],
            },
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "completed"
        assert approved.json()["approval"]["approved"] is True
        assert approved.json()["remediation_result"]["applied"] is True
        assert (
            client.post(
                f"/api/cases/{case_id}/approval",
                json={
                    "approved": True,
                    "proposal_hash": request["proposal_hash"],
                    "plan_hash": request["plan_hash"],
                    "source_hash": request["source_hash"],
                },
            ).status_code
            == 409
        )


def test_investigation_rejects_missing_or_cross_case_artifacts(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        first = client.post(
            "/api/cases",
            json={"name": "First", "incident_summary": "First incident summary."},
        ).json()["case_id"]
        second = client.post(
            "/api/cases",
            json={"name": "Second", "incident_summary": "Second incident summary."},
        ).json()["case_id"]
        artifact = client.post(
            f"/api/cases/{first}/artifacts",
            data={"kind": "dataset"},
            files={"file": ("data.csv", b"id\n1\n", "text/csv")},
        ).json()["artifact_id"]

        assert client.post(f"/api/cases/{second}/analyze", json={}).status_code == 409
        assert (
            client.post(
                f"/api/cases/{second}/analyze",
                json={"artifact_ids": [artifact]},
            ).status_code
            == 422
        )
