from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import UUID

import uvicorn
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command
from pydantic import BaseModel, Field

from data_incident_investigator import __version__
from data_incident_investigator.core.config import Settings, get_settings
from data_incident_investigator.core.secrets import load_or_create_approval_key
from data_incident_investigator.domain.artifacts import ArtifactKind, ArtifactView
from data_incident_investigator.domain.cases import (
    CaseStatus,
    CreateCaseRequest,
    IncidentCase,
)
from data_incident_investigator.evaluation import (
    EvaluationReadError,
    EvaluationSummaryView,
    LatestEvaluationReader,
    default_results_root,
)
from data_incident_investigator.llm import (
    OpenAIProvider,
    RecordingProvider,
    StructuredModelProvider,
    UsageLedger,
)
from data_incident_investigator.persistence import ApplicationRepository
from data_incident_investigator.security.artifacts import ArtifactStore, ArtifactValidationError
from data_incident_investigator.security.paths import CasePathResolver
from data_incident_investigator.security.policy import PolicyViolation
from data_incident_investigator.services import (
    HMACApprovalBindingService,
    LiveServiceBundle,
    SQLiteApprovalLedger,
    SystemClock,
    build_demo_services,
    build_live_services,
)
from data_incident_investigator.workflow import build_investigation_graph
from data_incident_investigator.workflow.state import ApprovalRequestRecord


class AnalyzeRequest(BaseModel):
    artifact_ids: list[UUID] = Field(default_factory=list, max_length=20)


class ApprovalInput(BaseModel):
    approved: bool
    note: str | None = Field(default=None, max_length=500)
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class InvestigationView(BaseModel):
    case_id: UUID
    status: str
    retrieval_round: int = 0
    plan_revision: int = 0
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)
    verification: dict[str, Any] | None = None
    remediation: dict[str, Any] | None = None
    approval_request: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    remediation_result: dict[str, Any] | None = None
    trace: list[dict[str, Any]] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AppContainer:
    settings: Settings
    repository: ApplicationRepository
    artifact_store: ArtifactStore
    graph: Any
    usage_ledger: UsageLedger | None


def create_app(
    settings: Settings | None = None,
    *,
    evaluation_results_dir: Path | None = None,
) -> FastAPI:
    configured = settings or get_settings()
    evaluation_reader = LatestEvaluationReader(evaluation_results_dir or default_results_root())

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        os.environ["LANGGRAPH_STRICT_MSGPACK"] = "true"
        configured.prepare_directories()
        repository = ApplicationRepository(configured.application_database)
        await repository.setup()
        approval_key = load_or_create_approval_key(configured)
        approval_ledger = SQLiteApprovalLedger(configured.approval_database)
        live_services: LiveServiceBundle | None = None
        usage_ledger: UsageLedger | None = None
        if configured.llm_provider == "fake":
            workflow_services = build_demo_services(
                secret_key=approval_key,
                ledger=approval_ledger,
                clock=SystemClock(),
            ).workflow
        elif configured.llm_provider == "openai":
            if configured.openai_api_key is None:
                raise RuntimeError("OPENAI_API_KEY is required when LLM_PROVIDER=openai")
            approval = HMACApprovalBindingService(
                secret_key=approval_key,
                ledger=approval_ledger,
                clock=SystemClock(),
            )
            usage_ledger = UsageLedger(
                input_cost_per_million=configured.openai_input_cost_per_million,
                cached_input_cost_per_million=(configured.openai_cached_input_cost_per_million),
                output_cost_per_million=configured.openai_output_cost_per_million,
            )
            provider = RecordingProvider(
                cast(
                    StructuredModelProvider,
                    OpenAIProvider(
                        api_key=configured.openai_api_key.get_secret_value(),
                        model=configured.openai_model,
                        reasoning_effort=configured.openai_reasoning_effort,
                    ),
                ),
                usage_ledger,
            )
            live_services = build_live_services(
                provider=provider,
                application_database=configured.application_database,
                retrieval_database=configured.retrieval_database,
                data_root=configured.resolved_data_dir,
                approval=approval,
                max_rows=configured.max_dataset_rows,
                max_patch_operations=configured.max_patch_operations,
            )
            workflow_services = live_services.workflow
        else:
            raise RuntimeError("the NVIDIA live provider adapter has not been configured")
        async with AsyncSqliteSaver.from_conn_string(
            str(configured.checkpoint_database)
        ) as checkpointer:
            await checkpointer.setup()
            graph = build_investigation_graph(
                workflow_services,
                checkpointer=checkpointer,
            )
            application.state.container = AppContainer(
                settings=configured,
                repository=repository,
                artifact_store=ArtifactStore(
                    CasePathResolver(configured.resolved_data_dir),
                    max_upload_bytes=configured.max_upload_bytes,
                ),
                graph=graph,
                usage_ledger=usage_ledger,
            )
            try:
                yield
            finally:
                if live_services is not None:
                    live_services.close()

    application = FastAPI(
        title="Data Incident Investigator API",
        version=__version__,
        description="Safety-scoped data incident diagnosis and remediation.",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @application.exception_handler(ArtifactValidationError)
    async def artifact_validation_handler(
        _request: Request, exc: ArtifactValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": str(exc)},
        )

    @application.exception_handler(PolicyViolation)
    async def policy_violation_handler(_request: Request, exc: PolicyViolation) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @application.get("/api/health", tags=["operations"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @application.get("/api/ready", tags=["operations"])
    async def ready(container: ContainerDependency) -> dict[str, str]:
        if not await container.repository.healthcheck():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="application database is unavailable",
            )
        return {"status": "ready"}

    @application.get(
        "/api/evaluations/latest",
        response_model=EvaluationSummaryView,
        tags=["evaluations"],
    )
    def latest_evaluation() -> EvaluationSummaryView:
        try:
            return evaluation_reader.read()
        except EvaluationReadError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="the latest evaluation summary is invalid",
            ) from exc

    @application.post(
        "/api/cases",
        response_model=IncidentCase,
        status_code=status.HTTP_201_CREATED,
        tags=["cases"],
    )
    async def create_case(
        body: CreateCaseRequest,
        container: ContainerDependency,
    ) -> IncidentCase:
        case = await container.repository.create_case(body)
        await container.repository.append_audit_event(
            case_id=case.case_id,
            event_type="case_created",
            actor="user",
            payload={"name": case.name},
        )
        return case

    @application.get("/api/cases", response_model=list[IncidentCase], tags=["cases"])
    async def list_cases(container: ContainerDependency) -> list[IncidentCase]:
        return await container.repository.list_cases()

    @application.get("/api/cases/{case_id}", response_model=IncidentCase, tags=["cases"])
    async def get_case(case_id: UUID, container: ContainerDependency) -> IncidentCase:
        case = await container.repository.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case not found")
        return case

    @application.post(
        "/api/cases/{case_id}/artifacts",
        response_model=ArtifactView,
        status_code=status.HTTP_201_CREATED,
        tags=["artifacts"],
    )
    async def upload_artifact(
        case_id: UUID,
        container: ContainerDependency,
        kind: Annotated[ArtifactKind, Form()],
        file: Annotated[UploadFile, File()],
    ) -> ArtifactView:
        case = await container.repository.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case not found")
        content = await file.read(container.settings.max_upload_bytes + 1)
        artifact = container.artifact_store.save(
            case_id=case_id,
            filename=file.filename or "upload",
            content=content,
            kind=kind,
        )
        await container.repository.add_artifact(artifact)
        await container.repository.append_audit_event(
            case_id=case_id,
            event_type="artifact_ingested",
            actor="user",
            payload={
                "artifact_id": str(artifact.artifact_id),
                "kind": artifact.kind.value,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
            },
        )
        return ArtifactView.from_stored(artifact)

    @application.get(
        "/api/artifacts/{artifact_id}", response_model=ArtifactView, tags=["artifacts"]
    )
    async def get_artifact(
        artifact_id: UUID,
        container: ContainerDependency,
    ) -> ArtifactView:
        artifact = await container.repository.get_artifact(artifact_id)
        if artifact is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found")
        return ArtifactView.from_stored(artifact)

    @application.get("/api/artifacts/{artifact_id}/download", tags=["artifacts"])
    async def download_artifact(
        artifact_id: UUID,
        container: ContainerDependency,
    ) -> FileResponse:
        artifact = await container.repository.get_artifact(artifact_id)
        if artifact is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found")
        trusted_case_root = CasePathResolver(container.settings.resolved_data_dir).case_root(
            artifact.case_id
        )
        resolved_path = artifact.storage_path.resolve()
        if not resolved_path.is_relative_to(trusted_case_root):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="artifact path is outside its case boundary",
            )
        if not resolved_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="artifact content is no longer available",
            )
        return FileResponse(
            resolved_path,
            media_type=artifact.media_type,
            filename=artifact.original_filename,
        )

    @application.post(
        "/api/cases/{case_id}/analyze",
        response_model=InvestigationView,
        tags=["investigations"],
    )
    async def analyze_case(
        case_id: UUID,
        body: AnalyzeRequest,
        container: ContainerDependency,
    ) -> InvestigationView:
        case = await container.repository.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case not found")
        artifacts = await container.repository.list_artifacts(case_id)
        available = {artifact.artifact_id: artifact for artifact in artifacts}
        selected_ids = body.artifact_ids or list(available)
        if not selected_ids:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="at least one validated artifact is required",
            )
        if any(artifact_id not in available for artifact_id in selected_ids):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="one or more artifacts do not belong to this case",
            )
        existing = await container.graph.aget_state(_graph_config(case_id))
        if existing.values:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="this case already has an investigation workflow",
            )

        await container.repository.set_case_status(case_id, CaseStatus.ANALYZING)
        config = _graph_config(case_id)
        result = await container.graph.ainvoke(
            {
                "case_id": str(case_id),
                "incident_summary": case.incident_summary,
                "artifact_ids": [str(artifact_id) for artifact_id in selected_ids],
            },
            config,
        )
        view = _investigation_view(case_id, cast(dict[str, Any], result))
        await _sync_case_status(container.repository, case_id, view.status)
        return view

    @application.get(
        "/api/cases/{case_id}/investigation",
        response_model=InvestigationView,
        tags=["investigations"],
    )
    async def get_investigation(
        case_id: UUID,
        container: ContainerDependency,
    ) -> InvestigationView:
        if await container.repository.get_case(case_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case not found")
        snapshot = await container.graph.aget_state(_graph_config(case_id))
        values = cast(dict[str, Any], snapshot.values)
        if not values:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="investigation has not been started",
            )
        return _investigation_view(case_id, values)

    @application.post(
        "/api/cases/{case_id}/approval",
        response_model=InvestigationView,
        tags=["investigations"],
    )
    async def decide_approval(
        case_id: UUID,
        body: ApprovalInput,
        container: ContainerDependency,
    ) -> InvestigationView:
        snapshot = await container.graph.aget_state(_graph_config(case_id))
        values = cast(dict[str, Any], snapshot.values)
        if not values or values.get("status") != "awaiting_approval":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="case is not awaiting an approval decision",
            )
        request = cast(ApprovalRequestRecord, values["approval_request"])
        submitted_hashes = (body.proposal_hash, body.plan_hash, body.source_hash)
        current_hashes = (
            request["proposal_hash"],
            request["plan_hash"],
            request["source_hash"],
        )
        if submitted_hashes != current_hashes:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval view is stale; reload the current remediation plan",
            )
        decision = {**request, "approved": body.approved, "note": body.note}
        result = await container.graph.ainvoke(
            Command(resume=decision),
            _graph_config(case_id),
        )
        view = _investigation_view(case_id, cast(dict[str, Any], result))
        await _sync_case_status(container.repository, case_id, view.status)
        return view

    frontend_dir = configured.resolved_frontend_dir
    if frontend_dir.is_dir():
        application.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return application


def get_container(request: Request) -> AppContainer:
    container: AppContainer = request.app.state.container
    return container


ContainerDependency = Annotated[AppContainer, Depends(get_container)]


def _graph_config(case_id: UUID) -> dict[str, dict[str, str]]:
    return {"configurable": {"thread_id": str(case_id)}}


def _investigation_view(case_id: UUID, state: dict[str, Any]) -> InvestigationView:
    return InvestigationView(
        case_id=case_id,
        status=str(state.get("status", "unknown")),
        retrieval_round=int(state.get("retrieval_round", 0)),
        plan_revision=int(state.get("plan_revision", 0)),
        evidence=list(state.get("evidence", [])),
        hypotheses=list(state.get("hypotheses", [])),
        diagnostics=list(state.get("diagnostics", [])),
        verification=state.get("verification"),
        remediation=state.get("remediation"),
        approval_request=state.get("approval_request"),
        approval=state.get("approval"),
        remediation_result=state.get("remediation_result"),
        trace=list(state.get("trace", [])),
    )


async def _sync_case_status(
    repository: ApplicationRepository,
    case_id: UUID,
    workflow_status: str,
) -> None:
    status_map = {
        "retrieving": CaseStatus.ANALYZING,
        "diagnosing": CaseStatus.ANALYZING,
        "awaiting_approval": CaseStatus.AWAITING_APPROVAL,
        "completed": CaseStatus.COMPLETED,
        "rejected": CaseStatus.REJECTED,
        "unresolved": CaseStatus.UNRESOLVED,
    }
    mapped = status_map.get(workflow_status)
    if mapped is not None:
        await repository.set_case_status(case_id, mapped)


app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "data_incident_investigator.api.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.app_env == "development",
    )
