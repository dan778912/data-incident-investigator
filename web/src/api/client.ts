import {
  dashboardFixture,
  evaluationFixture,
  investigationFixture
} from "./mockData";
import type {
  Approval,
  CaseStatus,
  Citation,
  DashboardData,
  EvaluationSummary,
  IncidentCase,
  Investigation,
  NewIncidentInput,
  TimelineEvent,
  TimelineKind
} from "./types";

export interface IncidentApi {
  getDashboard(): Promise<DashboardData>;
  createCase(input: NewIncidentInput): Promise<IncidentCase>;
  getInvestigation(caseId: string): Promise<Investigation>;
  decideApproval(
    approvalId: string,
    decision: "approved" | "rejected"
  ): Promise<Investigation>;
  getEvaluation(): Promise<EvaluationSummary>;
}

interface BackendCase {
  case_id: string;
  name: string;
  incident_summary: string;
  status: string;
  updated_at: string;
}

interface BackendTraceEvent {
  stage: string;
  message: string;
  details: Record<string, unknown>;
}

interface BackendEvidence {
  evidence_id: string;
  source: string;
  excerpt: string;
  relevance_score: number;
}

interface BackendHypothesis {
  hypothesis_id: string;
  statement: string;
  diagnostic_action: string;
  expected_signal: string;
}

interface BackendDiagnostic {
  hypothesis_id: string;
  action: string;
  observed_signal: string;
  supports_hypothesis: boolean;
}

interface BackendVerification {
  confirmed: boolean;
  root_cause_id: string | null;
  root_cause_codes?: string[];
  reason: string;
}

interface BackendApprovalRequest {
  proposal_hash: string;
  plan_hash: string;
  source_hash: string;
  nonce: string;
}

interface BackendInvestigation {
  case_id: string;
  status: string;
  retrieval_round: number;
  plan_revision: number;
  evidence: BackendEvidence[];
  hypotheses: BackendHypothesis[];
  diagnostics: BackendDiagnostic[];
  verification?: BackendVerification;
  remediation?: {
    disposition?: "automatic_fix" | "manual_escalation";
    proposal_id: string;
    title: string;
    explanation: string;
    operations: Array<{
      operation: string;
      arguments: Record<string, unknown>;
    }>;
  };
  approval_request?: BackendApprovalRequest;
  approval?: {
    approved: boolean;
  };
  remediation_result?: {
    applied: boolean;
    message: string;
    output_artifact_id: string | null;
  };
  trace: BackendTraceEvent[];
}

const jsonRequest = async <T>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers
    }
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => undefined)) as
      | { detail?: string }
      | undefined;
    throw new Error(payload?.detail ?? `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
};

const uploadArtifact = async (
  caseId: string,
  kind: "dataset" | "log" | "schema" | "runbook",
  file: File
) => {
  const body = new FormData();
  body.append("kind", kind);
  body.append("file", file);
  const response = await fetch(`/api/cases/${caseId}/artifacts`, {
    method: "POST",
    body
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => undefined)) as
      | { detail?: string }
      | undefined;
    throw new Error(
      payload?.detail ?? `Artifact upload failed with status ${response.status}`
    );
  }
  return response.json() as Promise<{ artifact_id: string }>;
};

const mapStatus = (status: string): CaseStatus => {
  if (status === "awaiting_approval") return "awaiting_approval";
  if (["completed", "rejected", "unresolved"].includes(status)) return "resolved";
  return "investigating";
};

const mapCase = (item: BackendCase, source = "Validated case artifacts"): IncidentCase => ({
  id: item.case_id,
  name: item.name,
  source,
  status: mapStatus(item.status),
  updatedAt: new Date(item.updated_at).toLocaleString(),
  confidence: item.status === "completed" ? 94 : 0,
  summary: item.incident_summary
});

const timelineKind = (stage: string): TimelineKind => {
  if (stage.includes("retriev") || stage.includes("query") || stage === "assess_evidence") {
    return "retrieval";
  }
  if (stage === "run_diagnostics" || stage === "verify_hypotheses") return "tool";
  if (stage === "revise_hypotheses") return "revision";
  if (stage.includes("approval")) return "guardrail";
  if (stage.includes("remediation") || stage.startsWith("finalize")) return "result";
  return "plan";
};

const stageTitle = (stage: string) =>
  stage
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const mapTimeline = (events: BackendTraceEvent[]): TimelineEvent[] =>
  events.map((event, index) => ({
    id: `event-${index + 1}`,
    kind: timelineKind(event.stage),
    title: stageTitle(event.stage),
    detail: event.message,
    time: `Step ${index + 1}`,
    status: event.stage === "prepare_approval" ? "active" : "complete",
    meta: Object.keys(event.details).length
      ? Object.entries(event.details)
          .slice(0, 2)
          .map(([key, value]) => `${key}: ${String(value)}`)
          .join(" · ")
      : undefined
  }));

const mapCitations = (evidence: BackendEvidence[]): Citation[] =>
  Array.from(new Map(evidence.map((item) => [item.evidence_id, item])).values()).map((item) => ({
    id: item.evidence_id,
    title: item.source.split("(")[0].trim(),
    locator: item.evidence_id,
    excerpt: item.excerpt,
    relevance: Math.round(item.relevance_score * 100)
  }));

const approvalContexts = new Map<string, BackendApprovalRequest>();

const mapInvestigation = (
  state: BackendInvestigation,
  incidentCase: IncidentCase
): Investigation => {
  const request = state.approval_request;
  if (request) approvalContexts.set(state.case_id, request);
  const approved = state.approval?.approved === true;
  const rejected = state.approval?.approved === false;
  const proposal = state.remediation;
  const manualEscalation = proposal?.disposition === "manual_escalation";
  const verification = state.verification;
  const rootCauseCodes = verification?.root_cause_codes ?? [];
  const rootCause = state.hypotheses.find(
    (hypothesis) => hypothesis.hypothesis_id === verification?.root_cause_id
  );
  return {
    case: { ...incidentCase, status: mapStatus(state.status) },
    progress: approved || rejected ? 100 : state.status === "awaiting_approval" ? 82 : 55,
    phase:
      state.status === "awaiting_approval"
        ? "Approval required"
        : approved && manualEscalation
          ? "Manual escalation recorded"
          : approved
          ? "Remediation verified"
          : stageTitle(state.status),
    timeline: mapTimeline(state.trace),
    citations: mapCitations(state.evidence),
    rootCause: {
      title:
        rootCauseCodes.length > 1
          ? rootCauseCodes.map(stageTitle).join(" + ")
          : rootCause?.statement ?? "Investigation in progress",
      explanation: verification?.reason ?? "The workflow is still validating evidence.",
      confidence: verification?.confirmed === true ? 94 : 0,
      causeCount: rootCauseCodes.length || (verification?.confirmed === true ? 1 : 0)
    },
    approval: {
      id: state.case_id,
      status: approved ? "approved" : rejected ? "rejected" : "pending",
      manualEscalation,
      planHash: request?.plan_hash ?? "pending",
      sourceHash: request?.source_hash ?? "pending",
      summary: proposal?.title ?? "No remediation proposed yet",
      impact: manualEscalation
        ? "No automated mutation is available; approval records the escalation without creating a working copy."
        : "Operations apply only to a working copy; the original remains immutable.",
      operations:
        proposal?.operations.map((operation) => ({
          type: operation.operation,
          target: String(operation.arguments.column ?? operation.arguments.from_name ?? "dataset"),
          change: JSON.stringify(operation.arguments)
        })) ?? []
    },
    validation: {
      before: "Original artifact hash preserved",
      after: approved && !manualEscalation
        ? state.remediation_result?.message ?? "Working copy created"
        : manualEscalation
          ? "No automated fix was attempted"
          : "Runs only after approval",
      status:
        approved && !manualEscalation
          ? "passed"
          : rejected || manualEscalation
            ? "not_run"
            : "pending"
    },
    outputArtifactId: state.remediation_result?.output_artifact_id ?? null
  };
};

const liveApi: IncidentApi = {
  getDashboard: async () => {
    const cases = await jsonRequest<BackendCase[]>("/api/cases");
    const mapped = cases.map((item) => mapCase(item));
    return {
      cases: mapped,
      stats: {
        active: mapped.filter((item) => item.status === "investigating").length,
        awaitingApproval: mapped.filter((item) => item.status === "awaiting_approval").length,
        resolvedThisWeek: mapped.filter((item) => item.status === "resolved").length,
        medianDiagnosisMinutes: 0
      }
    };
  },
  createCase: async (input) => {
    const created = await jsonRequest<BackendCase>("/api/cases", {
      method: "POST",
      body: JSON.stringify({
        name: input.name,
        incident_summary: input.context ?? "Investigate the uploaded pipeline incident artifacts."
      })
    });
    const pendingUploads: Array<
      ["dataset" | "log" | "schema" | "runbook", File]
    > = [["dataset", input.dataset]];
    if (input.log) pendingUploads.push(["log", input.log]);
    if (input.schema) pendingUploads.push(["schema", input.schema]);
    if (input.runbook) pendingUploads.push(["runbook", input.runbook]);
    const uploads = await Promise.all(
      pendingUploads.map(([kind, file]) => uploadArtifact(created.case_id, kind, file))
    );
    await jsonRequest<BackendInvestigation>(`/api/cases/${created.case_id}/analyze`, {
      method: "POST",
      body: JSON.stringify({ artifact_ids: uploads.map((item) => item.artifact_id) })
    });
    return mapCase(created, input.dataset.name);
  },
  getInvestigation: async (caseId) => {
    const [incidentCase, investigation] = await Promise.all([
      jsonRequest<BackendCase>(`/api/cases/${caseId}`),
      jsonRequest<BackendInvestigation>(`/api/cases/${caseId}/investigation`)
    ]);
    return mapInvestigation(investigation, mapCase(incidentCase));
  },
  decideApproval: async (approvalId, decision) => {
    const context = approvalContexts.get(approvalId);
    if (!context) throw new Error("Reload the investigation before deciding approval.");
    const investigation = await jsonRequest<BackendInvestigation>(
      `/api/cases/${approvalId}/approval`,
      {
        method: "POST",
        body: JSON.stringify({
          approved: decision === "approved",
          proposal_hash: context.proposal_hash,
          plan_hash: context.plan_hash,
          source_hash: context.source_hash
        })
      }
    );
    const incidentCase = await jsonRequest<BackendCase>(`/api/cases/${approvalId}`);
    return mapInvestigation(investigation, mapCase(incidentCase));
  },
  getEvaluation: async () =>
    jsonRequest<EvaluationSummary>("/api/evaluations/latest")
};

const createMockApi = (): IncidentApi => {
  let mockApproval: Approval = { ...investigationFixture.approval };
  return {
    getDashboard: async () => structuredClone(dashboardFixture),
    createCase: async (input) => ({
      id: "inc-new",
      name: input.name,
      source: input.dataset.name,
      status: "investigating",
      updatedAt: "Just now",
      confidence: 0,
      summary: "Artifacts validated. Investigation is ready to start."
    }),
    getInvestigation: async () => ({
      ...structuredClone(investigationFixture),
      approval: { ...mockApproval }
    }),
    decideApproval: async (_approvalId, decision) => {
      mockApproval = { ...mockApproval, status: decision };
      const approved = decision === "approved";
      return {
        ...structuredClone(investigationFixture),
        case: {
          ...structuredClone(investigationFixture.case),
          status: approved ? "resolved" : "awaiting_approval"
        },
        progress: 100,
        phase: approved ? "Remediation verified" : "Remediation rejected",
        approval: { ...mockApproval },
        validation: {
          ...structuredClone(investigationFixture.validation),
          after: approved
            ? "Working copy passed all post-fix checks"
            : "Not run after rejection",
          status: approved ? "passed" : "not_run"
        },
        outputArtifactId: approved ? "demo-output-artifact" : null
      };
    },
    getEvaluation: async () => structuredClone(evaluationFixture)
  };
};

export type ApiMode = "live" | "mock";

export const createApiClient = (
  mode: ApiMode = import.meta.env.VITE_API_MODE === "live" ? "live" : "mock"
): IncidentApi => (mode === "live" ? liveApi : createMockApi());
