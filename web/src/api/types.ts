export type CaseStatus = "investigating" | "awaiting_approval" | "resolved";
export type TimelineKind =
  | "plan"
  | "retrieval"
  | "tool"
  | "revision"
  | "guardrail"
  | "result";

export interface IncidentCase {
  id: string;
  name: string;
  source: string;
  status: CaseStatus;
  updatedAt: string;
  confidence: number;
  summary: string;
}

export interface DashboardData {
  cases: IncidentCase[];
  stats: {
    active: number;
    awaitingApproval: number;
    resolvedThisWeek: number;
    medianDiagnosisMinutes: number;
  };
}

export interface NewIncidentInput {
  name: string;
  dataset: File;
  log?: File;
  schema?: File;
  runbook?: File;
  context?: string;
}

export interface TimelineEvent {
  id: string;
  kind: TimelineKind;
  title: string;
  detail: string;
  time: string;
  status: "complete" | "active" | "blocked";
  meta?: string;
}

export interface Citation {
  id: string;
  title: string;
  locator: string;
  excerpt: string;
  relevance: number;
}

export interface RemediationOperation {
  type: string;
  target: string;
  change: string;
}

export interface Approval {
  id: string;
  status: "pending" | "approved" | "rejected";
  manualEscalation: boolean;
  planHash: string;
  sourceHash: string;
  summary: string;
  impact: string;
  operations: RemediationOperation[];
}

export interface Investigation {
  case: IncidentCase;
  progress: number;
  phase: string;
  timeline: TimelineEvent[];
  citations: Citation[];
  rootCause: {
    title: string;
    explanation: string;
    confidence: number;
    affectedRows: number;
  };
  approval: Approval;
  validation: {
    before: string;
    after: string;
    status: "pending" | "passed" | "not_run";
  };
  outputArtifactId: string | null;
}

export interface EvaluationMetric {
  label: string;
  value: string;
  detail: string;
  score: number;
  tone: "good" | "warn" | "neutral";
}

export interface AttackResult {
  id: string;
  surface: string;
  attack: string;
  outcome: string;
  status: "blocked" | "contained" | "failed";
}

export interface EvaluationSummary {
  runDate: string;
  sampleSize: number;
  metrics: EvaluationMetric[];
  attacks: AttackResult[];
  categories: Array<{ label: string; passed: number; total: number }>;
}
