import { afterEach, describe, expect, it, vi } from "vitest";
import { createApiClient } from "./client";
import type { EvaluationSummary } from "./types";

describe("live API client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads evaluation data from the real latest-evaluation endpoint", async () => {
    const payload: EvaluationSummary = {
      runDate: "Not yet run",
      sampleSize: 0,
      metrics: [
        {
          label: "Root-cause accuracy",
          value: "Not run",
          detail: "No incidents have been evaluated.",
          score: 0,
          tone: "neutral"
        }
      ],
      attacks: [],
      categories: []
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => payload
    } satisfies Partial<Response>);
    vi.stubGlobal("fetch", fetchMock);

    const result = await createApiClient("live").getEvaluation();

    expect(result).toEqual(payload);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/evaluations/latest");
  });

  it("maps an approved manual escalation as a recorded terminal decision", async () => {
    const casePayload = {
      case_id: "case-manual",
      name: "Reader configuration incident",
      incident_summary: "The source reader configuration is invalid.",
      status: "unresolved",
      updated_at: "2026-11-21T12:00:00Z"
    };
    const investigationPayload = {
      case_id: "case-manual",
      status: "unresolved",
      retrieval_round: 1,
      plan_revision: 0,
      evidence: [],
      hypotheses: [],
      diagnostics: [],
      remediation: {
        disposition: "manual_escalation",
        proposal_id: "proposal-manual",
        title: "Escalate reader configuration",
        explanation: "This change is outside the remediation DSL.",
        operations: []
      },
      approval: { approved: true },
      trace: []
    };
    const fetchMock = vi.fn().mockImplementation(async (path: string) => ({
      ok: true,
      json: async () =>
        path.endsWith("/investigation") ? investigationPayload : casePayload
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await createApiClient("live").getInvestigation("case-manual");

    expect(result.approval.status).toBe("approved");
    expect(result.approval.manualEscalation).toBe(true);
    expect(result.phase).toBe("Manual escalation recorded");
    expect(result.validation.status).toBe("not_run");
    expect(result.outputArtifactId).toBeNull();
  });

  it("shows every verified cause without inventing affected-row metrics", async () => {
    const casePayload = {
      case_id: "case-dual",
      name: "Dual-fault incident",
      incident_summary: "A rename and mixed timestamps block ingestion.",
      status: "awaiting_approval",
      updated_at: "2026-11-21T12:00:00Z"
    };
    const investigationPayload = {
      case_id: "case-dual",
      status: "awaiting_approval",
      retrieval_round: 1,
      plan_revision: 0,
      evidence: [
        {
          evidence_id: "runbook:chunk:0",
          source: "contract.md",
          excerpt: "Rename the column and parse both supported datetime formats.",
          relevance_score: 1
        }
      ],
      hypotheses: [
        {
          hypothesis_id: "rename",
          statement: "The required column was renamed.",
          diagnostic_action: "profile_dataset",
          expected_signal: "The alternate column exists."
        }
      ],
      diagnostics: [],
      verification: {
        confirmed: true,
        root_cause_id: "rename",
        root_cause_codes: ["schema_column_renamed", "mixed_datetime_formats"],
        reason: "Both causes are independently supported."
      },
      trace: []
    };
    const fetchMock = vi.fn().mockImplementation(async (path: string) => ({
      ok: true,
      json: async () =>
        path.endsWith("/investigation") ? investigationPayload : casePayload
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await createApiClient("live").getInvestigation("case-dual");

    expect(result.rootCause.title).toBe(
      "Schema Column Renamed + Mixed Datetime Formats"
    );
    expect(result.rootCause.causeCount).toBe(2);
  });
});
