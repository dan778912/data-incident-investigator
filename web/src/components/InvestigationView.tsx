import {
  AlertTriangle,
  ArrowLeft,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Download,
  FileCheck2,
  GitBranch,
  LockKeyhole,
  Search,
  ShieldAlert,
  Sparkles,
  Wrench,
  X
} from "lucide-react";
import type { Approval, Investigation, TimelineKind } from "../api/types";
import { StatusPill } from "./StatusPill";

interface Props {
  investigation: Investigation;
  onBack: () => void;
  onDecision: (decision: "approved" | "rejected") => Promise<void>;
  deciding: boolean;
}

const eventIcons: Record<TimelineKind, typeof Search> = {
  plan: GitBranch,
  retrieval: BookOpen,
  tool: Wrench,
  revision: Sparkles,
  guardrail: ShieldAlert,
  result: CheckCircle2
};

function ApprovalPanel({
  approval,
  outputArtifactId,
  onDecision,
  deciding
}: {
  approval: Approval;
  outputArtifactId: string | null;
  onDecision: Props["onDecision"];
  deciding: boolean;
}) {
  if (approval.status !== "pending") {
    const approved = approval.status === "approved";
    const remediated = approved && !approval.manualEscalation;
    return (
      <section className={`panel decision-complete ${approved ? "approved" : "rejected"}`}>
        {approved ? <CheckCircle2 aria-hidden="true" /> : <X aria-hidden="true" />}
        <div>
          <p className="eyebrow">Decision recorded</p>
          <h2>
            {approval.manualEscalation
              ? "Manual escalation recorded"
              : approved
                ? "Remediation complete"
                : "Remediation rejected"}
          </h2>
          <p>
            {approval.manualEscalation
              ? "The finding requires a source or configuration change outside the safe remediation DSL. No data was modified."
              : approved
              ? "The approved plan ran against a working copy. The original remains unchanged."
              : "No working copy was created and no source data was modified."}
          </p>
        </div>
        {remediated && outputArtifactId && (
          <a
            className="button button-primary result-download"
            download
            href={`/api/artifacts/${encodeURIComponent(outputArtifactId)}/download`}
          >
            <Download aria-hidden="true" size={17} />
            Download remediated copy
          </a>
        )}
      </section>
    );
  }

  return (
    <section className="panel approval-panel" aria-labelledby="approval-title">
      <div className="approval-header">
        <span className="approval-icon"><LockKeyhole aria-hidden="true" /></span>
        <div>
          <p className="eyebrow">Human checkpoint</p>
          <h2 id="approval-title">Review remediation</h2>
        </div>
        <span className="pending-chip"><Clock3 aria-hidden="true" size={14} /> Pending</span>
      </div>
      <p className="approval-summary">{approval.summary}</p>
      <div className="operation-list">
        {approval.operations.map((operation, index) => (
          <div className="operation" key={`${operation.type}-${operation.target}`}>
            <span>{index + 1}</span>
            <div>
              <code>{operation.type}</code>
              <strong>{operation.target}</strong>
              <small>{operation.change}</small>
            </div>
          </div>
        ))}
      </div>
      <div className="impact-box">
        <AlertTriangle aria-hidden="true" size={18} />
        <div>
          <strong>Estimated impact</strong>
          <span>{approval.impact}</span>
        </div>
      </div>
      <dl className="hash-list">
        <div><dt>Plan</dt><dd>{approval.planHash}</dd></div>
        <div><dt>Source</dt><dd>{approval.sourceHash}</dd></div>
      </dl>
      <div className="approval-actions">
        <button
          className="button button-danger-ghost"
          disabled={deciding}
          onClick={() => onDecision("rejected")}
        >
          <X aria-hidden="true" size={17} /> Reject
        </button>
        <button
          className="button button-primary"
          disabled={deciding}
          onClick={() => onDecision("approved")}
        >
          <Check aria-hidden="true" size={17} />
          {deciding ? "Recording..." : "Approve working copy"}
        </button>
      </div>
    </section>
  );
}

export function InvestigationView({
  investigation,
  onBack,
  onDecision,
  deciding
}: Props) {
  const ValidationIcon =
    investigation.validation.status === "passed"
      ? CheckCircle2
      : investigation.validation.status === "not_run"
        ? X
        : Clock3;
  const validationLabel =
    investigation.validation.status === "passed"
      ? "Post-fix checks passed"
      : investigation.validation.status === "not_run"
        ? "Validation not run"
        : "Awaiting approval";

  return (
    <div className="page-stack investigation-page">
      <header className="investigation-header">
        <button className="back-button" onClick={onBack}>
          <ArrowLeft aria-hidden="true" size={17} /> All cases
        </button>
        <div className="investigation-title-row">
          <div>
            <div className="title-meta">
              <StatusPill status={investigation.case.status} />
              <span>{investigation.case.id}</span>
            </div>
            <h1>{investigation.case.name}</h1>
            <p>{investigation.case.source}</p>
          </div>
          <div className="progress-card" aria-label={`${investigation.progress}% complete`}>
            <div><span>{investigation.phase}</span><strong>{investigation.progress}%</strong></div>
            <div className="progress-track"><span style={{ width: `${investigation.progress}%` }} /></div>
          </div>
        </div>
      </header>

      <div className="investigation-grid">
        <main className="panel timeline-panel" aria-labelledby="timeline-title">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Auditable reasoning</p>
              <h2 id="timeline-title">Investigation timeline</h2>
            </div>
            <span className="live-chip"><span /> Trace complete</span>
          </div>
          <ol className="timeline">
            {investigation.timeline.map((event) => {
              const Icon = eventIcons[event.kind];
              return (
                <li className={`timeline-event event-${event.kind}`} key={event.id}>
                  <span className="timeline-icon"><Icon aria-hidden="true" size={17} /></span>
                  <div className="timeline-content">
                    <div className="timeline-title">
                      <strong>{event.title}</strong>
                      <time>{event.time}</time>
                    </div>
                    <p>{event.detail}</p>
                    {event.meta && <span className="event-meta">{event.meta}</span>}
                  </div>
                </li>
              );
            })}
          </ol>
        </main>

        <aside className="evidence-column" aria-label="Investigation evidence">
          <section className="panel result-card" aria-labelledby="root-cause-title">
            <div className="result-heading">
              <span><FileCheck2 aria-hidden="true" /></span>
              <div><p className="eyebrow">Verified finding</p><h2 id="root-cause-title">Root cause</h2></div>
              <strong>{investigation.rootCause.confidence}%</strong>
            </div>
            <h3>{investigation.rootCause.title}</h3>
            <p>{investigation.rootCause.explanation}</p>
            <div className="result-facts">
              <div>
                <strong>{investigation.rootCause.causeCount}</strong>
                <span>
                  verified {investigation.rootCause.causeCount === 1 ? "cause" : "causes"}
                </span>
              </div>
              <div>
                <strong>{investigation.citations.length}</strong>
                <span>evidence items</span>
              </div>
            </div>
          </section>

          <section className="panel citations-panel" aria-labelledby="citations-title">
            <div className="panel-heading compact-heading">
              <div><p className="eyebrow">Source verification</p><h2 id="citations-title">Evidence</h2></div>
              <span className="count-chip">{investigation.citations.length}</span>
            </div>
            <ol className="citation-list">
              {investigation.citations.map((citation, index) => (
                <li key={citation.id}>
                  <span className="citation-number">{index + 1}</span>
                  <div>
                    <strong>{citation.title}</strong>
                    <small>{citation.locator}</small>
                    <p>“{citation.excerpt}”</p>
                    <span className="relevance">{citation.relevance}% relevant</span>
                  </div>
                </li>
              ))}
            </ol>
          </section>
        </aside>
      </div>

      <section className="panel validation-strip" aria-label="Validation summary">
        <div><p className="eyebrow">Before</p><strong>{investigation.validation.before}</strong></div>
        <ChevronRight aria-hidden="true" />
        <div><p className="eyebrow">After typed remediation</p><strong>{investigation.validation.after}</strong></div>
        <span
          className={`validation-status validation-${investigation.validation.status}`}
          role="status"
        >
          <ValidationIcon aria-hidden="true" size={16} /> {validationLabel}
        </span>
      </section>

      <ApprovalPanel
        approval={investigation.approval}
        deciding={deciding}
        outputArtifactId={investigation.outputArtifactId}
        onDecision={onDecision}
      />
    </div>
  );
}
