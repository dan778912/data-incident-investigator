import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  Plus,
  Search,
  ShieldCheck
} from "lucide-react";
import type { DashboardData } from "../api/types";
import { StatusPill } from "./StatusPill";

interface Props {
  data: DashboardData;
  onNewIncident: () => void;
  onOpenInvestigation: (caseId: string) => void;
}

export function Dashboard({ data, onNewIncident, onOpenInvestigation }: Props) {
  const stats = [
    { label: "Active cases", value: data.stats.active, icon: Search, tone: "teal" },
    {
      label: "Awaiting approval",
      value: data.stats.awaitingApproval,
      icon: Clock3,
      tone: "amber"
    },
    {
      label: "Resolved this week",
      value: data.stats.resolvedThisWeek,
      icon: CheckCircle2,
      tone: "blue"
    },
    {
      label: "Median diagnosis",
      value: `${data.stats.medianDiagnosisMinutes}m`,
      icon: ShieldCheck,
      tone: "violet"
    }
  ];

  return (
    <div className="page-stack">
      <section className="dashboard-hero">
        <div>
          <p className="eyebrow">Evidence-first operations</p>
          <h1>Find the failure. Prove the cause.</h1>
          <p className="hero-copy">
            Investigate structured-data incidents with auditable plans, cited evidence,
            and a human checkpoint before any change.
          </p>
        </div>
        <button className="button button-primary" onClick={onNewIncident}>
          <Plus aria-hidden="true" size={18} />
          New incident
        </button>
      </section>

      <section aria-label="Case summary" className="stats-grid">
        {stats.map(({ label, value, icon: Icon, tone }) => (
          <article className="stat-card" key={label}>
            <span className={`stat-icon stat-${tone}`}>
              <Icon aria-hidden="true" size={19} />
            </span>
            <div>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          </article>
        ))}
      </section>

      <section className="panel case-panel" aria-labelledby="recent-cases-title">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Case workspace</p>
            <h2 id="recent-cases-title">Recent investigations</h2>
          </div>
          <span className="muted">Updated moments ago</span>
        </div>
        <div className="case-table" role="list">
          {data.cases.map((incident) => (
            <button
              className="case-row"
              key={incident.id}
              onClick={() => onOpenInvestigation(incident.id)}
              role="listitem"
            >
              <span className="case-primary">
                <span className="case-name">{incident.name}</span>
                <span className="case-source">{incident.source}</span>
              </span>
              <span className="case-summary">{incident.summary}</span>
              <StatusPill status={incident.status} />
              <span className="case-confidence">
                <strong>{incident.confidence || "--"}%</strong>
                <small>confidence</small>
              </span>
              <span className="case-updated">{incident.updatedAt}</span>
              <ArrowRight aria-hidden="true" className="row-arrow" size={18} />
            </button>
          ))}
        </div>
      </section>

      <section className="trust-strip" aria-label="Safety commitment">
        <ShieldCheck aria-hidden="true" />
        <div>
          <strong>Safe by construction</strong>
          <span>
            Read-only diagnostics, immutable originals, typed remediations, and explicit
            approval are enforced outside the model.
          </span>
        </div>
      </section>
    </div>
  );
}
