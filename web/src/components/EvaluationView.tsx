import {
  BarChart3,
  CalendarDays,
  CheckCircle2,
  CircleDashed,
  FlaskConical,
  ShieldCheck,
  ShieldQuestion
} from "lucide-react";
import type { EvaluationSummary } from "../api/types";

export function EvaluationView({ data }: { data: EvaluationSummary }) {
  const hasRun = data.sampleSize > 0;
  const categoryPassed = data.categories.reduce((sum, category) => sum + category.passed, 0);
  const categoryTotal = data.categories.reduce((sum, category) => sum + category.total, 0);
  const attacksContained = data.attacks.filter((attack) => attack.status !== "failed").length;

  return (
    <div className="page-stack">
      <section className="evaluation-hero">
        <div>
          <p className="eyebrow">Reproducible evidence</p>
          <h1>Evaluation snapshot</h1>
          <p>
            {hasRun
              ? "Frozen custom-suite results from the same workflow and guardrails used by the application."
              : "This view will report only measured results produced by the local evaluation harness."}
          </p>
        </div>
        <dl className="run-meta">
          <div><CalendarDays aria-hidden="true" /><dt>Run date</dt><dd>{data.runDate}</dd></div>
          <div><FlaskConical aria-hidden="true" /><dt>Sample</dt><dd>{data.sampleSize} incidents</dd></div>
        </dl>
      </section>

      {!hasRun && (
        <section className="panel evaluation-empty" role="status" aria-live="polite">
          <span className="empty-state-icon"><CircleDashed aria-hidden="true" /></span>
          <div>
            <p className="eyebrow">Awaiting first measured run</p>
            <h2>Evaluation results pending</h2>
            <p>
              No benchmark incidents have been executed yet. Run the reproducible suite,
              then refresh this page to load its generated summary.
            </p>
            <code>dii-run-evals --limit 20</code>
          </div>
        </section>
      )}

      <section className="metric-grid" aria-label="Evaluation metrics">
        {data.metrics.map((metric) => (
          <article className="panel metric-card" key={metric.label}>
            <span className={`metric-dot metric-${metric.tone}`} />
            <p>{metric.label}</p>
            <strong>{metric.value}</strong>
            <span>{metric.detail}</span>
            <div className="metric-track" aria-hidden="true"><i style={{ width: `${metric.score}%` }} /></div>
          </article>
        ))}
      </section>

      <div className="evaluation-grid">
        <section className="panel category-panel" aria-labelledby="category-title">
          <div className="panel-heading">
            <div><p className="eyebrow">Coverage</p><h2 id="category-title">Incident categories</h2></div>
            {data.categories.length > 0 ? (
              <span className="success-chip">
                <CheckCircle2 aria-hidden="true" size={14} /> {categoryPassed} / {categoryTotal} passed
              </span>
            ) : (
              <span className="pending-chip"><CircleDashed aria-hidden="true" size={14} /> Pending</span>
            )}
          </div>
          {data.categories.length > 0 ? (
            <div className="category-list">
              {data.categories.map((category) => {
                const percent = category.total > 0 ? (category.passed / category.total) * 100 : 0;
                return (
                  <div className="category-row" key={category.label}>
                    <span>{category.label}</span>
                    <div className="category-track"><i style={{ width: `${percent}%` }} /></div>
                    <strong>{category.passed}/{category.total}</strong>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="section-empty">
              <BarChart3 aria-hidden="true" />
              <strong>Category coverage pending</strong>
              <span>Incident-level pass counts will appear after the first suite run.</span>
            </div>
          )}
        </section>

        <section className="panel attack-panel" aria-labelledby="attacks-title">
          <div className="panel-heading">
            <div><p className="eyebrow">Adversarial evidence</p><h2 id="attacks-title">Prompt-injection tests</h2></div>
            {data.attacks.length > 0 ? (
              <span className="success-chip">
                <ShieldCheck aria-hidden="true" size={14} /> {attacksContained} contained
              </span>
            ) : (
              <span className="pending-chip"><CircleDashed aria-hidden="true" size={14} /> Pending</span>
            )}
          </div>
          {data.attacks.length > 0 ? (
            <div className="attack-list">
              {data.attacks.map((attack) => (
                <article key={attack.id}>
                  <div className="attack-title"><strong>{attack.surface}</strong><span className={`attack-${attack.status}`}>{attack.status}</span></div>
                  <p>“{attack.attack}”</p>
                  <span>{attack.outcome}</span>
                </article>
              ))}
            </div>
          ) : (
            <div className="section-empty">
              <ShieldQuestion aria-hidden="true" />
              <strong>Adversarial traces pending</strong>
              <span>Executed prompt-injection results will appear here, never planned claims.</span>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
