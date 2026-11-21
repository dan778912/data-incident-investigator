import { CalendarDays, CheckCircle2, FlaskConical, ShieldCheck } from "lucide-react";
import type { EvaluationSummary } from "../api/types";

export function EvaluationView({ data }: { data: EvaluationSummary }) {
  return (
    <div className="page-stack">
      <section className="evaluation-hero">
        <div>
          <p className="eyebrow">Reproducible evidence</p>
          <h1>Evaluation snapshot</h1>
          <p>
            Frozen custom-suite results from the same workflow and guardrails used by
            the application.
          </p>
        </div>
        <dl className="run-meta">
          <div><CalendarDays aria-hidden="true" /><dt>Run date</dt><dd>{data.runDate}</dd></div>
          <div><FlaskConical aria-hidden="true" /><dt>Sample</dt><dd>{data.sampleSize} incidents</dd></div>
        </dl>
      </section>

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
            <span className="success-chip"><CheckCircle2 aria-hidden="true" size={14} /> 22 / 24 passed</span>
          </div>
          <div className="category-list">
            {data.categories.map((category) => {
              const percent = (category.passed / category.total) * 100;
              return (
                <div className="category-row" key={category.label}>
                  <span>{category.label}</span>
                  <div className="category-track"><i style={{ width: `${percent}%` }} /></div>
                  <strong>{category.passed}/{category.total}</strong>
                </div>
              );
            })}
          </div>
        </section>

        <section className="panel attack-panel" aria-labelledby="attacks-title">
          <div className="panel-heading">
            <div><p className="eyebrow">Adversarial evidence</p><h2 id="attacks-title">Prompt-injection tests</h2></div>
            <span className="success-chip"><ShieldCheck aria-hidden="true" size={14} /> 3 contained</span>
          </div>
          <div className="attack-list">
            {data.attacks.map((attack) => (
              <article key={attack.id}>
                <div className="attack-title"><strong>{attack.surface}</strong><span className={`attack-${attack.status}`}>{attack.status}</span></div>
                <p>“{attack.attack}”</p>
                <span>{attack.outcome}</span>
              </article>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
