import { useEffect, useMemo, useState } from "react";
import {
  BarChart3,
  Gauge,
  Menu,
  SearchCheck,
  ShieldCheck,
  X
} from "lucide-react";
import { createApiClient } from "./api/client";
import type {
  DashboardData,
  EvaluationSummary,
  Investigation,
  NewIncidentInput
} from "./api/types";
import { Dashboard } from "./components/Dashboard";
import { EvaluationView } from "./components/EvaluationView";
import { InvestigationView } from "./components/InvestigationView";
import { NewIncidentForm } from "./components/NewIncidentForm";

type View = "dashboard" | "investigation" | "evaluation";

export function App() {
  const apiMode = import.meta.env.VITE_API_MODE === "live" ? "live" : "mock";
  const api = useMemo(() => createApiClient(apiMode), [apiMode]);
  const [view, setView] = useState<View>("dashboard");
  const [dashboard, setDashboard] = useState<DashboardData>();
  const [investigation, setInvestigation] = useState<Investigation>();
  const [evaluation, setEvaluation] = useState<EvaluationSummary>();
  const [newIncidentOpen, setNewIncidentOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    api.getDashboard().then(setDashboard).catch((reason: Error) => setError(reason.message));
  }, [api]);

  const navigate = async (next: View, caseId?: string) => {
    setError(undefined);
    setSidebarOpen(false);
    try {
      if (next === "investigation") {
        const selectedCaseId = caseId ?? investigation?.case.id ?? dashboard?.cases[0]?.id;
        if (!selectedCaseId) {
          setView("dashboard");
          setError("Create an incident before opening the investigation workspace.");
          return;
        }
        setInvestigation(await api.getInvestigation(selectedCaseId));
      }
      if (next === "evaluation") {
        setEvaluation(await api.getEvaluation());
      }
      setView(next);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load view");
    }
  };

  const createIncident = async (input: NewIncidentInput) => {
    const created = await api.createCase(input);
    setNewIncidentOpen(false);
    await navigate("investigation", created.id);
  };

  const decide = async (decision: "approved" | "rejected") => {
    if (!investigation) return;
    setDeciding(true);
    setError(undefined);
    try {
      setInvestigation(await api.decideApproval(investigation.approval.id, decision));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to record approval");
    } finally {
      setDeciding(false);
    }
  };

  const navItems = [
    { id: "dashboard" as const, label: "Dashboard", icon: Gauge },
    { id: "investigation" as const, label: "Investigation", icon: SearchCheck },
    { id: "evaluation" as const, label: "Evaluation", icon: BarChart3 }
  ];

  return (
    <div className="app-shell">
      <button
        className="mobile-menu"
        aria-expanded={sidebarOpen}
        aria-label={sidebarOpen ? "Close navigation" : "Open navigation"}
        onClick={() => setSidebarOpen((open) => !open)}
      >
        {sidebarOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
      </button>

      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark"><SearchCheck aria-hidden="true" /></span>
          <div><strong>Incident Lens</strong><span>Data investigator</span></div>
        </div>
        <nav aria-label="Primary navigation">
          <p>Workspace</p>
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              aria-current={view === id ? "page" : undefined}
              className={view === id ? "nav-active" : ""}
              key={id}
              onClick={() => navigate(id)}
            >
              <Icon aria-hidden="true" size={19} /> {label}
            </button>
          ))}
        </nav>
        <div className="sidebar-spacer" />
        <section className="security-card">
          <ShieldCheck aria-hidden="true" />
          <strong>Controls active</strong>
          <span>Tools scoped · originals locked</span>
        </section>
        {apiMode === "mock" && <div className="demo-badge"><span /> Demo data mode</div>}
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div>
            <span className="topbar-context">Solo capstone workspace</span>
            <span className="topbar-separator">/</span>
            <strong>
              {view === "dashboard"
                ? "Overview"
                : view === "investigation"
                  ? investigation?.case.id ?? "Investigation"
                  : "Evaluation"}
            </strong>
          </div>
          <div className="environment-chip"><span /> Local · protected</div>
        </header>

        <div className="main-content">
          {error && <div className="error-banner" role="alert">{error}</div>}
          {!dashboard && !error && <div className="loading-state">Loading workspace...</div>}
          {dashboard && view === "dashboard" && (
            <Dashboard
              data={dashboard}
              onNewIncident={() => setNewIncidentOpen(true)}
              onOpenInvestigation={(id) => navigate("investigation", id)}
            />
          )}
          {view === "investigation" && investigation && (
            <InvestigationView
              deciding={deciding}
              investigation={investigation}
              onBack={() => setView("dashboard")}
              onDecision={decide}
            />
          )}
          {view === "investigation" && !investigation && !error && (
            <div className="loading-state">Loading investigation...</div>
          )}
          {view === "evaluation" && evaluation && <EvaluationView data={evaluation} />}
          {view === "evaluation" && !evaluation && !error && (
            <div className="loading-state">Loading evaluation...</div>
          )}
        </div>
      </div>

      {newIncidentOpen && (
        <NewIncidentForm onClose={() => setNewIncidentOpen(false)} onSubmit={createIncident} />
      )}
    </div>
  );
}
