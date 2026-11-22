import { render, screen } from "@testing-library/react";
import type { EvaluationSummary } from "../api/types";
import { EvaluationView } from "./EvaluationView";

const notRunSummary: EvaluationSummary = {
  runDate: "Not yet run",
  sampleSize: 0,
  metrics: [
    {
      label: "Root-cause accuracy",
      value: "Not run",
      detail: "No incidents have been evaluated.",
      score: 0,
      tone: "neutral"
    },
    {
      label: "Remediation success",
      value: "Not run",
      detail: "No repairs have been evaluated.",
      score: 0,
      tone: "neutral"
    }
  ],
  attacks: [],
  categories: []
};

describe("EvaluationView", () => {
  it("shows truthful pending states before the first measured run", () => {
    render(<EvaluationView data={notRunSummary} />);

    expect(screen.getByRole("status")).toHaveTextContent(/evaluation results pending/i);
    expect(screen.getByText(/dii-run-evals --limit 20/i)).toBeVisible();
    expect(screen.getByText(/category coverage pending/i)).toBeVisible();
    expect(screen.getByText(/adversarial traces pending/i)).toBeVisible();
    expect(screen.getAllByText("Not run")).toHaveLength(2);
    expect(screen.queryByText(/22 \/ 24 passed/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/3 blocked/i)).not.toBeInTheDocument();
  });
});
