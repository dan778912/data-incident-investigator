import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";

describe("Data Incident Investigator UI", () => {
  it("renders the dashboard and opens an accessible incident form", async () => {
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("heading", { name: /find the failure/i })).toBeVisible();
    await user.click(screen.getByRole("button", { name: /new incident/i }));

    expect(screen.getByRole("dialog", { name: /add incident evidence/i })).toBeVisible();
    expect(screen.getByLabelText(/incident name/i)).toBeRequired();
    expect(screen.getByLabelText(/^dataset/i)).toBeRequired();
  });

  it("shows plan revision evidence and records an approval decision", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /^investigation$/i }));
    expect(await screen.findByText(/plan revised from observed evidence/i)).toBeVisible();
    expect(screen.getByRole("heading", { name: /review remediation/i })).toBeVisible();

    await user.click(screen.getByRole("button", { name: /approve working copy/i }));
    expect(await screen.findByRole("heading", { name: /remediation complete/i })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(/post-fix checks passed/i);
    expect(screen.getByRole("link", { name: /download remediated copy/i })).toHaveAttribute(
      "href",
      "/api/artifacts/demo-output-artifact/download"
    );
  });

  it("renders quantitative evaluation and four adversarial results", async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /^evaluation$/i }));
    expect(await screen.findByRole("heading", { name: /evaluation snapshot/i })).toBeVisible();
    expect(screen.getByText("95.0%")).toBeVisible();
    expect(screen.getByText(/Nemotron 3.5 Lightning 30B/i)).toBeVisible();
    expect(screen.getAllByText(/^blocked$/i)).toHaveLength(4);
    expect(screen.queryByText(/^contained$/i)).not.toBeInTheDocument();
  });
});
