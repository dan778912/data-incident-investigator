import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { NewIncidentForm } from "./NewIncidentForm";

describe("NewIncidentForm", () => {
  it("submits browser File objects for the artifact upload API", async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const dataset = new File(["order_id,event_time\n1,2026-11-21T08:00:00Z"], "orders.csv", {
      type: "text/csv"
    });
    const log = new File(["pipeline completed with exclusions"], "pipeline.log", {
      type: "text/plain"
    });

    render(<NewIncidentForm onClose={vi.fn()} onSubmit={onSubmit} />);
    await user.type(screen.getByLabelText(/incident name/i), "Orders timestamp drift");
    const datasetInput = screen.getByLabelText(/^dataset/i) as HTMLInputElement;
    await user.upload(datasetInput, dataset);
    await user.upload(screen.getByLabelText(/pipeline log/i), log);
    await user.type(screen.getByLabelText(/what changed/i), "Revenue fell after deploy.");
    expect(datasetInput.files?.item(0)).toBe(dataset);
    const submitButton = screen.getByRole("button", { name: /create investigation/i });
    fireEvent.submit(submitButton.closest("form")!);

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({
        name: "Orders timestamp drift",
        dataset,
        log,
        schema: undefined,
        runbook: undefined,
        context: "Revenue fell after deploy."
      })
    );
  });
});
