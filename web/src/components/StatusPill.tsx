import { CheckCircle2, Clock3, Search } from "lucide-react";
import type { CaseStatus } from "../api/types";

const labels: Record<CaseStatus, string> = {
  investigating: "Investigating",
  awaiting_approval: "Awaiting approval",
  resolved: "Resolved"
};

export function StatusPill({ status }: { status: CaseStatus }) {
  const Icon =
    status === "resolved"
      ? CheckCircle2
      : status === "awaiting_approval"
        ? Clock3
        : Search;

  return (
    <span className={`status-pill status-${status}`}>
      <Icon aria-hidden="true" size={14} />
      {labels[status]}
    </span>
  );
}
