import { useState, type FormEvent } from "react";
import { FileJson2, FileSpreadsheet, FileText, X } from "lucide-react";
import type { NewIncidentInput } from "../api/types";

interface Props {
  onClose: () => void;
  onSubmit: (input: NewIncidentInput) => Promise<void>;
}

export function NewIncidentForm({ onClose, onSubmit }: Props) {
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const selectedFile = (name: string) => {
      const input = formElement.elements.namedItem(name);
      return input instanceof HTMLInputElement ? input.files?.item(0) ?? undefined : undefined;
    };
    const dataset = selectedFile("dataset");
    if (!dataset || dataset.size === 0) return;
    setSubmitting(true);
    try {
      await onSubmit({
        name: String(form.get("name")),
        dataset,
        log: selectedFile("log"),
        schema: selectedFile("schema"),
        runbook: selectedFile("runbook"),
        context: String(form.get("context") || "") || undefined
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation">
      <section
        aria-labelledby="new-incident-title"
        aria-modal="true"
        className="incident-dialog"
        role="dialog"
      >
        <div className="dialog-header">
          <div>
            <p className="eyebrow">New investigation</p>
            <h2 id="new-incident-title">Add incident evidence</h2>
            <p>Original files stay immutable. The investigator works from scoped copies.</p>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close form">
            <X aria-hidden="true" size={20} />
          </button>
        </div>

        <form className="incident-form" onSubmit={submit}>
          <label>
            Incident name
            <input name="name" required placeholder="e.g. Orders revenue dropped 5%" />
          </label>

          <div className="upload-grid">
            <label className="upload-field required-upload">
              <FileSpreadsheet aria-hidden="true" />
              <span>Dataset</span>
              <small>CSV or JSON, required</small>
              <input name="dataset" required type="file" accept=".csv,.json" />
            </label>
            <label className="upload-field">
              <FileText aria-hidden="true" />
              <span>Pipeline log</span>
              <small>Plain text</small>
              <input name="log" type="file" accept=".txt,.log" />
            </label>
            <label className="upload-field">
              <FileJson2 aria-hidden="true" />
              <span>Expected schema</span>
              <small>JSON schema</small>
              <input name="schema" type="file" accept=".json" />
            </label>
            <label className="upload-field">
              <FileText aria-hidden="true" />
              <span>Runbook</span>
              <small>Markdown or text</small>
              <input name="runbook" type="file" accept=".md,.txt" />
            </label>
          </div>

          <label>
            What changed?
            <textarea
              name="context"
              rows={3}
              placeholder="Describe the symptom, expected behavior, or last known good run."
            />
          </label>

          <div className="dialog-actions">
            <button className="button button-ghost" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="button button-primary" disabled={submitting} type="submit">
              {submitting ? "Creating case..." : "Create investigation"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
