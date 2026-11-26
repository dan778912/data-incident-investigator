# Capstone Demo Narration — 5:46

Use this script with `incident-lens-capstone-demo-silent-1080p.mp4`. Read naturally and leave short pauses so the interface remains readable. Do not read case IDs or hashes aloud.

## 0:00–0:11 — Product and safety boundary

“Incident Lens is a local-first agent for investigating data-pipeline failures. It combines evidence retrieval, read-only diagnostics, deterministic safety policy, and human approval before any data change.”

## 0:11–0:26 — Create the live NVIDIA incident

“This is a live NVIDIA Nemotron investigation. I upload the failed orders dataset, its pipeline log, and the active data contract. Each artifact is validated, hashed, and isolated to this case.”

## 0:26–0:48 — Verified dual cause

“The workflow verifies two independent causes. The source identifier was renamed, and the timestamp column contains two supported formats. The conclusion is backed by five cited evidence items rather than model confidence alone.”

## 0:48–1:35 — Evidence and typed diagnostics

“The timeline records every retrieval, hypothesis, diagnostic, and policy decision. Retrieval is restricted to the uploaded case files, and citations preserve their source locations. The model can request only six allowlisted, read-only diagnostic tools. Application code resolves artifact ownership, validates every argument, and determines which observations actually support a cause.”

“The repair proposal is also constrained. It may rename the column and parse only the timestamp formats that diagnostics positively observed. Arbitrary code, shell access, and direct source-file mutation are unavailable.”

## 1:35–2:03 — Human approval guardrail

“This is the enforceable guardrail. The workflow stops before mutation and displays the exact typed operations, expected impact, plan hash, and source hash. Approval is bound to this case and plan with an expiring, single-use nonce. Until I approve, no working copy can be created.”

## 2:03–2:28 — Working-copy remediation

“After approval, the system creates a separate working copy, applies the two operations, and runs seven post-fix checks. Every check passes, the original hash remains unchanged, and the remediated file is ready to download.”

## 2:28–2:42 — Reproducible feature exercise

“The live incident already demonstrated human approval. I now use the application’s deterministic development provider to force the other two advanced paths reproducibly: iterative retrieval and self-correction.”

## 2:42–3:02 — Second scenario result

“This scenario begins with join-row loss after a schema deployment. The final diagnosis is a customer identifier type drift, but the workflow does not reach that answer in one step.”

## 3:02–3:39 — Iterative retrieval triggers

“The first retrieval returns only generic null-rate guidance. The agent assesses that evidence as insufficient and explicitly refines its query. Retrieval round two finds the schema-version evidence showing that customer identifiers changed from integer to string. Only then does the workflow proceed.”

## 3:39–4:29 — Self-correction triggers

“The first hypothesis predicts a null spike. A read-only diagnostic disproves it, and verification records a failed result at plan revision zero. The agent then revises the hypothesis instead of forcing the original explanation. At plan revision one, a second diagnostic reproduces the integer-versus-string mismatch and verification confirms the corrected cause.”

## 4:29–4:54 — Approval remains mandatory

“Even after successful self-correction, the agent still cannot act autonomously. The proposed cast operation stops at the same approval boundary, with the original preserved and the operation restricted to a working copy.”

## 4:54–5:46 — Measured evaluation and close

“The frozen NVIDIA evaluation is pinned to its evaluated source commit. Across twenty incidents, it produced the exact root-cause set in all twenty cases. All twelve automatic repairs passed their post-fix checks, and all fifty citations supported their claims. Median latency was 8.2 seconds.”

“Four real prompt-injection attacks were placed in a pipeline log, retrieved runbook, dataset cell, and schema description. All four were blocked with no prohibited tool call, unauthorized mutation, or secret leakage. One strict workflow safely escalated because ordering evidence was insufficient. That limitation is retained rather than weakening the mutation boundary.”

“Incident Lens therefore demonstrates three end-to-end capabilities: iterative retrieval, verified self-correction, and durable human approval, with safety controls enforced outside the model.”

## Export checklist

- Record the narration as separate clips at the timestamps above.
- Keep the deterministic-provider disclosure in the final narration.
- Add reviewed captions.
- Export as a 1080p MP4 and confirm the final duration remains between 5 and 10 minutes.
