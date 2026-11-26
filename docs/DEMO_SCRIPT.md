# Seven-Minute Demo Script

## Preflight

- Run the application with `LLM_PROVIDER=nvidia` and the reviewed
  `nvidia/nemotron-3.5-lightning-30b-a3b` release configuration.
- Open the demo UI at `http://127.0.0.1:5173`; port 8000 is the API only.
- Keep the I20 fixture ready: `orders.csv`, `pipeline.log`, and
  `order_contract_v3.md`.
- Open the frozen NVIDIA evaluation report, one adversarial trace, and the
  architecture diagram in separate tabs.
- Confirm the original I20 dataset hash and release commit on screen.
- Never show `.env`, API keys, local credential stores, or full personal paths.

## 0:00–0:35 — Problem, model, and boundary

**Show:** The dashboard.

**Say:** “Incident Lens is a local-first data-incident investigator using NVIDIA
Nemotron. The model proposes typed actions; it cannot run shell commands,
arbitrary code, or overwrite source files.”

## 0:35–1:15 — Create the dual-fault incident

**Show:** Create “Renamed identifier and malformed timestamp,” upload the three
I20 artifacts, and start the investigation.

**Say:** “I’m uploading a dataset, pipeline log, and contract. Each file is
validated, hashed, and isolated to this case. This incident contains two
independent faults.”

## 1:15–2:05 — Bounded retrieval with provenance

**Show:** Evidence sources, locations, and the current contract citation.

**Say:** “Retrieval is limited to these case files. Citations retain their source
locations, retrieved text stays untrusted, and generated queries are reduced to
safe keywords.”

## 2:05–3:00 — Typed planning and deterministic verification

**Show:** The diagnostic timeline and the two verified causes:
`schema_column_renamed` and `mixed_datetime_formats`.

**Say:** “The agent uses allowlisted, read-only diagnostics. Deterministic code
verifies two causes: a renamed schema column and mixed datetime formats.”

## 3:00–4:00 — Exact repair and human approval boundary

**Show:** The `rename_column` and `parse_datetime` operations, followed by the
plan and source hashes.

**Say:** “The repair renames the column and accepts only timestamp formats proven
by diagnostics. Nothing changes until this exact hashed plan receives one-time
approval.”

## 4:00–4:40 — Working-copy remediation

**Show:** Approve the plan, show the passed validation, and display the download
button for the remediated copy.

**Say:** “Approval creates and validates a working copy. The original remains
unchanged, and all 12 automatically repaired evaluation cases passed their
postconditions.”

## 4:40–5:25 — Safe escalation is a feature

**Show:** The frozen I18 result.

**Say:** “I18 found duplicate replay records but could not prove their correct
ordering. It refused an unsafe keep-last repair and escalated without modifying
data.”

## 5:25–6:15 — Prompt-injection evidence

**Show:** The four-attack report and ATK-CSV-003 evidence.

**Say:** “We tested prompt injection through a log, runbook, CSV cell, and schema
description. All four attacks were blocked, with no prohibited calls,
unauthorized mutations, or secret leaks.”

## 6:15–7:00 — Numbers, deployment, and honest close

**Show:** The Evaluation page, then the architecture.

**Say:** “The release achieved 19 of 20 strict workflow passes, 20 of 20 exact
causes, 90.48 percent evidence recall, 100 percent citation precision, and four
of four attacks blocked. Median latency was 8.163 seconds, with a configured
cost estimate of zero dollars.”

“React and FastAPI provide the interface, LangGraph and SQLite preserve workflow
state, and deterministic policy controls every mutation. NVIDIA’s endpoint is
for development, and I18 still requires stronger ordering evidence.”

## Recording contingencies

- If the provider is unavailable, use the dated frozen baseline traces and say
  clearly that they are recorded evidence rather than a live call.
- Do not substitute the paid OpenAI baseline metrics for the NVIDIA release.
- Stop and restart if a notification exposes unrelated personal information.
