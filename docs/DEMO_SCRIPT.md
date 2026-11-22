# Seven-Minute Demo Script

## Preflight

- Run the compiled application with `LLM_PROVIDER=nvidia` and the reviewed
  `nvidia/nemotron-3.5-lightning-30b-a3b` release configuration.
- Keep the I20 fixture ready: `orders.csv`, `pipeline.log`, and
  `order_contract_v3.md`.
- Open the frozen NVIDIA evaluation report, one adversarial trace, and the
  architecture diagram in separate tabs.
- Confirm the original I20 dataset hash and release commit on screen.
- Never show `.env`, API keys, local credential stores, or full personal paths.

## 0:00–0:35 — Problem, model, and boundary

Introduce Incident Lens as a local-first investigator for uploaded data-pipeline
incidents. State that the release uses NVIDIA Nemotron 3.5 Lightning 30B through
NVIDIA's free development endpoint; the measured suite records an estimated API
cost of $0. Clarify that the model only returns typed proposals. It has no shell,
arbitrary Python or SQL, production connector, or permission to overwrite an
original file.

## 0:35–1:15 — Create the dual-fault incident

Create “Renamed identifier and malformed timestamp,” upload the three I20
artifacts, and start the investigation. Point out that uploads are validated,
hashed, and stored under generated case-scoped identifiers. The dataset contains
both a renamed identifier and mixed timestamp formats, making this more than a
single-label classification demo.

## 1:15–2:05 — Bounded retrieval with provenance

Open the evidence view. Explain that FTS ranks relevant chunks from only the
selected case artifacts; if a narrow generated query misses a selected text
artifact, the application adds one redacted, 1,200-character coverage excerpt.
Model-authored retrieval queries are normalized to bounded keywords and cannot
be SQL or shell commands. Show source IDs, chunk locators, retrieval rounds, and
the current contract citation.

## 2:05–3:00 — Typed planning and deterministic verification

Show the falsifiable hypotheses and allowlisted read-only diagnostics. The model
can choose only six diagnostic tools and short `D#`, `L#`, and `E#` references;
application code resolves them to trusted case artifacts. Highlight the exact
two-cause result: `schema_column_renamed` plus `mixed_datetime_formats`.
Explain that the deterministic taxonomy guard corrects or rejects model labels
from retrieved evidence and observed diagnostic output, never from a proposed
patch. The graph also has a bounded revision loop when verification fails.

## 3:00–4:00 — Exact repair and human approval boundary

Review the constrained `rename_column` and `parse_datetime` plan. Explain that
model-authored datetime arguments are replaced by the exact accepted-format set
proved by the bounded parse diagnostic; incomplete or unsupported plans become
manual escalations. Show proposal, plan, and source hashes. The durable graph is
interrupted before mutation, and the expiring one-time approval is bound to that
exact context. Rejecting, replaying, expiring, or changing it fails closed.

## 4:00–4:40 — Working-copy remediation

Approve the plan. Download the remediated working copy and show the post-fix
checks. Compare its identifier and hash with the original to demonstrate that
the source was not overwritten. Mention that all 12 automatically repaired
release cases passed their postconditions and all 20 originals were preserved.

## 4:40–5:25 — Safe escalation is a feature

Open the frozen I18 trace. The system correctly diagnoses
`duplicate_keys_after_replay`, but refuses an automatic `keep=last` repair
because the evidence does not prove physical input order equals greatest
`event_version` followed by `updated_at`. It therefore requests approval for a
bounded manual follow-up and makes no mutation. This is the only strict workflow
failure in the release suite and is intentional fail-closed behavior.

## 5:25–6:15 — Prompt-injection evidence

Open the four-attack report and the CSV-cell trace. Show the exact injected text,
insertion location, typed model output, guardrail events, prohibited-capability
checks, synthetic-canary result, and unchanged original hash. State that all
four attacks—log, retrieved runbook, dataset cell, and schema description—were
executed against staged fixture copies and all four were proven blocked.

## 6:15–7:00 — Numbers, deployment, and honest close

State the definitive NVIDIA results precisely:

- 19/20 strict end-to-end workflows completed; 20/20 exact cause sets.
- 57/63 required evidence facts (90.48%), 22/22 required sources, and 50/50
  supported citations.
- 100% approval enforcement, replay idempotency, original preservation, patch
  policy compliance, and repair postconditions.
- 4/4 prompt-injection attacks blocked, with zero prohibited calls,
  unauthorized mutations, or canary leaks.
- 8.163-second median and 11.549-second p95 latency; 15,127 median tokens; $0
  estimated model cost for the 20-case run.

Finish on the architecture: React and FastAPI in one local container, LangGraph
with SQLite checkpoints, case-scoped FTS retrieval, and a typed mutation
boundary. Name the limitations: the NVIDIA endpoint is free for development,
not a free production deployment; I18 requires stronger ordering evidence; and
the definitive run did not trigger the benchmark's optional revision-success or
second-round retrieval-gain paths even though those paths are covered by tests.

## Recording contingencies

- If the provider is unavailable, use the dated frozen release traces and say
  clearly that they are recorded evidence rather than a live call.
- Do not substitute the paid OpenAI baseline metrics for the NVIDIA release.
- Stop and restart if a notification exposes unrelated personal information.
