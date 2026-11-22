# Seven-Minute Demo Script

## Preflight

- Start the compiled application with the reviewed release configuration.
- Keep the I04 fixture files ready: `orders.csv`, `pipeline.log`, and
  `timezone_policy_v2.md`.
- Open the application, the frozen evaluation report, and the repository's
  architecture diagram before recording.
- Confirm the original I04 dataset hash and the release commit on screen.
- Confirm the final four-attack rerun completed without provider errors. Until
  that credit-restored run is reviewed and frozen, do not record the
  adversarial trace as final release evidence.

## 0:00–0:40 — Problem and boundary

Introduce Incident Lens as a local-first investigator for uploaded data-pipeline
incidents. State the boundary plainly: it can inspect case artifacts and propose
typed repairs, but it has no shell, arbitrary Python/SQL, production connector,
or permission to overwrite an original file.

## 0:40–1:25 — Create the incident

Create “Timezone window mismatch,” upload the I04 dataset, log, and runbook,
and start the investigation. Point out that uploads are validated, hashed, and
stored under generated case-scoped identifiers.

## 1:25–2:15 — Iterative agentic retrieval

Show the retrieval events and cited runbook chunk. Explain that the first query
does not provide enough evidence, so the graph grades coverage, refines the
query, and searches again. Open the evidence card to show its stable source and
chunk identifier.

## 2:15–3:10 — Planning and self-correction

Show the initial hypothesis, the allowlisted diagnostic check, and the
contradictory observation. Highlight the explicit revision event naming the
invalidated hypothesis and replacement. The important point is not that the
model “thought twice,” but that application code captured evidence that forced
a bounded plan change.

## 3:10–4:15 — Human approval boundary

Review the verified root cause and `parse_datetime` proposal. Show the source,
proposal, and plan hashes. Explain that the durable graph is interrupted here;
no working copy exists until the exact signed context is approved. Rejecting,
replaying, expiring, or changing that context fails closed.

## 4:15–5:10 — Safe remediation and validation

Approve the plan. Download the remediated copy and show the post-fix checks.
Compare its identifier and hash with the original to demonstrate that the
source was not overwritten. Mention that configuration or corruption cases
outside the DSL end in recorded manual escalation without mutation.

## 5:10–6:10 — Guardrails and adversarial evidence

After the credit-restored final rerun is reviewed, open the evaluation view and
one prompt-injection trace. Show the exact attack text, insertion location,
prohibited-capability checks, canary result, and unchanged original hash. State
that the attack was executed against a staged fixture copy. If that rerun is
still pending, replace this segment with an explicit placeholder: the attempted
final run stopped on OpenAI HTTP 429 with no credits, so it proves neither
containment nor attack success. Do not present the earlier 4/4 pre-fix baseline
as final release evidence.

## 6:10–7:00 — Evaluation, deployment, and close

State the reviewed numbers precisely: 19/20 strict end-to-end passes, 20/20
exact root causes, 60/63 required evidence items, 22/22 required sources, 12/12
successful repairs with 75/75 post-repair checks, and 20/20 original hashes
preserved. Median latency was 29.011 seconds, median usage was 11,590 tokens,
and the 20-case run cost $2.9146708 total ($0.14573354 per attempted case).
Report final adversarial outcomes only after the credit-restored rerun; until
then, say “pending” on screen. Finish on the architecture: React and FastAPI in
one local container, LangGraph with SQLite checkpoints, case-scoped FTS
retrieval, and a typed mutation boundary. Name the concrete limitation: I18
escalated safely because the evidence did not prove that input order matched
greatest `event_version`; the live run also did not elicit the rubric's
required self-correction or iterative-retrieval paths.

## Recording contingencies

- If the provider is unavailable, use the already frozen release traces and
  state clearly that they came from the dated live operating-system run.
- Never display `.env`, an API key, full local paths, or the GitHub credential
  manager.
- Stop and restart the recording if a notification exposes unrelated personal
  information.
