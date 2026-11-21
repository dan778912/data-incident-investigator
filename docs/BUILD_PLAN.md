# Data Incident Investigator Build Plan

## Target

Deliver a complete solo capstone by **December 10, 2026**. December 10 is reserved for submission and contingency work, not core implementation.

The implementation will be considered complete only when the application, safety subsystem, evaluation evidence, deployment configuration, and submission artifacts tell the same verifiable story.

## Scope Commitment

The project claims exactly three advanced features:

1. Multi-step planning with verification and self-correction.
2. Agentic RAG with iterative retrieval and citations.
3. Human-in-the-loop approval before remediation.

Cross-session storage is used for reliable application operation but is not claimed as long-term memory. Browser automation, A2A, hybrid inference routing, and arbitrary code execution are outside the committed scope.

## Definition of Done

### Application

- A user can create a case and upload a CSV or JSON dataset, text log, optional schema, and runbooks.
- Uploads are validated and stored using immutable, case-scoped artifacts.
- The investigation produces a trace of hypotheses, checks, observations, and citations.
- At least one evaluation fixture forces a visible, evidence-driven plan revision.
- Iterative retrieval records query refinement when initial evidence is insufficient.
- The system proposes only typed remediation operations.
- The workflow pauses at a persistent approval boundary.
- Approval applies the plan to a working copy and triggers post-fix validation.
- Rejection completes the report without modifying data.
- The original artifact remains unchanged in every path.

### Safety

- File, path, tool, argument, row, runtime, and operation limits are enforced in code.
- Known credential-like secrets are redacted before model calls and logs; selected retrieval excerpts and bounded derived diagnostic values are still sent to the configured model.
- Untrusted content cannot invoke a tool or bypass approval.
- Four real prompt-injection attacks are executed and preserved with actual traces and mitigations.
- The attack surfaces include a log, a retrieved runbook, dataset cell content, and an uploaded schema description.

### Evaluation

- A reproducible fixture suite covers the supported incident categories.
- The harness produces machine-readable per-case results and aggregate metrics.
- Metrics include root-cause accuracy, remediation success, post-fix validation, citation quality, revision behavior, latency, tokens, and cost.
- Significant failure modes and mitigations are documented.
- A dated evaluation report is generated from frozen results.

### Operations and Submission

- Native setup and run instructions work from a clean checkout.
- The single-container build serves both the frontend and backend.
- SQLite and case artifacts survive container replacement through a mounted volume.
- Continuous integration runs formatting, linting, tests, and an offline evaluation smoke test.
- The README includes an accurate capability-to-code map with final line numbers.
- The 5-10 minute demo visibly triggers all three feature claims and at least one guardrail.
- The technical presentation contains at least 10 slides covering all five required topics.
- The evaluation report includes metrics, adversarial results, failure modes, and cost analysis.
- `PROCESS_LOG.md` is 200-300 words and reflects the actual development process.

## Delivery Strategy

Implementation proceeds as vertical slices. Each milestone ends with an executable path and automated evidence rather than disconnected modules.

### Milestone 1: Deterministic investigation core

Create the repository structure, domain models, persistence layer, fixture generator, artifact validation, and read-only diagnostic tools. A deterministic fake model must run the graph skeleton in tests before an external API is introduced.

Exit criteria:

- A fixture case is ingested and profiled.
- A typed plan executes through the diagnostic gateway.
- Trace events are stored and test assertions verify them.
- No tool accepts a raw path or free-form code.

### Milestone 2: Real planning and self-correction

Add the OpenAI provider adapter, structured planning output, the verifier, bounded conditional edges, and explicit revision records.

Exit criteria:

- A seeded incident disproves the initial hypothesis.
- The verifier records the conflicting observation.
- The graph produces and executes a revised plan.
- Loop and token limits terminate safely.

### Milestone 3: Iterative retrieval and citations

Index case documents in SQLite FTS5, add query generation and evidence grading, and preserve stable source locators.

Exit criteria:

- An initial insufficient search causes a recorded query refinement.
- The root-cause explanation cites source chunks.
- Case boundaries prevent cross-case retrieval.
- A malicious runbook cannot directly select or execute a tool.

### Milestone 4: Approval and safe remediation

Implement the constrained remediation DSL, preview generation, plan hashing, persistent interruption, approval decisions, working-copy execution, and post-fix validation.

Exit criteria:

- No mutation occurs before approval.
- Rejected, expired, stale, or replayed approvals cannot apply a plan.
- Approved operations run only against a working copy.
- Post-fix checks appear in the final report and audit trail.

### Milestone 5: Product UI and evaluation

Complete the case dashboard, intake wizard, live investigation timeline, approval review, results view, and evaluation dashboard. Run the full fixture and adversarial suites.

Exit criteria:

- A non-developer can complete the entire workflow in the web UI.
- Plan revision, retrieval refinement, citations, and guardrails are visible.
- The evaluation harness exports reproducible JSON and Markdown results.
- The four required attacks include exact inputs, actual traces, outcomes, and mitigations.

### Milestone 6: Packaging and submission artifacts

Build the single-container deployment, validate the mounted data volume, freeze the evaluation results, and produce the README, report, slides, process log, and demo video.

Exit criteria:

- A clean-machine or CI build succeeds.
- A complete demo rehearsal fits comfortably within 10 minutes.
- Every capability-to-code entry points to current code and line numbers.
- All submission files are present and reviewed.

## Calendar

| Date | Primary outcome |
|---|---|
| Nov 21-23 | Architecture, private repository, backend/frontend scaffold, domain models, deterministic fixtures, artifact validation. |
| Nov 24-27 | Diagnostic tools, tool gateway, SQLite persistence, graph skeleton, fake provider, OpenAI provider, initial self-correction case. |
| Nov 28-Dec 1 | Iterative FTS5 retrieval, evidence grading, citation tracking, investigation API, live trace UI. |
| Dec 2-3 | Remediation DSL, preview, plan/source hashing, persistent HITL approval, working-copy execution, post-fix checks. |
| Dec 4-5 | Complete guardrails, four adversarial attacks, full evaluation harness, UI integration. |
| Dec 6 | Run and freeze evaluation, analyze failures, repair only the highest-impact issues. |
| Dec 7 | Container build, mounted-volume verification, CI, deployment and setup documentation. |
| Dec 8 | Evaluation report, 10+ slide presentation, process log, capability-to-code map, demo script. |
| Dec 9 | Clean rehearsal, final regression run, video recording, release tag, submission package review. |
| Dec 10 | Submission and contingency buffer only. |

## Testing Layers

### Unit tests

- Upload validation and path confinement.
- Redaction behavior.
- Each diagnostic tool and its row/time limits.
- Retrieval scoring and case isolation.
- DSL schema and plan hashing.
- Approval freshness, single-use nonce, and source-hash binding.
- Immutable-original enforcement.

### Workflow tests

- Straightforward successful diagnosis.
- Contradicted hypothesis followed by a successful revision.
- Inconclusive result after the maximum revision count.
- Retrieval refinement after insufficient evidence.
- Approval, rejection, expiration, and replay paths.
- Post-fix success and post-fix failure.

### Evaluation and adversarial tests

- Known null, type, duplicate, datetime, domain, join, distribution, and log-signature incidents.
- Prompt injection in a log.
- Prompt injection in a retrieved runbook.
- Prompt injection in a dataset cell.
- Attempts to request unknown tools, raw paths, excessive row access, and unapproved mutation.

Deterministic fake-provider tests run in CI. External-model evaluations are explicit, dated runs whose provider, configured model, prompt version, and cost are captured.

## Demo Rehearsal

The target demonstration is approximately seven minutes:

1. Create or open a seeded incident case.
2. Start the investigation and show an iterative retrieval refinement.
3. Show the initial hypothesis fail and the diagnostic plan revise.
4. Show a malicious artifact instruction being treated as untrusted data.
5. Review the cited root cause and typed remediation preview.
6. Approve the plan and show post-fix validation on a working copy.
7. Close with aggregate evaluation metrics and the four adversarial cases.

The demo dataset and API configuration are frozen after the December 6 evaluation run. No live external data source is required during recording.

## Risk Register

| Risk | Trigger | Mitigation |
|---|---|---|
| Model output is unreliable | Invalid structure or inconsistent plans | Strict schemas, bounded retries, deterministic fallback errors, fake-provider regression tests. |
| Scope expands | Requests for more file types, connectors, or features | Preserve the committed CSV/JSON and three-feature scope until every definition-of-done item passes. |
| Self-correction appears staged | The initial plan never changes in real runs | Use a reproducible fixture whose plausible first hypothesis is contradicted by a diagnostic observation. Preserve the full trace. |
| Prompt injection affects reasoning | Malicious text appears in logs, documents, or cells | Separate data from control flow, validate all actions in code, scope tools, require approval, and retain adversarial traces. |
| Remediation damages data | Incorrect or stale plan is applied | Immutable originals, working copies, typed DSL, source and plan hashes, preview, approval nonce, post-fix checks. |
| Docker setup is delayed | Docker Desktop or WSL 2 is unavailable | Keep native execution fully supported; validate the image in CI before local installation and reserve Dec 7 for local packaging verification. |
| API outage or quota issue | External provider cannot be reached | Deterministic fake provider for development and recorded evaluation artifacts; avoid provider-dependent work after Dec 6. |
| Submission artifacts drift from code | Late code changes invalidate diagrams or line numbers | Freeze feature code after Dec 7, regenerate metrics, and update the capability map only from the release candidate. |

## Change Control

After December 6, changes must fix a demonstrated evaluation failure, safety issue, or submission blocker. New features are not accepted after that date. After December 8, code changes require a full regression run and capability-to-code map review.

This control keeps the final two days focused on evidence, communication, and a reliable demo rather than unfinished implementation.
