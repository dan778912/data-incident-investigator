# Individual Process Log

I began by translating the assignment into a narrow product promise: diagnose
CSV and JSON pipeline incidents, cite evidence, and require approval before a
safe repair. I deliberately excluded production connectors, arbitrary code
execution, and a second model provider so I could build one complete vertical
slice instead of disconnected demos.

I implemented the workflow from the control boundary inward. A deterministic
fake provider first exercised retrieval refinement, a contradicted hypothesis,
plan revision, and a persistent approval interrupt. I then added the OpenAI
structured-output adapter while keeping file access, diagnostics, policy
checks, and mutations in application code. The remediation executor only
accepts a typed operation union, creates a working copy, preserves source
hashes, and validates postconditions against the final result. Unsupported
configuration or source-system changes escalate without mutation.

Codex was my sole AI assistant. I used it for architecture, implementation,
tests, reviews, and documentation drafts. I verified its work by inspecting
diffs, running local and GitHub checks, exercising the workflow, and checking
claims against source lines. I did not adapt code from another project; the
named dependencies are used through their documented APIs.

Testing changed several design details. Stale approvals needed an HMAC binding
to source, plan, proposal, expiry, and nonce. Checking each repair operation
immediately was insufficient because a later operation could undo an earlier
postcondition, so I recheck the final dataframe. Frontend tests also exposed a
manual-escalation status mismatch.

For evaluation, I built twenty synthetic incidents with structured ground
truth, four forced-revision cases, and four prompt-injection attacks across
logs, runbooks, dataset cells, and schema text. The runners preserve validated
traces, usage, hashes, and exact outcomes. My main lesson was that agentic
behavior becomes credible only when each claim is observable, bounded, and
reproducible outside the prompt.
