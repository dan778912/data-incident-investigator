# Individual Process Log

I began by translating the assignment into a narrow product promise: diagnose
CSV and JSON pipeline incidents, cite evidence, and require approval before a
safe repair. The largest early decision was refusing attractive scope such as
production connectors, arbitrary code execution, and a second model provider.
That let me build one complete vertical slice instead of several disconnected
demos.

I implemented the workflow from the control boundary inward. A deterministic
fake provider first exercised retrieval refinement, a contradicted hypothesis,
plan revision, and a persistent approval interrupt. I then added the OpenAI
structured-output adapter while keeping file access, diagnostics, policy
checks, and mutations in application code. The remediation executor only
accepts a typed operation union, creates a working copy, preserves source
hashes, and validates every postcondition against the final result. Cases that
need configuration or source-system changes now escalate without mutation.

Testing changed several design details. Stale approvals needed an HMAC binding
to source, plan, proposal, expiry, and nonce. A review also found that checking
each repair operation immediately was insufficient because a later operation
could undo an earlier postcondition; I changed validation to recheck the final
dataframe. Frontend integration tests exposed a separate manual-escalation
status mismatch.

For evaluation, I built twenty synthetic incidents with structured ground
truth, four forced-revision cases, and four prompt-injection attacks across
logs, runbooks, dataset cells, and schema text. The runners preserve raw state,
validated traces, token/cost usage, hashes, and exact attack outcomes. My main
lesson was that agentic behavior becomes credible only when every claim is
observable, bounded, and reproducible outside the prompt.
