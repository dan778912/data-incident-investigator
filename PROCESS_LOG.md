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

The live OpenAI integration exposed issues that the fake provider could not.
The first diagnostic schema used a discriminator, `oneOf`, and a free-form
mapping that the provider's structured-output subset rejected. A later
remediation schema exposed the same problem through `minProperties`. I replaced
those shapes with strict `anyOf` branches and bounded lists, converted the lists
back to runtime dictionaries after validation, and added an offline contract
test for every model-facing schema. This let me diagnose schema errors before
another paid call.

I also hardened the evaluator after an early smoke run showed that it could
mistake an unresolved workflow for a pass and could infer approval behavior
instead of measuring it. The release runner now returns a nonzero result for
logical failures, compares the proposed repair with frozen ground truth, records
working-copy counts before and after valid, stale, and replayed approvals, and
preserves the original server exception. Category results now require the whole
run to pass rather than only the cause label.

The first truthful twenty-case baseline passed 10 of 20 strict end-to-end
cases. Its strongest results were unchanged originals and passing repair
postconditions; its main weakness was that log diagnostics returned keyword
counts without the matching lines needed to justify causality. I added bounded,
credential-redacted log lines, passed retrieved evidence into verification,
defined the overlapping replay cause codes, and introduced canonical datetime
formats that both diagnostics and repairs actually enforce. Targeted reruns
validated those general fixes before I repeated the full suite.

The definitive live run passed 19 of 20 cases. It achieved exact root-cause
accuracy on all 20, preserved all originals, and passed every applied repair
postcondition. The remaining case diagnosed versioned replay duplicates but
safely escalated because the available evidence could not prove that input
order selected the greatest version; I kept that conservative outcome instead
of weakening the mutation boundary to satisfy the fixture.

Recorded live-run cost estimates total $8.1609: $0.4043 for four early smoke
runs, $2.7470 for the truthful baseline, $2.0950 for targeted validation, and
$2.9147 for the definitive suite. These are configured token-rate estimates,
not provider invoices, and they exclude adversarial-run usage because that
runner does not record token cost. A pre-fix adversarial run blocked all four
attacks. The final-build rerun could not be claimed: the provider returned HTTP
429 after the account exhausted its API credit, so the fail-closed classifier
marked all four outcomes unproven. I preserved that evidence and deferred the
final freeze until the exact attacks can be rerun with available credit.
