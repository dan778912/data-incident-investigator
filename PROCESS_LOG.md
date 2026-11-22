# Individual Process Log

I began by translating the assignment into a narrow product promise: diagnose
CSV and JSON pipeline incidents, cite evidence, and require approval before a
safe repair. I initially excluded production connectors, arbitrary code
execution, and a second model provider so I could build one complete vertical
slice instead of disconnected demos. I later added a second provider behind the
same protocol only after evaluation cost became a demonstrated release risk.

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

The definitive OpenAI baseline passed 19 of 20 cases. It achieved exact
root-cause accuracy on all 20, preserved all originals, and passed every applied
repair postcondition. The remaining case diagnosed versioned replay duplicates
but safely escalated because the evidence could not prove that input order
selected the greatest version; I kept that conservative outcome instead of
weakening the mutation boundary to satisfy the fixture.

Recorded OpenAI live-run estimates total $8.1609: $0.4043 for four early smoke
runs, $2.7470 for the truthful baseline, $2.0950 for targeted validation, and
$2.9147 for the definitive suite. These are configured token-rate estimates,
not provider invoices. A pre-fix adversarial run blocked all four attacks, but
the final-build rerun returned HTTP 429 after the account exhausted its API
credit. The fail-closed classifier correctly marked those outcomes unproven
rather than turning a provider failure into a safety claim.

That cost experience changed the release plan. I added NVIDIA Nemotron 3.5
Lightning behind the same structured-model protocol, using the hosted
development endpoint rather than weakening the workflow. The adapter embeds a
strict JSON Schema in trusted instructions, rejects extra, missing, malformed,
or truncated output, and records token usage at a configured zero API rate. The
evaluation CLIs require an explicit provider and refuse to combine attack
evidence unless provider, model, and corpus identities all match. This keeps the
OpenAI result as an honest baseline while making the NVIDIA run an independent
qualification, not a substituted label.

The first NVIDIA full run exposed eight failures. They were not connectivity
problems: taxonomy predicates were too literal, one repeated retrieval query
raised instead of advancing safely, invented short evidence references aborted
whole plans, and a correct numeric-locale diagnosis was downgraded to manual
because the model omitted one required operation. I fixed those as general
control-boundary rules. Model references are now selections over
application-issued short IDs; executable-looking queries are normalized into
bounded FTS keywords; selected text artifacts receive one redacted coverage
excerpt when ranking misses them; taxonomy codes are canonicalized from
observable evidence; and numeric and datetime repairs are completed only from
successful bounded diagnostics.

The definitive NVIDIA run at `2026-11-22T024013Z` passed 19 of 20 strict
workflows and produced the exact root-cause set on all 20. It recovered 57 of
63 required evidence facts, all 22 required sources, and 50 of 50 supported
citations. Approval enforcement, replay idempotency, original preservation,
patch-policy compliance, and applied-repair postconditions were all 100%, with
zero prohibited calls, unauthorized mutations, or canary leaks. The estimated
model API cost was $0.00, with 8.163-second median latency. I18 remained the
same deliberate safe escalation because physical input ordering was still not
proven equivalent to version ordering.

The first matched NVIDIA adversarial run blocked three attacks, but the dataset
cell case failed during postcondition validation: the model proposed only one
of two observed datetime formats. The injection itself did not execute, yet an
incomplete run is not containment evidence. I changed the remediation policy to
replace every model-authored datetime parser with the exact format set proven by
a successful diagnostic, or escalate when no proof exists. After a focused
regression, the complete rerun at `2026-11-22T024558Z-adversarial` blocked all
four attacks with every required trace assertion. That clean provider-matched
pair is the release evidence.
