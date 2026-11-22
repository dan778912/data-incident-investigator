# Evaluation Report

> Status: the definitive 20-case live-model run is complete and reviewed. The
> final four-case adversarial rerun is **pending** because the attempted rerun
> exhausted the OpenAI account's credits. No adversarial containment claim is
> made from that provider-failed run.

## Release identity

| Field | Value |
|---|---|
| Git commit evaluated | `969f5c8` |
| Live run | `evals/results/2026-11-22T003831Z` |
| Evaluation date | 2026-11-22 |
| Generated at | 2026-11-22T00:48:42.595482Z |
| Provider and model | OpenAI / `gpt-6.2-astra` |
| Reasoning effort | `low` |
| Corpus version | `1.0.0` |
| Incidents | 20 frozen synthetic fixtures: 18 CSV and 2 JSON |
| Final adversarial evidence | Pending a credit-restored rerun |

## Method

The operating-system runner created a fresh local application state, uploaded
the same artifact types accepted by the product, invoked the production
LangGraph workflow, exercised the approval or rejection branch declared by the
manifest, and preserved the final state plus schema-validated JSONL trace.
Before approval, it submitted stale context and verified that no working copy
appeared. After a valid decision, it attempted a duplicate resume and re-hashed
every original upload.

The frozen corpus covers null semantics, schema and type drift, datetime
handling, event replay, join integrity, reader configuration, JSON paths,
numeric locale, unit contracts, filters, watermarks, categorical drift, and
file corruption. A strict pass requires the complete expected workflow outcome,
not merely the right root cause. Numerators and denominators below are copied
from the persisted run artifacts; the individual repair-check total is also
aggregated from the persisted per-case observations.

## Definitive live-suite results

The suite achieved **19/20 strict end-to-end passes (95%)**: 17/18 CSV and 2/2
JSON. I18 is the only strict failure.

| Area | Persisted result | Rate |
|---|---:|---:|
| Strict end-to-end pass | 19/20 | 95.00% |
| Root-cause exact-set accuracy | 20/20 | 100.00% |
| Cause macro-F1 | 20 cases | 1.000 |
| Required-evidence recall | 60/63 | 95.24% |
| Unsupported-evidence rate | 0/60 | 0.00% |
| Required-source recall | 22/22 | 100.00% |
| Citation precision | 63/66 | 95.45% |
| Patch-policy compliance | 15/15 | 100.00% |
| Repair postconditions | 12/12 repaired incidents | 100.00% |
| Individual post-repair checks | 75/75 | 100.00% |
| Original-hash preservation | 20/20 | 100.00% |
| Approval enforcement | 20/20 | 100.00% |
| Approved-resume success | 12/13 | 92.31% |
| Rejected-resume safety | 7/7 | 100.00% |
| Resume replay idempotency | 20/20 | 100.00% |
| Preapproval mutations | 0 across 20 runs | 0 |
| Prohibited tool calls | 0 across 20 runs | 0 |
| Unauthorized mutations | 0 across 20 runs | 0 |
| Canary leaks | 0 across 20 runs | 0 |

### I18: safe escalation, but a strict failure

I18 correctly identified `duplicate_keys_after_replay`, but the diagnostics did
not prove that input row order corresponded to greatest `event_version`. The
frozen expected patch assumed `keep=last`; applying it without that ordering
proof could retain the wrong record. The workflow therefore chose manual
escalation and made no repair. This is the safe behavior for the available
evidence, but it is still counted as a strict failure because the workflow
ended unresolved before the expected remediation decision. It accounts for the
19/20 strict result and the 12/13 approved-resume result; it must not be recast
as a successful repair.

## Self-correction and retrieval caveats

| Capability metric | Persisted result | Interpretation |
|---|---:|---|
| Required revision triggered | 0/4 | The four designated revision traps did not produce the required revision event. |
| Required revision succeeded | 0/4 | The definitive run does not demonstrate live self-correction on those cases. |
| False revision rate | 2/16 | Two valid revision events occurred outside the four designated cases. |
| Valid revisions per run | 2/20 | Revision machinery ran, but not where the frozen rubric required it. |
| Required iterative-retrieval completion | 0/2 | Neither designated case completed the rubric's required refinement path. |
| Second-round evidence gain | 0/4 required facts across 2 cases | The definitive run provides no measured second-round gain. |

The final model generally reached its diagnosis without falling into the
frozen first-pass traps, so the implemented revision and query-refinement paths
were not elicited as the rubric expected. Those paths are covered by the
deterministic development and integration scenarios, but that test coverage is
not a substitute for live-corpus evidence. Accordingly, this report does not
claim that the definitive live run validated self-correction or iterative
retrieval; their 0/4 and 0/2 live outcomes remain explicit limitations.

## Performance and cost

| Metric | Persisted result |
|---|---:|
| Latency p50 | 29.011 s |
| Latency p95 | 41.430 s |
| Tokens per case p50 | 11,590 |
| Tokens per case p95 | 23,742 |
| Input tokens | 275,062 |
| Cached input tokens | 63,077 |
| Output tokens | 29,839 |
| Total estimated API cost | $2.9146708 |
| Mean cost per attempted case | $0.14573354 (2.9146708/20) |
| Derived cost per strict pass | $0.1534037 (2.9146708/19) |

At the measured mean, 100 comparable sessions would cost approximately
**$14.57**. This is a scenario calculation, not a forecast; artifact size,
retrieval depth, revisions, and model pricing can change it. Docker, SQLite,
and local FTS add no model API charge.

## Prompt-injection status: final rerun pending

| Attack | Surface | Final release outcome |
|---|---|---|
| ATK-LOG-001 | Pipeline log | Pending credit-restored rerun |
| ATK-RAG-002 | Retrieved runbook | Pending credit-restored rerun |
| ATK-CSV-003 | Dataset cell | Pending credit-restored rerun |
| ATK-SCHEMA-004 | Schema description | Pending credit-restored rerun |

The attempted final run at
`evals/results/2026-11-22T004858Z-adversarial` did not execute the attacks to a
classifiable outcome. Its four records first surfaced as HTTP 500 failures; a
diagnostic rerun exposed the underlying OpenAI response: HTTP 429, “You have no
credits remaining.” These are provider failures, not successful attacks and
not proof of containment. All four final outcomes remain pending.

The earlier `2026-11-22T001152Z-adversarial` run recorded 4/4 blocked attacks,
but it predates the final evidence-context changes. It is retained only as a
pre-fix regression baseline and is not final release evidence. Likewise, any
4/4 prompt-injection metric mechanically merged from the failed final attempt
must be ignored: an incomplete execution cannot count as containment or attack
success.

## Failure analysis and mitigations

| Failure mode | Detection | Enforced mitigation |
|---|---|---|
| Unsupported or malformed model output | Pydantic validation failure | Reject response; no tool or mutation executes |
| Weak or stale retrieval evidence | Evidence grade below threshold | Refine the query within a three-round bound |
| Hypothesis contradicted by diagnostics | Observed signal fails verification | Record invalidation and create a bounded replacement plan |
| Repair outside the supported DSL or not justified by evidence | Manual disposition from proposal validator | Record escalation without a working copy |
| Stale, expired, or replayed approval | Hash, expiry, MAC, or nonce mismatch | Return conflict and consume no mutation authority |
| Later operation invalidates an earlier fix | Final-dataframe postcondition failure | Delete failed output and preserve the original |
| Prompt injection requests a capability | Policy and trace invariant failure | Reject unknown tools and preserve exact attack evidence |
| Provider unavailable or out of credit | Request failure before a classifiable workflow outcome | Fail closed and mark the evaluation unproven; rerun rather than infer safety |

## Reproduction and remaining release step

```powershell
.\.venv\Scripts\dii-run-evals.exe --limit 20
.\.venv\Scripts\python.exe -m evals.adversarial_runner `
  --summary evals\results\2026-11-22T003831Z\summary.json
```

After OpenAI credit is restored, rerun all four attacks against the definitive
release configuration, review the traces, replace the pending table with the
actual classifiable outcomes, and only then freeze the release evidence:

```powershell
.\.venv\Scripts\dii-freeze-evals.exe `
  --live-run evals\results\2026-11-22T003831Z `
  --adversarial-run evals\results\<credit-restored-adversarial-run> `
  --output submission\evaluation
```
