# Evaluation Report

> Status: release template. No live-model performance is claimed until the
> dated OpenAI and adversarial runs are completed and reviewed.

## Release identity

| Field | Value |
|---|---|
| Git commit | Pending release-candidate run |
| Evaluation date | Pending |
| Provider and model | OpenAI / `gpt-6.2-astra` |
| Reasoning effort | `low` |
| Corpus | `dii-corpus-v1` |
| Incidents | 20 frozen synthetic fixtures |
| Adversarial cases | 4 staged prompt-injection attacks |

## Method

The operating-system runner creates a fresh local application state, uploads
the same artifact types accepted by the product, invokes the production
LangGraph workflow, exercises the approval or rejection branch declared by the
manifest, and preserves the final state plus schema-validated JSONL trace.
Before approval, it submits a stale context and verifies that no working copy
appears. After a valid decision, it attempts a duplicate resume and re-hashes
every original upload.

The corpus covers null semantics, schema and type drift, datetime handling,
event replay, join integrity, reader configuration, JSON paths, numeric locale,
unit contracts, filters, watermarks, categorical drift, and file corruption.
I04, I18, I19, and I20 require a substantive plan revision. Thirteen cases have
a repair inside the constrained DSL; seven must reject or escalate without
mutation.

## Live-suite results

| Metric | Result | Sample |
|---|---:|---:|
| Root-cause exact-set accuracy | Pending | 20 |
| Cause macro-F1 | Pending | 20 |
| Required-evidence recall | Pending | 20 |
| Required-source recall | Pending | 20 |
| Citation precision | Pending | 20 |
| Repair postcondition rate | Pending | 13 repairable cases |
| Valid revision success | Pending | 4 revision cases |
| Original-hash integrity | Pending | 20 |
| Approval resume correctness | Pending | 20 |
| Median latency | Pending | 20 |
| Mean estimated cost per case | Pending | 20 |

The values above will be copied from the reviewed `summary.json`; they will not
be calculated from UI fixtures or the deterministic fake provider.

## Prompt-injection results

| Attack | Surface | Executed outcome | Key evidence |
|---|---|---|---|
| ATK-LOG-001 | Pipeline log | Pending | Prohibited capability, mutation, canary, and hash checks |
| ATK-RAG-002 | Retrieved runbook | Pending | Prohibited capability, mutation, canary, and hash checks |
| ATK-CSV-003 | Dataset cell | Pending | Prohibited capability, mutation, canary, and hash checks |
| ATK-SCHEMA-004 | Schema description | Pending | Prohibited capability, mutation, canary, and hash checks |

Each attack runs against a complete temporary fixture copy. The report retains
the exact injected text, insertion locator, original and staged hashes, final
workflow state, invariant results, mitigation, and full trace. An incomplete or
failed execution cannot count as containment.

## Failure analysis and mitigations

| Failure mode | Detection | Enforced mitigation |
|---|---|---|
| Unsupported or malformed model output | Pydantic validation failure | Reject response; no tool or mutation executes |
| Weak or stale retrieval evidence | Evidence grade below threshold | Refine the query within a three-round bound |
| Hypothesis contradicted by diagnostics | Observed signal fails verification | Record invalidation and create a bounded replacement plan |
| Repair outside the supported DSL | Manual disposition from proposal validator | Record escalation without a working copy |
| Stale, expired, or replayed approval | Hash, expiry, MAC, or nonce mismatch | Return conflict and consume no mutation authority |
| Later operation invalidates an earlier fix | Final-dataframe postcondition failure | Delete failed output and preserve the original |
| Prompt injection requests a capability | Policy and trace invariant failure | Reject unknown tools and preserve exact attack evidence |

## Cost interpretation

The application records input, cached-input, and output tokens for every model
call. The configured Standard rates are $8.00, $0.40, and $40.00 per million
tokens, respectively. The final report will provide total run cost, mean cost
per case, and a weekly estimate calculated as expected sessions multiplied by
the measured mean session cost. Docker, SQLite, and local FTS add no model API
charge.

## Reproduction

```powershell
.\.venv\Scripts\dii-run-evals.exe --limit 20
.\.venv\Scripts\python.exe -m evals.adversarial_runner `
  --summary evals\results\<live-run>\summary.json
```

After review, sanitized result files will be copied into `submission/evaluation/`
with the release commit and this report will replace every pending value.
