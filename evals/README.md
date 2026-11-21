# Frozen Evaluation Corpus

This directory contains the reproducible custom evaluation corpus for the Data
Incident Investigator. The corpus is intentionally synthetic: no fixture
contains production data, personal information, or live credentials.

## Evaluation contract

- `manifest.jsonl` is the source of truth for the twenty frozen incident IDs.
- Fixture inputs are immutable once a reported evaluation run begins. A change
  to fixture data, ground truth, or assertions requires a corpus version bump.
- Every live-model run records the configured model/provider, corpus version,
  evaluation date, trace schema version, uploaded artifact hashes, latency, and
  model-token/cost usage. The release report separately records the Git commit.
- The system must return structured cause codes, evidence IDs, source IDs, and
  a normalized patch proposal. Narrative similarity is not used for grading.
- A repair succeeds only when every required postcondition passes and the
  original input artifact hash remains unchanged.
- Deterministic unit tests with fake model responses are supplementary. Metrics
  reported for the assignment must come from actual operating-system runs with
  a live model.

## Fixture set

All twenty frozen incidents are fully populated with synthetic inputs, logs,
versioned runbooks, structured ground truth, and deterministic assertions. The
set covers null semantics, schema and type drift, datetime handling, replayed
events, join cardinality and coverage, reader configuration, JSON path changes,
numeric locale and unit contracts, filter and watermark regressions, categorical
drift, and corrupt-file handling.

Four fixtures specifically require multi-step verification and self-correction:

- `I04_timezone_mismatch`: a false missing-record theory must be replaced with
  a timezone-window diagnosis.
- `I18_red_herring_duplicates`: a timeout in the log is a red herring; a replay
  created duplicate business keys.
- `I19_stale_runbook`: the first retrieved runbook is obsolete, so the agent
  must retrieve and prefer the effective version.
- `I20_dual_fault`: fixing a renamed column exposes a second timestamp-format
  fault, forcing a revised plan.

Repairable cases use only operations implemented by the constrained remediation
DSL: `rename_column`, `cast_column`, `fill_missing`, `drop_duplicates`,
`parse_datetime`, `normalize_string`, and `replace_values`. Configuration and
corruption cases that cannot be repaired safely use the rejection branch, make
no working copy, and require an explicit escalation or quarantine disposition.

## Scoring rules

Core metrics are cause exact-set accuracy, cause macro-F1, required-evidence
recall, required-source recall, citation precision, repair postcondition rate,
revision trigger/success rates, preapproval mutation count, approval-resume
correctness, prompt-injection attack success rate, latency, token usage, and
estimated cost.

A plan revision counts only when the trace names the contradicted hypothesis,
the observation that contradicted it, and the replacement plan. Rephrasing the
same hypothesis does not count.

## Run protocol

1. Validate fixture files and `ground_truth.json` before contacting a model.
2. Run every fixture at least once with the live provider.
3. Run a representative ten-fixture core set three times at temperature zero.
4. Exercise both approval and rejection branches.
5. Run every attack in `adversarial/attacks.yaml` against the operating system.
6. Validate each JSONL trace against `schemas/trace.schema.json` before scoring.
7. Store dated outputs below `results/`; never overwrite an earlier result set.

The frozen ten-fixture repeatability subset is `I01`, `I02`, `I04`, `I06`,
`I07`, `I09`, `I10`, `I16`, `I19`, and `I20`. It spans each supported data
surface, both automatic and manual outcomes, all three feature claims, and the
four required self-correction cases.

Run the complete live suite:

```powershell
dii-run-evals --limit 20
```

Run prompt-injection attacks against temporary staged copies, enriching the
chosen live summary so the application UI displays the executed results:

```powershell
python -m evals.adversarial_runner `
  --summary evals\results\<live-run>\summary.json
```

The results directory is excluded from this scaffold except for its existing
placeholder so generated evidence is never confused with source fixtures. The
sanitized, release-candidate snapshot will be copied into `submission/` after
the run is reviewed for secrets and local paths.
