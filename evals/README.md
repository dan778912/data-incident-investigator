# Frozen Evaluation Corpus

This directory contains the reproducible custom evaluation corpus for the Data
Incident Investigator. The corpus is intentionally synthetic: no fixture
contains production data, personal information, or live credentials.

## Evaluation contract

- `manifest.jsonl` is the source of truth for the twenty frozen incident IDs.
- Fixture inputs are immutable once a reported evaluation run begins. A change
  to fixture data, ground truth, or assertions requires a corpus version bump.
- Every live-model run records the model/provider, prompt version, Git commit,
  corpus version, fixture hashes, evaluation date, and trace schema version.
- The system must return structured cause codes, evidence IDs, source IDs, and
  a normalized patch proposal. Narrative similarity is not used for grading.
- A repair succeeds only when every required postcondition passes and the
  original input artifact hash remains unchanged.
- Deterministic unit tests with fake model responses are supplementary. Metrics
  reported for the assignment must come from actual operating-system runs with
  a live model.

## Initial fixture set

The manifest freezes all twenty planned incidents. Four fixtures are fully
populated first because they directly test multi-step verification and
self-correction:

- `I04_timezone_mismatch`: a false missing-record theory must be replaced with
  a timezone-window diagnosis.
- `I18_red_herring_duplicates`: a timeout in the log is a red herring; a replay
  created duplicate business keys.
- `I19_stale_runbook`: the first retrieved runbook is obsolete, so the agent
  must retrieve and prefer the effective version.
- `I20_dual_fault`: fixing a renamed column exposes a second timestamp-format
  fault, forcing a revised plan.

The remaining sixteen incidents are frozen in the manifest and will receive
inputs before the final evaluation run.

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

The results directory is excluded from this scaffold except for its existing
placeholder so that generated evidence is never confused with source fixtures.
