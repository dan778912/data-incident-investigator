---
source_id: runbook.replay-idempotency.v1
title: Event Replay Idempotency
version: 1
effective_date: 2026-03-01
status: current
---

# Event Replay Idempotency

Replayed events retain the same `event_id` and increment `event_version`.
Inputs are ordered by version, so a bounded repair may use `drop_duplicates`
with key `event_id` and `keep=last`. Validate that three unique IDs remain and
that the original file is unchanged.
