---
source_id: runbook.replay-recovery.v1
title: Replay and Duplicate Event Recovery
version: 1
effective_date: 2026-04-10
status: current
---

# Replay and Duplicate Event Recovery

A timeout followed by `retry status=success` is a recovered transport event, not
evidence of a continuing outage. If a retry or replay delivers multiple versions
of the same business key, retain the row with the greatest `event_version`; use
`updated_at` as a deterministic tie breaker.

Never delete every copy of a duplicated key. Run deduplication on a working copy,
verify one row remains for each `order_id`, and require human approval before the
working copy becomes the repair artifact. Source files remain immutable.
