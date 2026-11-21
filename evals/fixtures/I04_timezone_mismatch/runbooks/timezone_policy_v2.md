---
source_id: runbook.timezone-policy.v2
title: Event Timestamp Normalization Policy
version: 2
effective_date: 2026-08-01
status: current
---

# Event Timestamp Normalization Policy

Inbound event timestamps may include a numeric UTC offset. The ingestion layer
must parse that offset and convert the instant to UTC before applying event-time
windows. It must never strip an offset and then label the remaining wall-clock
value as UTC.

For `west-orders`, `created_at` is an RFC 3339 timestamp with an offset. A valid
repair preserves every row, converts the represented instant to a `Z` timestamp,
and then reruns the window assertion. The original source artifact is immutable;
repairs operate on a working copy only.
