---
source_id: runbook.event-time.v1
title: Event Time Normalization
version: 1
effective_date: 2026-09-01
status: current
---

# Event Time Normalization

During the source migration, `created_at` may use RFC 3339 or
`MM/DD/YYYY hh:mm AM UTC`. Parse only those formats, normalize to RFC 3339 UTC,
reject other values, and preserve every row on a working copy.
