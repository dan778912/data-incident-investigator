---
source_id: runbook.task-status.v2
title: Task Status Vocabulary Migration
version: 2
effective_date: 2026-11-10
status: current
---

# Task Status Vocabulary Migration

The source now emits `completed`; the downstream canonical value remains
`complete`. On a working copy, replace `completed` with `complete`. Preserve
`in_progress`, all task IDs, and the row count.
