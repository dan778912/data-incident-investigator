---
source_id: runbook.event-watermark.v1
title: Event Lateness Policy
version: 1
effective_date: 2026-04-01
status: current
---

# Event Lateness Policy

The source service-level objective permits events up to 15 minutes late. The
watermark is pipeline configuration and cannot be changed by the approved data
patch DSL. Reject a data repair, preserve the source file, and escalate restoring
the watermark to 15 minutes.
