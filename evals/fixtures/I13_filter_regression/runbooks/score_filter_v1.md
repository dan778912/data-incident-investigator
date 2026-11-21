---
source_id: runbook.score-filter.v1
title: Quality Score Eligibility
version: 1
effective_date: 2026-01-10
status: current
---

# Quality Score Eligibility

Records with `quality_score >= 0.75` are eligible. The runtime threshold is a
pipeline configuration, not a data field. The approved data-remediation DSL
cannot edit configuration files, so reject a data patch and escalate restoring
`minimum_quality_score` to `0.75`.
