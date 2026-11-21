---
source_id: runbook.payment-reader.v1
title: European Payment Export Reader
version: 1
effective_date: 2026-08-20
status: current
---

# European Payment Export Reader

Payment exports are UTF-8 and semicolon-delimited. A comma/ASCII reader is a
pipeline-configuration fault. The remediation DSL cannot change reader settings,
so do not rewrite the input or propose a data patch. Reject remediation and
escalate the required delimiter and encoding configuration change.
