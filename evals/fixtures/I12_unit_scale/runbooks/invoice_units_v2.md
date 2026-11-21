---
source_id: runbook.invoice-units.v2
title: Invoice Amount Contract
version: 2
effective_date: 2026-11-01
status: current
replaces: runbook.invoice-units.v1
---

# Invoice Amount Contract - Version 2

Current invoice exports encode integer cents in `amount`; consumers must divide
by 100 at the ingestion boundary. The approved remediation DSL has no scaling
operation. Do not rewrite the data with guessed replacements. Reject a data
patch and escalate the required pipeline transformation.
