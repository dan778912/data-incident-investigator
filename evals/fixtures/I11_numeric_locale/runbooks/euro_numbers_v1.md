---
source_id: runbook.euro-numbers.v1
title: EUR Decimal Formatting
version: 1
effective_date: 2026-05-01
status: current
---

# EUR Decimal Formatting

The export uses a period as the thousands separator and a comma as the decimal
separator. For the frozen values, replace each documented representation with
its decimal form and cast `amount_eur` to float. Reject unknown formats rather
than guessing or coercing to null.
