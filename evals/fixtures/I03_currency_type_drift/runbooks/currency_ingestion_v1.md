---
source_id: runbook.currency-ingestion.v1
title: USD Amount Ingestion
version: 1
effective_date: 2026-05-12
status: current
---

# USD Amount Ingestion

`amount_usd` is a numeric dollar value. A source may prefix values with `$`.
For the bounded fixture values, replace the documented formatted strings with
their decimal representations and then cast the column to float. Reject any
unrecognized value rather than coercing it to null.
