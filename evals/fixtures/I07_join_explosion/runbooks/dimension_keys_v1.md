---
source_id: runbook.dimension-keys.v1
title: Customer Dimension Cardinality
version: 1
effective_date: 2026-07-01
status: current
---

# Customer Dimension Cardinality

The current customer dimension must contain one row per `customer_id`. Versioned
extracts are sorted oldest to newest. On a working copy, retain the last row for
each customer with `drop_duplicates`. A valid order-to-customer join preserves
the order row count.
