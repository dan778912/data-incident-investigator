---
source_id: runbook.customer-id.v2
title: Customer Identifier Migration
version: 2
effective_date: 2026-11-01
status: current
---

# Customer Identifier Migration

Source schema v2 emits `customerId`; the canonical downstream name remains
`customer_id`. Consumers may adapt a working copy with `rename_column` from
`customerId` to `customer_id`. Identifier values and row count must not change.
