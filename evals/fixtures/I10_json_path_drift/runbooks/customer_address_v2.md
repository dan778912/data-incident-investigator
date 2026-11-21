---
source_id: runbook.customer-address.v2
title: Customer Address Schema Migration
version: 2
effective_date: 2026-10-15
status: current
---

# Customer Address Schema Migration

Schema v2 emits the flattened path `address.postal_code`; the downstream
canonical path remains `address.zip`. On a working copy, `rename_column` may
adapt `address.postal_code` to `address.zip`. Postal-code values and row count
must remain unchanged.
