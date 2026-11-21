---
source_id: runbook.customer-schema.v1
title: Customer Export Schema
version: 1
effective_date: 2025-03-01
status: superseded
superseded_on: 2026-09-15
superseded_by: runbook.customer-schema.v2
---

# Customer Export Schema - Version 1

Historical exports identify a customer with the `client_id` column. Consumers
written against this version map `customer_key` to `client_id`.

This document is retained for audit history. It is not the current production
contract after 2026-09-15. Follow the `superseded_by` metadata before proposing
a mapping change.
