---
source_id: runbook.customer-schema.v2
title: Customer Export Schema
version: 2
effective_date: 2026-09-15
status: current
replaces: runbook.customer-schema.v1
---

# Customer Export Schema - Version 2

Current customer exports identify a customer with `customer_id`. The export no
longer supplies `client_id`. Downstream consumers must update their mapping from
`client_id` to `customer_id`; they must not rename or rewrite the source export.

The source schema and data should both be checked before changing a mapping. A
mapping change is outside the approved data-remediation DSL. Reject a data patch,
preserve all source artifacts, and escalate the consumer-configuration update.
