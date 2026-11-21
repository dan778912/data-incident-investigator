---
source_id: runbook.order-contract.v3
title: Order Ingestion Contract
version: 3
effective_date: 2026-10-01
status: current
---

# Order Ingestion Contract

The canonical order identifier is `order_id`. A source that emits
`order_identifier` may be adapted on a working copy with an explicit
`rename_column` operation.

`created_at` must be normalized to RFC 3339 UTC before final validation. A
candidate schema repair must be tested through all downstream assertions; a
passing column check alone is not proof that the incident is resolved. Mixed
timestamp formats may be parsed only with explicit accepted formats, and no row
may be dropped merely because parsing initially fails.

The original source is immutable. The complete repair plan requires human
approval after preview validation succeeds.
