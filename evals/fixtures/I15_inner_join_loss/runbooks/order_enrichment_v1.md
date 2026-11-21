---
source_id: runbook.order-enrichment.v1
title: Order Customer Enrichment
version: 1
effective_date: 2026-03-15
status: current
---

# Order Customer Enrichment

Customer enrichment must preserve every order with a left join. Unmatched
customer IDs are retained and routed to a review queue. Join type is pipeline
configuration outside the approved data patch DSL. Reject a data rewrite and
escalate changing the join from inner to left.
