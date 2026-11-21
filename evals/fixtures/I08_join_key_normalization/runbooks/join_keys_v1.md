---
source_id: runbook.join-keys.v1
title: Product Join-Key Normalization
version: 1
effective_date: 2026-02-15
status: current
---

# Product Join-Key Normalization

Product SKUs are lowercase canonical strings. Source exports may contain leading
or trailing whitespace and mixed casing. Normalize the `sku` string on a working
copy with trimming and case folding enabled, then verify complete join coverage.
