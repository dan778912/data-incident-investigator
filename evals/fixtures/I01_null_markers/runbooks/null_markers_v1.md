---
source_id: runbook.null-markers.v1
title: Priority Code Null Semantics
version: 1
effective_date: 2026-06-01
status: current
---

# Priority Code Null Semantics

For `priority_code`, the literal `N/A` means "not applicable" and is valid data.
Only an empty field or the literal `NULL` represents a missing value. If a CSV
reader converts `N/A` to null, restore the domain meaning with the durable
canonical value `NOT_APPLICABLE` on a working copy using `fill_missing`. Preserve
all rows and the original file.
