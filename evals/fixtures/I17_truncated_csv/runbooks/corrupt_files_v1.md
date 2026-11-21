---
source_id: runbook.corrupt-files.v1
title: Corrupt Extract Handling
version: 1
effective_date: 2026-01-05
status: current
---

# Corrupt Extract Handling

An unexpected end of file inside a quoted CSV field indicates truncation. Do
not guess the missing bytes, drop the malformed row, or rewrite the evidence.
The approved patch DSL cannot safely reconstruct the file. Reject remediation,
quarantine the artifact, and request a fresh export from the source system.
