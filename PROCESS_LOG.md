# Individual Process Log

I built Incident Lens, an original, local-first agent for diagnosing CSV and JSON pipeline incidents. I deliberately limited it to evidence retrieval, read-only diagnostics, typed remediation, and human approval because completing one workflow mattered more than building several shallow features. I began with a deterministic provider to test retrieval refinement and plan revision reliably, then added OpenAI and NVIDIA Nemotron through the same structured-model interface.

Codex was the only AI tool I used. It helped draft the architecture, code, tests, reviews, and documentation, but I reviewed and verified everything it generated. I did not copy or adapt code from another student, tutorial, or outside project. Course-standard frameworks and libraries are used through their documented APIs.

I verified the project by inspecting diffs and running formatting, linting, strict type checking, backend and frontend tests, GitHub Actions, and live browser rehearsals. I also built a twenty-incident evaluation harness and ran four prompt-injection attacks through logs, runbooks, dataset cells, and schema text. The frozen evidence preserves traces, token usage, source hashes, approval behavior, and post-fix checks.

Evaluation results drove several changes: bounded and redacted log evidence, canonical datetime formats, a deterministic cause-code policy, HMAC-bound single-use approvals, final-dataframe postconditions, and fail-closed handling for malformed model output or unavailable providers. I kept the I18 manual escalation because the evidence could not prove a safe duplicate ordering rule.

My main lesson is that an agentic claim is believable only when it can be observed outside the prompt. Structured output is not enough by itself. Evidence ownership, tool permissions, approval authority, mutations, and evaluation outcomes must all be enforced and reproducible in application code.
