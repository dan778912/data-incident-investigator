# Individual Process Log

I designed Incident Lens as an original, local-first agent for diagnosing CSV and JSON pipeline incidents. I narrowed the scope to evidence retrieval, read-only diagnostics, typed remediation, and human approval so I could deliver one complete workflow rather than several shallow features. I first used a deterministic provider to exercise retrieval refinement and plan revision, then integrated OpenAI and NVIDIA Nemotron through the same structured-model interface.

Codex was my sole AI development assistant. I used it to help draft architecture, code, tests, reviews, and documentation. Its generated code required my review and verification; I did not adapt source code from another student, tutorial, or external project. Course-standard frameworks and libraries are used through their documented APIs.

I verified the implementation by inspecting diffs, running formatting, linting, strict type checking, backend and frontend tests, GitHub Actions, and live browser rehearsals. I also built a twenty-incident evaluation harness and executed four prompt-injection attacks across logs, runbooks, dataset cells, and schema text. The release evidence preserves traces, token usage, source hashes, approval behavior, and post-fix checks.

Evaluation drove several important changes. I added bounded and redacted log evidence, canonical datetime formats, deterministic cause-code policy, HMAC-bound single-use approvals, final-dataframe postconditions, and fail-closed handling for malformed model output or unavailable providers. I retained the I18 manual escalation because the evidence could not prove a safe duplicate ordering rule.

My main lesson was that an agentic claim is credible only when it is observable outside the prompt. Structured output alone is insufficient; evidence ownership, tool permissions, approval authority, mutations, and evaluation outcomes must all be enforced and reproducible in application code.
