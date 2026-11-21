# Data Incident Investigator

Data Incident Investigator is a local-first agentic application for diagnosing data-pipeline
incidents. Its web interface is currently branded **Incident Lens**. A user uploads a CSV or JSON
dataset plus optional logs, schemas, and runbooks; the workflow retrieves evidence, tests and
revises hypotheses, cites its sources, and pauses for human approval before creating a remediated
working copy.

This is a solo capstone project targeted for December 10, 2026. It is intentionally narrow: the
agent can investigate uploaded artifacts, but it cannot run arbitrary code, access production
systems, or modify an original dataset.

## Capstone feature claims

The submission claims exactly three advanced capabilities:

1. **Multi-step planning with self-correction.** Diagnostic hypotheses are checked against
   deterministic observations and revised when evidence contradicts them.
2. **Agentic RAG with iterative retrieval.** The workflow grades retrieved evidence, refines an
   insufficient query, and preserves source/chunk citations.
3. **Persistent human-in-the-loop approval.** A durable LangGraph interrupt blocks remediation
   until a human accepts the exact proposal, plan, and source hashes.

SQLite persistence and restart-safe checkpoints support these features but are not claimed as a
fourth advanced capability.

## Current status

| Area | Status |
|---|---|
| Deterministic end-to-end workflow | Working and covered by integration tests |
| React investigation/approval dashboard | Working in mock mode and connected to the live API |
| OpenAI structured-reasoning adapter | Implemented with structured outputs, low reasoning effort, and token/cost accounting; live-key evaluation remains |
| Signed approval and replay protection | Working with a durable SQLite nonce ledger |
| Typed remediation on immutable working copies | Working with final-state post-fix checks and manual escalation outside the safe DSL |
| Evaluation system | All 20 fixtures are populated; live and adversarial operating-system runners emit auditable traces and reports |
| Container and CI | Remote CI passed backend, frontend, and container jobs; local Docker rehearsal remains |
| Submission artifacts | Process log, 13-slide deck, and seven-minute demo script are drafted; the live-result report and recorded video remain |

The default `LLM_PROVIDER=fake` is deliberate. It gives development and CI a reproducible scenario
that visibly performs an insufficient retrieval, refines the query, disproves a null hypothesis,
revises to a type-drift hypothesis, and stops for approval. `LLM_PROVIDER=openai` enables the live
typed-reasoning services.

## Safety boundary

- Uploads have type, extension, size, UTF-8, and JSON validation before storage.
- Artifact identifiers are resolved inside case-scoped directories; model output never supplies a
  filesystem path.
- Retrieved text and diagnostic output are labeled as untrusted data in model instructions.
- Model responses must match Pydantic schemas, then pass deterministic ownership and policy checks.
- Only allowlisted, read-only diagnostic tools can run.
- Remediation is a typed DSL; there is no shell, Python, or free-form SQL tool.
- The original SHA-256 is checked before and after remediation, and output goes to a new file.
- Approval is HMAC-bound to the case, proposal, diagnostic plan, sources, expiry, and one-time nonce.
- CSV output escapes spreadsheet-formula prefixes.
- Secrets are redacted before retrieved text enters prompts and are never committed.

## Native quick start (Windows)

Requirements: Python 3.13, Node.js 22, npm, and Git.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
npm --prefix web ci
Copy-Item .env.example .env
.\scripts\dev.ps1
```

Open `http://127.0.0.1:5173`. The development script starts FastAPI on port 8000, starts Vite in
live-API mode, stores logs below ignored `tmp/dev/`, and stops the API when the frontend exits.
Use `-ApiPort` or `-WebPort` if either default port is occupied.

To run the compiled single-process application instead:

```powershell
$env:VITE_API_MODE = "live"
npm --prefix web run build
.\.venv\Scripts\dii-api.exe
```

FastAPI then serves both the API and `web/dist` at `http://127.0.0.1:8000`.

## Enable live OpenAI reasoning

Edit the ignored `.env` file locally:

```dotenv
LLM_PROVIDER=openai
OPENAI_API_KEY=your-key-here
OPENAI_MODEL=gpt-6.2-astra
```

Do not paste an API key into an issue, chat, commit, screenshot, or evaluation artifact. The live
adapter uses the Responses API with Pydantic structured outputs and `store=False`. Changing to the
live provider does not broaden the tool boundary: the model proposes typed data, while application
code owns retrieval, diagnostics, approval, and file changes.

NVIDIA credentials are not required for the committed scope. The configuration reserves an NVIDIA
provider name, but that adapter is intentionally not implemented unless evaluation shows a concrete
need for it.

## What “install Docker later” means

Docker is optional for building and using the project during development. On Windows, installing it
usually means adding Docker Desktop with its WSL 2 backend so the final container can be rehearsed
locally. That can consume several gigabytes and may require a restart, which is why it is not a
day-one dependency.

The repository already contains the Docker configuration, and CI builds it on every change. Local
installation is only needed before the final demo to verify this command on the presentation
machine:

```powershell
# In .env, set a random value of at least 32 characters for APPROVAL_HMAC_KEY.
docker compose up --build
```

The container builds the React UI, installs the Python service, runs as a non-root user, exposes only
localhost port 8000, uses a read-only root filesystem, and persists cases/checkpoints in a named
volume. Docker does not require another LLM or create extra API charges by itself.

## Verification

Run the complete local quality gate:

```powershell
.\scripts\test.ps1
```

It runs Ruff lint/format checks, strict mypy, backend tests with branch coverage, frontend tests, and
a production frontend build. Individual commands are also available:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy
npm --prefix web test
npm --prefix web run build
```

Run the real 20-case workflow suite after setting `OPENAI_API_KEY` in the ignored `.env` file:

```powershell
dii-run-evals --limit 20
```

The command writes dated raw states, schema-validated traces, observations, a machine-readable
summary, and a Markdown report beneath ignored `evals/results/`. Run the prompt-injection suite
against staged copies of the frozen fixtures, then merge its frontend records into that live
summary:

```powershell
python -m evals.adversarial_runner `
  --summary evals\results\<live-run>\summary.json
```

The provider-neutral grader can also grade previously captured JSONL observations:

```powershell
dii-eval --manifest evals/manifest.jsonl `
  --observations path\to\observations.jsonl `
  --format markdown `
  --output evals\results\YYYY-MM-DD\report.md
```

Reported capstone metrics will come from dated live-model operating-system runs, not the fake
provider or UI fixtures.

## Repository layout

```text
src/data_incident_investigator/  FastAPI service, graph, policies, and provider adapters
web/                             React/TypeScript interface
tests/                           Unit and integration tests
evals/                           Frozen corpus, adversarial cases, schemas, and grader
docs/                            Architecture and delivery plan
scripts/                         Native development and verification commands
data/                            Ignored local databases and case artifacts
```

## API outline

- `GET /api/health` and `GET /api/ready`
- `POST /api/cases`, `GET /api/cases`, and `GET /api/cases/{case_id}`
- `POST /api/cases/{case_id}/artifacts`
- `POST /api/cases/{case_id}/analyze`
- `GET /api/cases/{case_id}/investigation`
- `POST /api/cases/{case_id}/approval`
- `GET /api/artifacts/{artifact_id}/download`
- `GET /api/evaluations/latest`

Interactive API documentation is available at `/docs` while the service is running.

## Capability-to-Code Map

The submission-grade [capability-to-code map](docs/CAPABILITY_MAP.md) ties every advanced feature,
enforceable guardrail, evaluation claim, persistence boundary, and deployment claim to exact source
lines, key classes/functions, and scoped verification notes.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component and trust-boundary design,
[docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) for the delivery schedule and definition of done, and
[docs/EVALUATION_REPORT.md](docs/EVALUATION_REPORT.md) for the evaluation protocol and pending live
results.
