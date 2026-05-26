# Assurix — AI Agent Development Guide

## Project Overview

Assurix is an **authorized autonomous security validation platform**. It takes an authorized target (web application, API, or codebase), orchestrates specialized AI agents to discover and analyze security issues, correlates findings in a graph-native knowledge model, and produces professional HTML reports with evidence and remediation guidance.

**Mission:** Provide validated, evidence-backed security findings — not scanner noise.

**Scope Boundary:** The platform operates only on explicitly authorized targets with ownership verification. It never targets arbitrary third-party assets. Safe, non-destructive testing is the default.

---

## Technology Decisions

| Layer | Technology | Rejected Alternatives | Rationale |
|---|---|---|---|
| API | FastAPI + Pydantic v2 | Django, Flask | Native async, auto-generated OpenAPI docs, dominant modern Python framework |
| Database | SQLite + SQLAlchemy 2.0 | PostgreSQL, Neo4j | Hard requirement: single local `.db` file. WAL mode handles concurrent reads |
| Graph | NetworkX + SQLite adjacency tables | Neo4j, KuzuDB | Python-native, 150+ graph algorithms, hydrate per engagement. KuzuDB reserved for Phase 3 |
| Orchestration | Custom asyncio engine | Temporal, Celery | Temporal is out of scope; Celery does not support SQLite as a broker. ~500 line engine |
| Browser | Playwright (Python async) | Selenium, Puppeteer | Required for SPAs; native async; network interception; headless Chromium |
| LLM | Ollama (local) | Claude API, OpenAI | No cloud API dependencies; no keys; runs offline. Tiered models |
| SAST | Semgrep CLI | CodeQL, Bandit | Fast, Python-friendly JSON output, custom rule DSL |
| HTTP Client | HTTPX async | requests, aiohttp | HTTP/2, connection pooling, async-native, modern API |
| Reports | Jinja2 + TailwindCSS + WeasyPrint | ReportLab, Playwright PDF | Self-contained HTML; WeasyPrint converts to PDF without browser |
| Frontend | SvelteKit 5 | Next.js, Streamlit | Easier than React/Next.js; builds to static files; excellent dashboard interactivity |

---

## Project Structure

```
assurix/
├── pyproject.toml                  # uv project config
├── README.md
├── .env.example
├── alembic/                        # Schema migrations (Alembic)
│   ├── env.py
│   └── versions/
├── data/
│   ├── assurix.db                  # SQLite production DB
│   └── artifacts/                  # HAR, screenshots, DOM snapshots, traces
├── frontend/                       # SvelteKit dashboard (separate build)
│   ├── src/routes/                 # Dashboard pages
│   └── src/lib/components/         # Reusable Svelte components
├── templates/                      # Jinja2 HTML report templates
│   └── report_base.html
├── src/
│   ├── api/
│   │   ├── main.py                 # FastAPI app factory
│   │   ├── deps.py                 # Dependency injection (DB session, current user)
│   │   └── routers/
│   │       ├── scans.py            # Start, list, get scan status
│   │       ├── findings.py         # List, filter, validate findings
│   │       ├── reports.py          # Generate, download HTML/PDF reports
│   │       ├── targets.py          # CRUD for authorized targets
│   │       └── policies.py         # Scope policy management
│   ├── db/
│   │   ├── session.py              # Async SQLAlchemy session factory
│   │   ├── models.py               # All ORM models
│   │   └── queries.py              # Complex query helpers
│   ├── graph/
│   │   ├── store.py                # NetworkX <-> SQLite bridge
│   │   ├── models.py               # Pydantic graph types
│   │   ├── algorithms.py           # PageRank, shortest path, chain detection
│   │   └── serializers.py          # Graph -> JSON for reports
│   ├── orchestrator/
│   │   ├── engine.py               # Core asyncio workflow engine
│   │   ├── state.py                # State machine + workflow routing
│   │   ├── scheduler.py            # PriorityQueue + SQLite job store
│   │   └── events.py               # Asyncio event bus
│   ├── agents/
│   │   ├── base.py                 # BaseAgent abstract class
│   │   ├── planner.py              # Strategic attack surface planner
│   │   ├── recon.py                # Surface mapper (crawler + prober)
│   │   ├── webapp.py               # OWASP DAST agent
│   │   ├── code.py                 # SAST / code intelligence agent
│   │   ├── api.py                  # API security agent
│   │   ├── config.py               # TLS/header/config agent
│   │   ├── auth.py                 # Authentication testing agent
│   │   ├── reasoner.py             # Verifier + attack path reasoner
│   │   ├── reporter.py             # Report composer agent
│   │   ├── browser/
│   │   │   ├── operator.py         # Playwright wrapper
│   │   │   ├── interceptor.py      # Network interception + HAR
│   │   │   ├── dom_graph.py        # DOM -> NetworkX graph
│   │   │   └── session.py          # Identity state manager
│   │   └── tools/
│   │       ├── httpx_client.py     # Async HTTP probe
│   │       ├── semgrep_runner.py   # Semgrep subprocess wrapper
│   │       └── fuzzer.py           # Lightweight async fuzzer
│   ├── llm/
│   │   ├── router.py               # Model tier selection
│   │   ├── client.py               # Ollama async client
│   │   ├── prompts/                # Jinja2 prompt templates
│   │   └── embeddings.py           # Embedding model wrapper
│   ├── core/
│   │   ├── config.py               # Pydantic Settings (.env)
│   │   ├── scope.py                # Scope validation + ownership verification
│   │   ├── policy.py               # Policy enforcement
│   │   ├── audit.py                # Immutable audit logger
│   │   └── exceptions.py           # Custom exceptions
│   ├── reporting/
│   │   ├── generator.py            # Report orchestrator
│   │   ├── html_render.py          # Jinja2 -> HTML
│   │   └── pdf_export.py           # WeasyPrint -> PDF
│   └── cli.py                      # Typer CLI entry point
├── tests/
│   ├── unit/                       # Agent logic, graph algorithms
│   ├── integration/                # End-to-end flows
│   └── fixtures/                   # Mock data, sample targets
└── docs/
    ├── architecture/               # Original architecture docs
    └── CLAUDE.md                   # This file
```

---

## Development Rules

### Language & Style
- **Python 3.12+** with full type hints on all public functions and classes
- **Async-first**: All I/O-bound code must use `async`/`await` (database, HTTP, Playwright, subprocess)
- **Pydantic v2** for all API request/response models and configuration
- **SQLAlchemy 2.0** style queries (select(), not session.query())
- **Ruff** for linting and formatting (configured in pyproject.toml)
- **Single responsibility**: One clear purpose per module; refactor when files exceed 400 lines

### Agent Development Guide

To add a new agent:

1. **Inherit `BaseAgent`** in `src/agents/base.py`:
   ```python
   class MyAgent(BaseAgent):
       name = "my_agent"

       async def execute(self, payload: dict) -> dict:
           # Agent logic here
           return {"findings": [...], "artifacts": [...]}
   ```

2. **Register in engine** (`src/orchestrator/engine.py`):
   ```python
   engine.register("my_agent", MyAgent)
   ```

3. **Add routing logic** in `src/orchestrator/state.py` if the agent participates in the cyclic workflow.

4. **Add prompt template** in `src/llm/prompts/` if the agent uses LLM reasoning.

5. **Add tests** in `tests/unit/test_my_agent.py`.

### Database Conventions
- Table names: snake_case, plural (e.g., `scope_policies`, `evidence_artifacts`)
- Column names: snake_case
- Use `JSON` columns (SQLAlchemy `JSON`) for flexible schema properties (e.g., graph node properties, audit params)
- Always use Alembic for schema migrations; never hand-edit the DB directly
- Foreign keys defined with `ON DELETE CASCADE` where appropriate
- All datetime columns: `DateTime(timezone=True)` with UTC

### Graph Conventions
- Graph nodes use UUID v4 string IDs (not integer PKs)
- Node types are lowercase snake_case: `asset`, `page`, `endpoint`, `code_symbol`, `finding_hypothesis`, `evidence_artifact`, `exploit_step`, `verified_finding`, `mitigation`
- Edge types are uppercase snake_case: `EXPOSES`, `CALLS`, `ACCESSED_AS`, `INFLUENCES`, `SUPPORTED_BY`, `REMEDIATED_BY`
- `GraphStore` methods are `async` because they read/write SQLite

---

## Security Rules

These are **non-negotiable** for every agent and tool.

1. **Scope validation before every request**
   - Every HTTP request from any agent routes through `src/core/scope.py`
   - Out-of-scope requests raise `ScopeViolationError` and abort the agent
   - Scope is verified at the network level, not just application logic

2. **Audit logging**
   - Every agent action, LLM invocation, and tool execution is logged to `audit_logs` with a Merkle chain hash
   - Logs are immutable; never delete or modify audit entries

3. **No secrets in code**
   - No API keys, tokens, or credentials in source files
   - All secrets loaded from `.env` via `Pydantic Settings`
   - Use `pydantic.SecretStr` for sensitive config values

4. **Subprocess sandboxing**
   - Semgrep and other CLI tools run in restricted subprocesses
   - File system access limited to target repo and artifact directories
   - Network disabled for SAST tools where possible

5. **Safe testing by default**
   - No destructive payloads (no `DROP`, `DELETE`, file deletion)
   - Boolean/time-based detection for injection vulnerabilities
   - Reflection-only XSS detection (no script execution)
   - Rate limiting enforced by policy engine

6. **Finding validation**
   - Every finding must have at least one evidence artifact
   - LLM-generated hypotheses must pass deterministic tool validation before becoming a verified finding
   - Only findings with `confidence_score >= 0.7` and `validated = true` appear in reports

---

## Testing Conventions

- **pytest** with `pytest-asyncio` for async tests
- **Naming**: `test_{component}_{scenario}_{expected}`
- **Fixtures**: `tests/fixtures/` contains mock LLM responses, sample HTML pages, expected scan outputs
- **Mocking**: Mock Ollama client in unit tests; use `httpx.AsyncMock` for HTTP tests
- **Coverage**: Aim for 80%+ on core modules (orchestrator, graph, scope, agents)
- **Integration tests**: Run against `http://testphp.vulnweb.com` (intentionally vulnerable test target)

---

## Common Commands

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest
uv run pytest tests/unit/test_graph_store.py -v

# Run API server
uv run uvicorn src.api.main:app --reload --port 8000

# Run CLI scan
uv run python -m assurix scan --target example.com

# Database migration
uv run alembic revision --autogenerate -m "add findings table"
uv run alembic upgrade head

# Frontend dev server
cd frontend && npm run dev

# Build frontend (output goes to static/ for FastAPI serving)
cd frontend && npm run build

# Lint and format
uv run ruff check .
uv run ruff format .

# Type check
uv run mypy src/
```

---

## Environment Variables

Create a `.env` file based on `.env.example`:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///data/assurix.db` | SQLite async connection string |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_FAST_MODEL` | `mistral:7b` | Lightweight model for classification |
| `OLLAMA_REASONING_MODEL` | `qwen2.5-coder:14b` | Heavy model for reasoning |
| `OLLAMA_EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model for dedup |
| `MAX_BROWSER_CONTEXTS` | `2` | Max concurrent Playwright contexts |
| `DEFAULT_RATE_RPS` | `10.0` | Default requests per second limit |
| `ARTIFACTS_DIR` | `./data/artifacts` | Evidence storage path |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `ENV` | `development` | `development`, `staging`, `production` |

---

## Critical File Reference

| File | Responsibility |
|---|---|
| `src/orchestrator/engine.py` | Custom asyncio workflow engine with SQLite durability |
| `src/graph/store.py` | NetworkX in-memory graph with SQLite persistence |
| `src/db/models.py` | All SQLAlchemy ORM models |
| `src/api/main.py` | FastAPI application factory |
| `src/agents/base.py` | BaseAgent abstract class |
| `src/core/scope.py` | Scope validation + ownership verification |
| `src/llm/router.py` | Model tier selection logic |
| `src/reporting/html_render.py` | Jinja2 report generation |
| `src/core/audit.py` | Immutable Merkle-chain audit logger |

---

## Architecture Principles (from ARCHITECTURE.md)

1. **Evidence over verbosity** — Every finding must have reproducible evidence
2. **Multi-agent specialization** — Specialized agents, not one monolithic agent
3. **Policy-bounded autonomy** — Scope, rate, and action limits enforced before execution
4. **Replayability** — Every step reproducible in a deterministic sandbox
5. **Graph-native reasoning** — Assets, findings, exploit steps, and mitigations as a graph

**When in doubt, prefer:**
- Deterministic validation over LLM-only claims
- Simple, explicit code over clever abstractions
- Safety boundaries over speed
- Evidence quality over finding quantity
