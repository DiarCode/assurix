# Assurix — Architecture & Technical Reference

## Overview

Assurix is an **authorized autonomous security validation platform** that combines LLM-driven browser agents with HTTP-level scanning to perform deep, reasoning-based security testing of web applications. Unlike traditional DAST scanners that run static checklists, Assurix uses AI browser agents (powered by Ollama/cloud LLMs) that navigate, interact with, and reason about web applications like a human pentester — clicking links, filling forms, analyzing responses, and chaining vulnerabilities into attack paths.

**Key differentiator**: The platform runs cyclic iterations (planner → recon → webapp → reasoner → reporter) where each cycle deepens understanding, and the AI browser agent can autonomously discover vulnerabilities that scripted scanners miss.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLI (Typer)                              │
│  assurix scan <url> [--iterations N] [--parallel N]              │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                    WorkflowEngine (Orchestrator)                  │
│  Manages engagement lifecycle, job queue, agent routing          │
│  Cycle: planner → recon → webapp → reasoner → reporter/planner  │
└──────┬──────────┬──────────┬──────────┬──────────┬─────────────┘
       │          │          │          │          │
  ┌────▼───┐ ┌───▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼──────┐
  │Planner │ │ Recon │ │ Webapp │ │Reasoner│ │ Reporter │
  │ Agent  │ │ Agent │ │ Agent  │ │ Agent  │ │  Agent   │
  └────────┘ └───┬───┘ └───┬────┘ └────────┘ └──────────┘
                  │          │
        ┌─────────▼──────────▼─────────┐
        │     AIBrowserOperator          │
        │  (browser-use + OllamaChatLLM) │
        │                                │
        │  ┌──────────┐  ┌────────────┐  │
        │  │ Security  │  │  Finding   │  │
        │  │  Tools    │  │  Memory    │  │
        │  └──────────┘  └────────────┘  │
        │                                │
        │  ┌──────────────────────────┐  │
        │  │   BrowserSession          │  │
        │  │   (Playwright/Chromium)   │  │
        │  └──────────────────────────┘  │
        └────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  Ollama LLM  │
                    │ (cloud/local) │
                    └──────────────┘
```

### Agent Pipeline

| Stage | Agent | LLM Tier | Purpose |
|-------|-------|-----------|---------|
| 1 | Planner | Fast (gemma4:31b) | Analyze surface data, produce strategic testing directives |
| 2 | Recon | Fast (HTTPX) + Reasoning (AI browser) | Map attack surface via HTTPX crawl + AI-driven browser exploration |
| 3 | Webapp | Fast (HTTP checks) + Reasoning (AI browser) | Run HTTP-level checks + parallel AI vulnerability investigations |
| 4 | Reasoner | Reasoning (deepseek-v4-flash) | Deduplicate, validate, score confidence, infer attack paths |
| 5 | Reporter | Fast (gemma4:31b) | Compose executive summary + generate MD report |

The cycle repeats if `iteration_count < max_iterations`, feeding findings back into the Planner for deeper investigation.

---

## Project Structure

```
assurix/
├── src/
│   ├── agents/
│   │   ├── base.py                    # BaseAgent abstract class
│   │   ├── planner.py                 # Strategic planning agent
│   │   ├── recon.py                   # Surface mapper (HTTPX + AI browser)
│   │   ├── webapp.py                  # DAST agent (HTTP checks + AI browser)
│   │   ├── reasoner.py                # Finding validation + attack path analysis
│   │   ├── reporter.py                # Report composition + MD generation
│   │   └── browser/
│   │       ├── ai_operator.py         # AI browser agent (browser-use wrapper)
│   │       ├── llm_adapter.py         # OllamaChatLLM (browser-use compatible)
│   │       ├── security_tools.py      # Custom browser-use security tools
│   │       ├── prompts.py             # LLM task prompts for each scan type
│   │       ├── memory.py              # MD file-based finding memory
│   │       ├── operator.py            # Legacy scripted Playwright operator (deprecated)
│   │       └── __init__.py
│   ├── core/
│   │   ├── config.py                  # Pydantic Settings (env-based config)
│   │   ├── audit.py                   # Audit logging
│   │   ├── exceptions.py             # Custom exceptions
│   │   ├── policy.py                 # Scope policy enforcement
│   │   └── scope.py                   # Target scope validation
│   ├── db/
│   │   ├── models.py                  # SQLAlchemy ORM models
│   │   └── session.py                # Async SQLite session management
│   ├── graph/
│   │   ├── models.py                  # Graph node/edge models
│   │   └── store.py                   # Graph persistence
│   ├── llm/
│   │   ├── client.py                  # OllamaClient (direct HTTP calls)
│   │   ├── router.py                  # ModelRouter (tier selection)
│   │   └── embeddings.py             # Embedding generation
│   ├── orchestrator/
│   │   ├── engine.py                  # WorkflowEngine (async job loop)
│   │   ├── state.py                   # WorkflowRouter + EngagementStateMachine
│   │   ├── events.py                  # EventBus for engagement events
│   │   └── scheduler.py               # JobScheduler (priority queue)
│   ├── api/
│   │   ├── main.py                    # FastAPI application
│   │   ├── deps.py                    # Dependency injection
│   │   └── routers/
│   │       ├── targets.py             # Target CRUD
│   │       ├── scans.py               # Scan lifecycle
│   │       ├── findings.py            # Finding queries
│   │       ├── reports.py             # Report retrieval
│   │       └── policies.py            # Policy management
│   ├── reporting/
│   │   └── md_report.py               # Markdown report generator
│   └── cli.py                         # Typer CLI entry point
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── data/
│   └── artifacts/                     # Evidence artifacts (screenshots, DOM, HAR)
├── docs/
├── .env                               # Environment configuration
├── .env.example                       # Template for .env
└── pyproject.toml                     # Project metadata & dependencies
```

---

## Configuration (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `https://ollama.com` | Ollama server URL (cloud or local) |
| `OLLAMA_API_KEY` | (empty) | Bearer token for Ollama Cloud |
| `OLLAMA_REASONING_MODEL` | `deepseek-v4-flash` | Heavy model for reasoning/analysis |
| `OLLAMA_FAST_MODEL` | `gemma4:31b` | Lightweight model for classification/extraction |
| `OLLAMA_EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model (always local) |
| `BROWSER_USE_HEADLESS` | `true` | Run browser-use in headless mode |
| `BROWSER_USE_MAX_STEPS` | `50` | Max steps per browser-use agent run |
| `BROWSER_USE_KEEP_ALIVE` | `true` | Keep browser session alive between runs |
| `PARALLEL_AGENTS` | `3` | Max parallel AI investigation sub-agents |
| `MAX_ITERATIONS_PER_SCAN` | `50` | Max planner cycles per engagement |
| `SAFE_MODE` | `true` | Non-destructive testing only |
| `DATABASE_URL` | `sqlite+aiosqlite:///data/assurix.db` | Async SQLite connection |
| `ARTIFACTS_DIR` | `./data/artifacts` | Evidence output directory |
| `API_HOST` / `API_PORT` | `0.0.0.0:8000` | FastAPI server bind address |

---

## LLM Integration

### Two Integration Paths

1. **OllamaClient** (`src/llm/client.py`) — Direct HTTP calls to Ollama for planner, reasoner, and reporter agents. Uses `ollama.AsyncClient` for chat completions with structured JSON output.

2. **OllamaChatLLM** (`src/agents/browser/llm_adapter.py`) — Custom adapter implementing browser-use's `BaseChatModel` protocol. Used by `AIBrowserOperator` to drive autonomous browser exploration.

### OllamaChatLLM Adapter

The browser-use library requires an LLM that implements its `BaseChatModel` protocol (with `ainvoke()`, `provider`, `name`, `model_name` properties). The native `browser_use.llm.ollama.chat.ChatOllama` works for local Ollama but fails with cloud-hosted models that wrap structured JSON in markdown code fences.

`OllamaChatLLM` solves this by:
- Using `ollama.AsyncClient` directly (bypassing browser-use's internal client)
- Stripping markdown fences (`\`\`\`json...\`\`\``) from structured output before Pydantic validation
- Falling back to `json.loads()` + `model_validate()` if `model_validate_json()` fails
- Setting a 180s default timeout for large context windows
- Passing `client_params` (e.g., auth headers) through to the Ollama client

### Model Router (`src/llm/router.py`)

Routes LLM calls by task type:

| Task Type | Model | Purpose |
|-----------|-------|---------|
| `classification` | Fast (gemma4:31b) | Planning, classification, extraction |
| `reasoning` | Reasoning (deepseek-v4-flash) | Deep analysis, attack path inference |
| `embedding` | nomic-embed-text | Finding deduplication |

---

## AI Browser Agent

### AIBrowserOperator (`src/agents/browser/ai_operator.py`)

The core component bridging Assurix with the `browser-use` library. Key responsibilities:

- **LLM instantiation**: Creates `OllamaChatLLM` with cloud API key in `client_params` headers
- **Browser session management**: Creates fresh `BrowserSession` per agent run with Chrome discovery via `_find_chrome()`
- **Task execution**: Runs browser-use `Agent` with security task prompts
- **Evidence capture**: Uses `on_step_start` hook to track visited URLs
- **History extraction**: Parses `AgentHistory` for thoughts, actions, and extracted content
- **Parallel investigations**: `run_parallel_investigations()` spawns concurrent browser sessions for different vulnerability classes

### Browser Session Lifecycle

```
AIBrowserOperator._run_agent()
    │
    ├── Create OllamaChatLLM (with auth headers)
    ├── Create BrowserSession (headless, with Chrome path)
    ├── Create Agent (task, llm, browser_session, max_failures=10, use_vision=False)
    │
    ├── agent.run(max_steps=N, on_step_start=hook)
    │   └── browser-use drives browser autonomously
    │       └── Calls security tools via Tools registry
    │
    ├── Extract: model_thoughts(), model_actions(), extracted_content(), urls()
    ├── Process security tool results from self._evidence
    └── Close browser_session
```

### Security Tools (`src/agents/browser/security_tools.py`)

Seven custom browser-use `ActionResult` actions the AI agent can invoke during exploration:

| Tool | Purpose | Returns |
|------|---------|---------|
| `check_security_headers` | Analyze X-Frame-Options, CSP, HSTS, etc. via JS injection | Missing/misconfigured headers |
| `check_cookies` | Audit cookie Secure/HttpOnly/SameSite flags via CDP | Cookie security issues |
| `test_xss` | Inject safe probe marker, check for unencoded reflection | XSS reflection evidence |
| `test_csrf` | Analyze forms for CSRF tokens in hidden fields/meta | Forms missing CSRF protection |
| `analyze_javascript` | Scan inline scripts for DOM XSS sinks, external scripts for SRI | Dangerous JS patterns |
| `capture_evidence` | Screenshot + DOM snapshot saved as artifacts | Evidence files on disk |
| `check_authentication` | Detect login forms, OAuth/SSO buttons, CAPTCHA, autocomplete | Auth security findings |

> **Note**: Security tools are registered but currently NOT passed to the browser-use Agent constructor due to Pydantic schema conflicts (browser-use builds a discriminated union of all action models, and custom tools cause validation failures for built-in actions). Re-integration planned once browser-use supports tool namespaces.

### LLM Task Prompts (`src/agents/browser/prompts.py`)

Five specialized prompts for different vulnerability classes:

| Prompt | Purpose |
|--------|---------|
| `SECURITY_RECON_PROMPT` | Deep surface mapping — discover pages, forms, APIs, auth flows |
| `XSS_HUNTER_PROMPT` | Focused XSS testing — reflected, stored, DOM-based |
| `AUTH_TESTER_PROMPT` | Authentication testing — login flows, session management, CSRF |
| `API_DISCOVERY_PROMPT` | API endpoint discovery — from JS/network traffic |
| `ERROR_PROBE_PROMPT` | Error page testing — path traversal, info disclosure |

Each prompt includes role definition, methodology, safe-mode constraints, and output format instructions.

### FindingMemory (`src/agents/browser/memory.py`)

MD file-based memory system for anti-hallucination:

```
data/artifacts/{engagement_id}/memory/
├── surface.md          # Attack surface map
├── findings.md         # Finding ledger with evidence references
├── hypotheses.md       # Active hypotheses for investigation
└── investigated.md     # Already-checked items (dedup)
```

Key features:
- **Evidence requirement**: `add_finding()` returns `False` if no `evidence_ref` is provided
- **Deduplication**: Composite key `vuln_type:url:title` prevents duplicate findings
- **Context summary**: `get_context_summary()` returns a concise string for LLM prompt injection

---

## Agent Details

### PlannerAgent (`src/agents/planner.py`)

- **Input**: Target URL + optional surface data from previous iterations
- **LLM**: Fast model (classification task)
- **Output**: JSON with `directives`, `hypotheses`, `technologies_detected`, `attack_surface_summary`
- **Fallback**: If LLM fails, produces a generic directive set covering headers, cookies, info disclosure, injection, misconfig
- **Directive types**: `crawl`, `test_category`, `test_auth`, `test_form`, `test_api`

### ReconAgent (`src/agents/recon.py`)

Two-phase reconnaissance:

**Phase 1 — HTTPX Fast Crawl** (no browser):
- Fetch headers, cookies, TLS info
- Crawl linked pages (configurable depth)
- Extract links, forms, API endpoints from HTML
- Detect technologies from headers/meta/scripts

**Phase 2 — AI-Driven Browser Exploration**:
- Uses `AIBrowserOperator.explore()` with `SECURITY_RECON_PROMPT`
- AI agent navigates pages, clicks links, fills forms
- Records findings in `FindingMemory`
- Extracts visited URLs, agent thoughts, and security tool results

**Fallback**: If AI browser finds insufficient content, falls back to scripted `BrowserOperator` for page data extraction.

### WebappAgent (`src/agents/webapp.py`)

Two-phase vulnerability testing:

**Phase 1 — HTTP-Level Fast Checks** (no browser):
- Security header analysis (X-Frame-Options, CSP, HSTS, etc.)
- Cookie security audit (Secure, HttpOnly, SameSite flags)
- CSP directive analysis (unsafe-inline, unsafe-eval, wildcards)
- Information disclosure via headers (X-Powered-By, X-AspNet-Version)
- Injection reflection testing (parameter fuzzing with safe markers)
- Transport security check (HTTP vs HTTPS)
- JavaScript analysis (external scripts without SRI, console error signatures)

**Phase 2 — AI-Driven Browser Investigations**:
- Selects investigation types based on surface data:
  - `xss_hunt` if forms/inputs found
  - `auth_test` if auth pages detected
  - `api_discover` if endpoints/scripts found
  - `error_probe` (always runs)
- Uses `AIBrowserOperator.run_parallel_investigations()` for concurrent sessions
- Falls back to scripted browser tests if AI agent fails

### ReasonerAgent (`src/agents/reasoner.py`)

- **Input**: Raw findings from webapp + surface data + AI memory context
- **LLM**: Reasoning model (deepseek-v4-flash)
- **Core tasks**:
  1. Deduplicate overlapping findings
  2. Score confidence (0.0–1.0) based on evidence quality
  3. Validate with concrete evidence (not generic checklists)
  4. Infer attack paths (how findings chain together)
  5. Generate specific remediation guidance
  6. Identify false positives
- Persists validated findings to the `findings` database table
- Injects `FindingMemory.get_context_summary()` into the LLM prompt for anti-hallucination

### ReporterAgent (`src/agents/reporter.py`)

- **Input**: Validated findings + attack paths + surface data
- **LLM**: Fast model (classification task)
- **Output**: JSON with executive_summary, risk_assessment, key_findings, remediation_priority
- **MD Report**: Calls `generate_report()` to create `data/artifacts/{engagement_id}/report.md`
- **Risk assessment**: Auto-calculated from highest severity finding

---

## Vulnerability Classes Detected

### HTTP-Level (Fast, No Browser)

| Category | Checks | CWE |
|----------|--------|-----|
| **Header Security** | Missing X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS | CWE-693, CWE-319 |
| **Cookie Security** | Missing Secure, HttpOnly, SameSite flags | CWE-614, CWE-1004 |
| **CSP Analysis** | Missing CSP, unsafe-inline, unsafe-eval, wildcard sources | CWE-693 |
| **Information Disclosure** | X-Powered-By, X-AspNet-Version, X-Runtime headers | CWE-200 |
| **Injection Reflection** | Parameter fuzzing with safe markers (aJ7xK9mP2qR) | CWE-79 |
| **Transport Security** | HTTP-only targets | CWE-319 |
| **JavaScript Analysis** | External scripts without SRI, console error signatures | CWE-353 |

### AI-Driven (Browser Agent)

| Category | Approach | CWE |
|----------|----------|-----|
| **XSS (Reflected)** | Inject safe probes, check for unencoded reflection in DOM | CWE-79 |
| **XSS (DOM)** | Analyze innerHTML, document.write, eval, setTimeout(string) sinks | CWE-79 |
| **CSRF** | Check forms for CSRF tokens, meta tags, custom headers | CWE-352 |
| **Authentication** | Detect login forms, OAuth/SSO, CAPTCHA, autocomplete issues | CWE-287, CWE-307 |
| **API Discovery** | Find API endpoints from JS analysis and network traffic | CWE-200 |
| **Error Probing** | Trigger error pages, check for stack traces, path disclosure | CWE-209 |
| **Surface Mapping** | AI-driven page discovery, link following, form identification | — |
| **Mixed Content** | Detect HTTP resources on HTTPS pages | CWE-319 |

### Attack Path Inference (Reasoner)

The reasoner chains findings into realistic attack scenarios:
- Missing CORS + XSS → credential theft
- Error disclosure + SQL injection → data exfiltration
- Missing CSRF + login form → login CSRF attack
- CSP unsafe-inline + reflected input → XSS exploitation

---

## Finding Validation Flow

```
Raw Findings (webapp agent)
        │
        ▼
┌─────────────────┐
│ FindingMemory    │  ← Anti-hallucination: requires evidence_ref
│ (MD files)      │  ← Deduplication: composite key vuln_type:url:title
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ReasonerAgent   │
│  - Deduplicate  │
│  - Score 0.0-1.0│
│  - Validate     │  ← Checks for concrete evidence vs generic checks
│  - Attack paths │  ← Chains findings into exploit scenarios
│  - Remediation  │  ← Specific, actionable guidance
│  - False pos    │  ← Downgrade/remove findings without evidence
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Database        │  ← Persisted to Finding table
│ (findings)      │  ← Linked to Engagement via engagement_id
└─────────────────┘
```

---

## Data Model

### Core Entities

```
ScopePolicy ──1:N──→ Target ──1:N──→ Engagement ──1:N──→ Finding
                                              │              │
                                              │              └── EvidenceArtifact
                                              │
                                              ├── Job (agent execution jobs)
                                              ├── AuditLog (tamper-evident chain)
                                              └── EvidenceArtifact
```

### Engagement State Machine

```
PENDING → RUNNING → COMPLETED
   │         │  │
   │         │  └──→ FAILED
   │         │
   │         └──→ PAUSED → RUNNING
   │
   └──→ CANCELLED
```

### Key Fields

- **Finding**: title, description, severity (info/low/medium/high/critical), confidence_score (0.0–1.0), validated (bool), cwe_id, owasp_category, remediation, source_agent, finding_metadata (JSON)
- **EvidenceArtifact**: artifact_type (screenshot/har/request_response/trace/dom_snapshot), file_path, content (JSON)
- **Job**: agent_name, status (queued/running/completed/failed/retrying), payload, result, retry_count
- **AuditLog**: action, actor, payload, prev_hash, current_hash (tamper-evident chain)

---

## Reporting

### MD Report (`src/reporting/md_report.py`)

Generates a structured Markdown report at `data/artifacts/{engagement_id}/report.md` containing:

1. **Header**: Engagement ID, target URL, timestamp, risk rating
2. **Executive Summary**: LLM-generated narrative
3. **Risk Matrix**: Severity × likelihood matrix
4. **Findings Table**: All validated findings with severity, confidence, CWE
5. **Attack Paths**: Chained vulnerability scenarios
6. **Detailed Findings**: Per-finding sections with evidence, remediation
7. **Surface Map**: Technologies, pages, forms, endpoints discovered
8. **Remediation Priority**: Ordered fix list

---

## Orchestration

### WorkflowEngine (`src/orchestrator/engine.py`)

- Singleton `engine` instance manages the agent pipeline
- `start_engagement()`: Creates first job (planner) and sets engagement to RUNNING
- `_run_loop()`: Async job dequeue → execute → route → checkpoint cycle
- `WorkflowRouter.next_agent()` determines the next agent in the cycle
- After reasoner: if `iteration_count < max_iterations`, routes back to planner; otherwise to reporter
- Each agent execution is tracked as a `Job` with status, result, and retry logic

### JobScheduler (`src/orchestrator/scheduler.py`)

- Priority-based job queue (lower number = higher priority)
- `enqueue()`, `dequeue()`, `mark_running()`, `mark_completed()`, `mark_failed()`
- Retry support with configurable `max_retries`
- Loads pending jobs on engine start for crash recovery

---

## Scope & Safety

### Safe Mode (default: enabled)

- **Non-destructive testing only**: No actual exploit execution
- Uses safe marker strings (e.g., `aJ7xK9mP2qR`, `AssurixXSSProbe2026`) for injection testing
- Rate limiting via `default_rate_rps` (10 req/s default)
- `max_iterations_per_scan` cap prevents infinite loops
- Scope policies restrict testing to authorized domains

### ScopePolicy

- `allowed_domains`: Whitelist of domains to test
- `rate_rps`: Per-policy rate limit
- `max_iterations`: Per-policy iteration cap
- `safe_mode`: Force safe mode for this policy
- `allow_destructive`: Enable destructive tests (default: false)
- `auth_state`: Store auth tokens/cookies for authenticated testing

---

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/targets/` | Create a new target |
| GET | `/api/targets/` | List all targets |
| GET | `/api/targets/{id}` | Get target details |
| POST | `/api/scans/` | Start a new scan (engagement) |
| GET | `/api/scans/{id}` | Get scan status |
| POST | `/api/scans/{id}/stop` | Stop a running scan |
| GET | `/api/findings/` | List findings |
| GET | `/api/findings/{id}` | Get finding details |
| GET | `/api/reports/{id}` | Get generated report |
| POST | `/api/policies/` | Create scope policy |
| GET | `/api/policies/` | List policies |

---

## CLI Commands

```bash
# Start a security scan
assurix scan <url> [--iterations N] [--parallel N]

# Start the API server
assurix serve [--host 0.0.0.0] [--port 8000]

# Database migrations
assurix db migrate
```

---

## Key Design Decisions

1. **OllamaChatLLM adapter over LangChain**: browser-use's native `ChatOllama` doesn't handle cloud-hosted models that wrap JSON in markdown fences. Our custom adapter strips fences and falls back to `json.loads()` when `model_validate_json()` fails.

2. **Two-phase agent architecture**: Each agent combines fast HTTP-level checks (no browser needed) with slower AI-driven browser exploration. This gives breadth (headers, cookies, CSP) AND depth (DOM XSS, auth flows, API discovery).

3. **Fresh BrowserSession per run**: Each agent run creates a new `BrowserSession` to avoid state leakage between investigations. Sessions are closed in `finally` blocks to prevent resource leaks.

4. **Security tools as separate registry**: Custom security tools are registered via `browser_use.Tools()` but currently NOT passed to the Agent constructor due to Pydantic discriminated union conflicts. The AI agent still uses built-in browser-use actions (click, fill, navigate) for security testing.

5. **MD file-based memory**: Anti-hallucination system requires evidence references for every finding. MD files serve as shared context between agents and iterations.

6. **Fallback to scripted operator**: If the AI browser agent fails (model errors, timeout), the system falls back to the legacy `BrowserOperator` for basic page data extraction.

7. **Engagement iteration loop**: The planner can receive findings from previous iterations and produce deeper investigation directives, enabling progressive deepening of security analysis.

---

## Dependencies

### Core
- **fastapi** + **uvicorn**: API server
- **pydantic** + **pydantic-settings**: Data validation and config
- **sqlalchemy** (async) + **aiosqlite**: Async ORM and SQLite
- **httpx**: Async HTTP client (HTTP/2 support)
- **typer** + **rich**: CLI framework and terminal output
- **structlog**: Structured logging

### Browser & AI
- **browser-use** (>=0.2.0): LLM-driven browser automation
- **ollama** (>=0.4.0): Ollama Python client
- **langchain-ollama** (>=0.3.0): LangChain Ollama integration
- **playwright** (>=1.48.0): Browser automation (used by browser-use)

### Reporting
- **jinja2**: Report template rendering
- **weasyprint**: PDF report generation

---

## Running

```bash
# Install dependencies
uv sync

# Install Playwright browsers
playwright install chromium

# Configure environment
cp .env.example .env
# Edit .env with Ollama host, API key, models

# Initialize database
assurix db migrate

# Run a scan
assurix scan https://example.com

# Start API server
assurix serve
```

---

## Future Enhancements

- **Re-integrate security tools**: Once browser-use supports tool namespaces or isolated schemas, pass custom security tools to the Agent for autonomous invocation
- **Authenticated scanning**: Support login flows via scope policy `auth_state` (cookies, tokens)
- **HAR capture**: Record full HTTP traffic during AI browser sessions for evidence
- **Screenshot evidence**: Automatic screenshot on every security finding via browser-use hooks
- **Parallel scan scaling**: Support multiple targets scanned concurrently
- **PDF report output**: WeasyPrint-based PDF generation from MD reports
- **Graph-based attack path visualization**: NetworkX graph of finding chains
- **Continuous scanning**: Scheduled re-scans with diff-based change detection