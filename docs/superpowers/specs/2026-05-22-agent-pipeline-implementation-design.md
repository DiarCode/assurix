# Agent Pipeline Implementation + Live Security Test

**Date:** 2026-05-22
**Status:** Approved
**Target:** https://dj1naq.sytes.net

## Context

Assurix infrastructure (DB, audit, orchestration, API) is wired. All 5 agents are empty stubs returning zero results. The Ollama client uses raw HTTPX to localhost — needs cloud API support.

## Model Selection (Ollama Cloud)

| Role | Model | Why |
|------|-------|-----|
| Fast (classification, extraction, routing) | `gemma4:31b` | Balance of speed/quality |
| Reasoning (hypothesis, attack path, remediation) | `deepseek-v4-flash` | Strong reasoning, fast |
| Embedding (dedup, similarity) | `nomic-embed-text` (local) | Local embedding, no latency issue |

Cloud API: `https://ollama.com` with `OLLAMA_API_KEY` auth via `ollama` Python library.

## Implementation Scope

### 1. OllamaClient Refactor
- Replace raw HTTPX calls with `ollama` Python library
- Support cloud host (`https://ollama.com`) + API key via `OLLAMA_API_KEY` env var
- Fall back to local Ollama if no API key
- Update `EmbeddingClient` similarly

### 2. PlannerAgent
- LLM call (fast model) to analyze target URL and produce strategic directives
- Output: list of what to crawl, what OWASP categories to test, initial hypotheses

### 3. ReconAgent
- HTTPX-based surface mapping (no Playwright for this phase)
- Crawl target homepage, follow links, discover endpoints/forms
- Collect response headers, check TLS, record technologies
- Output: surface map (pages, endpoints, forms, headers, technologies)

### 4. WebappAgent
- Safe OWASP Top 10 checks using HTTPX probes:
  - Security header analysis (CSP, HSTS, X-Frame-Options, cookies)
  - Injection reflection (XSS, SQLi — boolean/detection only)
  - Cookie security flags
  - Auth surface detection
  - Information disclosure checks
- Output: findings list with evidence artifacts

### 5. ReasonerAgent
- LLM-powered (reasoning model):
  - Deduplicate findings from webapp/recon
  - Score confidence for each finding
  - Infer attack paths from correlated evidence
  - Generate remediation guidance
- Output: validated findings, attack paths

### 6. ReporterAgent
- Compose structured findings summary
- Include evidence, remediation, severity ratings
- Output: report metadata (findings count by severity, key paths)

### 7. .env Configuration
- Real Ollama cloud host and API key
- Cloud model names
- Local embedding model
- Safe mode enabled, rate limits configured

### 8. Live Test
- Run `assurix scan https://dj1naq.sytes.net`
- Analyze: does it find real issues? Does LLM reasoning work? Quality of findings?

## Constraints
- Safe mode ON: non-destructive testing only
- Max iterations = 3 per scan
- Rate limit: 5 RPS (respectful scanning)
- No Playwright browser (future phase)
- Embeddings stay local (nomic-embed-text)