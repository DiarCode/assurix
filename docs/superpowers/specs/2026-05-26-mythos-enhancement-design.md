# Assurix Mythos Enhancement Design

**Date:** 2026-05-26
**Status:** Approved
**Scope:** P0-P3 priority enhancements + full research integration

## Problem Statement

Assurix's current scanning produces false positives from soft-404 pages, SPA catch-all responses, login redirects scored as medium, and lacks detection for blind injection, GraphQL, WebSocket, and credential testing. The agent pipeline doesn't deduplicate findings by response content, validate IDOR properly, or dynamically adapt its investigation strategy based on observed technology.

## Design Goals

1. **Zero false positives on soft-404/SPA catch-all responses** -- response dedup + content-aware severity
2. **Real IDOR validation** -- multi-account differential testing with SPA-aware discrimination
3. **Blind vulnerability detection** -- timing-based analysis for blind SQLi/SSRF
4. **Complete attack surface coverage** -- GraphQL introspection, WebSocket testing, credential brute-force
5. **Mythos-level reasoning** -- independent validation, Bayesian hypotheses, dynamic prompts, action dedup, LATS backtracking

## New Modules

### 1. ResponseDeduplicator (`src/agents/tools/response_dedup.py`) -- P0

Two-tier response deduplication:

- **Tier 1 -- Exact hash**: `sha256(response_body.encode()).hexdigest()[:16]`. Identical response bodies across different URLs are grouped into one finding.
- **Tier 2 -- SimHash similarity**: For near-identical responses (SPA catch-all pages with minor dynamic content), compute SimHash with 64-bit feature tokens. Flag responses with >85% similarity as duplicates.

**Integration**: Called in `WebappAgent.execute()` after all findings collected, deduping findings with the same response hash. Also in `Fuzzer._is_soft_404()` for enhanced detection.

### 2. IDORValidator (`src/agents/tools/idor_validator.py`) -- P0

Multi-account differential IDOR testing with SPA-aware discrimination:

- Probe `/api/users/1`, `/api/users/2`, `/api/users/9999`
- Compare response structure: JSON with user-specific fields = likely real IDOR; HTML with `<div id="app">` = SPA shell; redirect to `/login` = auth gate
- If JSON, check if different IDs return different user data
- Report confidence: confirmed IDOR vs likely false positive
- Multi-account testing if credentials available via ScopePolicy

**Integration**: Called in `PentesterAgent._run_offensive_tools()` replacing simple `test_idor()`, and in `ExploitVerifier._verify_auth_bypass()`.

### 3. SeverityAdjuster (`src/agents/tools/severity_adjuster.py`) -- P1

Content-aware severity downgrade pipeline with rules:

| Condition | Action |
|-----------|--------|
| Response body is HTML login page / redirect | Downgrade by 2 levels |
| Response structural similarity to 404 page > 85% | Downgrade to Info |
| Response is JSON with 4xx error (expected) | Downgrade to Info |
| Timing differential < 50ms for "timing-based" finding | Downgrade by 1 level |
| Finding has no concrete evidence reference | Downgrade by 1 level |

**Integration**: Called in `ReasonerAgent.execute()` after LLM validation, before persisting findings.

### 4. TimingAnalyzer (`src/agents/tools/timing_analyzer.py`) -- P1

Differential timing analysis for blind injection detection:

- Collect baseline timing (3 samples)
- Test time-delay payloads for MySQL, PostgreSQL, MSSQL, SQLite, Oracle
- Test control payload (same length, no delay trigger)
- If delay payload takes >3s longer than both baseline and control, flag as likely blind injection
- Statistical significance check with 3 samples per test

**Integration**: New tool in `PentesterAgent`, new investigation type `timing_analyze` in `WebappAgent`.

### 5. GraphQLScanner (`src/agents/tools/graphql_scanner.py`) -- P3

GraphQL endpoint discovery, introspection, and security testing:

- Probe common endpoints: `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`
- Attempt full introspection query
- If blocked, try bypass techniques (field suggestions, `__typename` probing)
- Test batch queries, alias overloading, circular fragments
- Test CSRF via GET method
- Map discovered mutations/queries for auth testing

**Integration**: New investigation type `graphql_scan` in `WebappAgent`. Prompt added to `prompts.py`.

### 6. WebSocketScanner (`src/agents/tools/websocket_scanner.py`) -- P3

WebSocket security testing:

- Detect WebSocket URLs (`ws://`, `wss://`) in HTML/JS
- Connect and test CSWSH (spoofed Origin header)
- Test authenticated vs. unauthenticated message access
- Fuzz message payloads for injection
- Test rate limiting on messages

**Integration**: New investigation type `websocket_scan` in `WebappAgent`. Prompt added to `prompts.py`.

### 7. CredentialTester (`src/agents/tools/credential_tester.py`) -- P2

LLM-guided credential testing on discovered login pages:

- Analyze login form structure (field names, CSRF tokens, submit selectors)
- Establish baseline: send one known-invalid credential, record response signature
- Test technology-specific default credentials (lookup table by detected technology)
- Test common patterns: `admin:admin`, `admin:password`, `root:root`, etc.
- Rate-aware: respect rate limiting, add jitter, detect lockout responses
- Validate successful logins against protected resource

**Integration**: New investigation type `credential_test` in `WebappAgent`. Called from `PentesterAgent._chain_attacks()`.

### 8. ValidationAgent (`src/agents/validation.py`) -- Research (High Impact)

Independent exploit re-verification (MAPTA pattern):

- For each high/medium finding, generate a minimal PoC
- Re-execute against the live target independently
- Verify the expected behavior occurs
- Mark finding as `exploit_verified=True/False` with `verification_evidence`
- Increase confidence by +0.15 for verified, decrease by -0.2 for unverified
- Cap at 20 validations per scan to control cost

**Integration**: New stage in `WorkflowEngine` between Reasoner and Reporter.

## Modified Modules

### WebappAgent (`src/agents/webapp.py`)
- Import and instantiate `ResponseDeduplicator`, `SeverityAdjuster`, `TimingAnalyzer`, `GraphQLScanner`, `WebSocketScanner`, `CredentialTester`
- Add response dedup after findings collection
- Add `graphql_scan`, `websocket_scan`, `timing_analyze`, `credential_test` to investigation type selection
- Stream progress events via `EventBus`

### ReasonerAgent (`src/agents/reasoner.py`)
- Import and apply `SeverityAdjuster` after LLM validation
- Import and apply `ResponseDeduplicator` for root-cause dedup
- Add Bayesian hypothesis update logic
- Add action dedup tracking

### PentesterAgent (`src/agents/pentester.py`)
- Replace `test_idor()` with `IDORValidator.validate_idor()`
- Add `TimingAnalyzer` as new tool
- Add `CredentialTester` in `_chain_attacks()`
- Add `ResponseDeduplicator` for tool result dedup
- Add `completed_actions` tracking via `FindingMemory`

### AIBrowserOperator (`src/agents/browser/ai_operator.py`)
- Add `completed_actions` set check before spawning investigations
- Add dynamic prompt construction based on technology fingerprint
- Stream partial results via `EventBus`

### FindingMemory (`src/agents/browser/memory.py`)
- Add `completed_actions` set (hash of `(action_type, url, params)`)
- Add `hypotheses` with Bayesian posterior tracking
- Add `add_hypothesis()`, `update_hypothesis()`, `get_top_hypotheses()`, `mark_hypothesis_failed()`

### Prompts (`src/agents/browser/prompts.py`)
- Add `GRAPHQL_SCAN_PROMPT`
- Add `WEBSOCKET_SCAN_PROMPT`
- Add `CREDENTIAL_TEST_PROMPT`

### WorkflowEngine (`src/orchestrator/engine.py`)
- Add `ValidationAgent` stage between Reasoner and Reporter
- Add LATS backtracking: if Reasoner marks findings as false positives, re-queue Planner with alternative hypotheses

### Tools Init (`src/agents/tools/__init__.py`)
- Export new tools: `ResponseDeduplicator`, `IDORValidator`, `SeverityAdjuster`, `TimingAnalyzer`, `GraphQLScanner`, `WebSocketScanner`, `CredentialTester`

## Testing Strategy

### Unit Tests
- `ResponseDeduplicator`: exact hash matching, SimHash similarity, edge cases
- `IDORValidator`: SPA discrimination, multi-account detection, redirect handling
- `SeverityAdjuster`: all downgrade rules, no upgrade, boundary cases
- `TimingAnalyzer`: mock HTTP server, baseline collection and delay detection
- `GraphQLScanner`: introspection, batch queries, CSRF
- `CredentialTester`: form analysis, baseline establishment, rate limiting

### Integration Tests
- Run full pipeline against test targets (DVWA, WebGoat, Juice Shop)
- Verify response dedup reduces finding count on SPA targets
- Verify IDOR validation rejects SPA catch-all false positives
- Verify timing analysis detects blind SQLi on deliberately vulnerable endpoints
- Verify severity adjuster downgrades login redirect findings

## Open Decisions

1. **OOB callback server**: Should we add an out-of-band callback server (like interactsh) for blind SSRF/XSS detection? This requires a publicly accessible server and is a larger infrastructure change. Could be Phase 2.

2. **Model fine-tuning**: xOffense research suggests fine-tuning mid-scale LLMs on pentest reasoning data could improve agent performance. Out of scope for this phase but worth tracking.