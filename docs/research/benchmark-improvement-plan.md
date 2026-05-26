# Assurix Benchmark Improvement Implementation Plan

**Date:** 2026-05-26
**Based on:** benchmark-improvement-research.md
**Target:** #1 rank across all 5 benchmark suites

---

## Implementation Phases

### Phase 1: Quick Wins (P0 + P5 + P8 + P9) — Target: F1 87.4%

#### P0: Fix Validation False-Positive Bugs (2h)

**File:** `src/agents/validation.py`

1. **`_validate_exposure` (L173-185)** — Currently marks ANY 200 as verified. Fix:
   - Only verify if sensitive markers found in response body
   - Remove the fallback on L182 that marks 200 without markers as verified
   - Add check: if response is SPA shell, mark as unverified
   - Add content-type check: if Content-Type is text/html and no sensitive markers, mark as unverified

2. **`_validate_generic` (L187-196)** — Currently marks any 200 >50 bytes as verified. Fix:
   - Compare against baseline response (same URL without finding-specific parameters)
   - Only verify if response differs significantly from baseline OR contains finding-specific evidence
   - Add soft-404 detection

3. **`_validate_sqli` (L136-150)** — Currently marks any 500 as confirmed SQLi. Fix:
   - 500 alone is not evidence of SQLi — need SQL error keywords in response body
   - Remove the L141 shortcut that confirms on status 500
   - Actually send a SQL-specific probe and check for SQL error messages
   - Add differential testing: send normal request and SQLi request, only confirm if responses differ

4. **`_validate_ssrf` (L152-160)** — Currently marks any 200/301/302 as verified. Fix:
   - SSRF means the SERVER made a request to an internal resource, not that a URL is reachable
   - Actually test SSRF by sending a request with an internal URL parameter
   - Add cloud metadata probe: send `?url=http://169.254.169.254/latest/meta-data/` and check for AWS metadata
   - Mark as unverified if response is same as baseline

5. **`_validate_idor` (L95-119)** — L116 marks 200 without auth as confirmed IDOR. Fix:
   - Add: if response is identical across different user IDs, it is not real IDOR
   - Only confirm if JSON contains user-specific data with different values for different IDs

#### P5: Authenticated Session Sharing (6h)

**Files:** `src/agents/tools/` (multiple), `src/agents/pentester.py`

1. Create `src/agents/tools/session.py` — SharedSessionManager:
   - Maintains an httpx.AsyncClient with persistent cookies
   - Provides `get_authenticated_client(target_url)` that discovers login, attempts credential testing, stores session cookies
   - Provides `get_client(target_url)` that returns authenticated client if available

2. Modify each tool to accept an optional `client` parameter:
   - Fuzzer, BruteForcer, IDORValidator, TimingAnalyzer, AuthTester, CredentialTester, GraphQLScanner, WebSocketScanner

3. Modify `PentesterAgent._run_offensive_tools()` to create SharedSessionManager, attempt authentication, pass authenticated client to tools

#### P8: POST Body/Cookie/Header Fuzzing (8h)

**File:** `src/agents/tools/fuzzer.py`

1. Add `fuzz_post_body(base_url, endpoints)` method:
   - For each discovered endpoint, send POST requests with injection payloads in body
   - Support JSON body, form-urlencoded, and multipart

2. Add `fuzz_cookies(base_url)` method:
   - Test injection payloads in common cookie names (session, token, user, lang, theme)

3. Add `fuzz_headers_injection(base_url)` method:
   - Test injection payloads in Referer, User-Agent, Accept-Language, X-Forwarded-For

4. Add new methods to `PentesterAgent._run_offensive_tools()` tasks list

#### P9: Discovered-Endpoint-Aware Testing (6h)

**Files:** `src/agents/tools/idor_validator.py`, `src/agents/tools/timing_analyzer.py`, `src/agents/pentester.py`

1. Modify `IDORValidator.validate_idor()` to accept `discovered_endpoints` parameter:
   - Parse discovered API endpoints from recon results
   - For each endpoint with numeric path segments, test IDOR by varying the numeric segment

2. Modify `TimingAnalyzer.test_blind_sqli()` to accept `discovered_endpoints` and `discovered_params`:
   - Use discovered endpoints instead of hardcoded 4 paths
   - Use discovered parameters instead of just "id"

3. Modify `PentesterAgent.execute()` to pass discovered endpoints/params from observations

---

### Phase 2: Deep Validation (P1 + P3) — Target: F1 90.8%

#### P1: Vulnerability-Specific Pipelines (16h)

**New file:** `src/agents/tools/vuln_pipelines.py`

1. **XSSPipeline** class:
   - Reflected XSS: inject into URL parameters, check reflection in HTML context
   - DOM XSS: inject DOM-specific payloads, check DOM sinks in JavaScript source
   - Stored XSS: submit payloads via POST, check if they appear in other pages
   - Context-aware encoding: test different HTML contexts

2. **SQLiPipeline** class:
   - Error-based: send SQL error-inducing payloads, check for SQL error patterns
   - Boolean-based blind: send `OR 1=1` vs `OR 1=2`, compare responses
   - Time-based blind: send `SLEEP(5)` / `WAITFOR DELAY`, measure timing differential
   - Union-based: send `UNION SELECT NULL--` with increasing column count

3. **SSRFPipeline** class:
   - Cloud metadata: test AWS/GCP/Azure metadata endpoints
   - Internal services: test localhost:8080, localhost:3306, localhost:6379
   - Protocol smuggling: test gopher://, file://, dict://

4. **CommandInjectionPipeline** class:
   - Test OS command payloads (`;id`, `|id`, `$(id)`)
   - Test time-based detection (`;sleep 5`)

5. Integrate into `PentesterAgent._run_offensive_tools()`

#### P3: Adversarial Debate Validation (12h)

**New file:** `src/agents/adversarial.py`

1. **AdversarialValidator** class implementing MDASH debate pattern:
   - For each finding: Attack side generates evidence for TP, Defense side generates benign explanation, Judge evaluates

2. **DefenseAttorney** internal class:
   - Generates counter-arguments: "This 200 is a default page", "This 500 is generic error", "This redirect is standard behavior"

3. **Judge** internal class:
   - Weighs evidence from both sides, returns verdict: confirmed / likely_false_positive / uncertain

4. Modify `ValidationAgent.execute()` to run rule-based validation first, then adversarial debate for survivors

---

### Phase 3: Full ReAct (P2 + P4 + P6 + P7) — Target: F1 93.8%

#### P2: True ReAct Loop (20h)

**File:** `src/agents/pentester.py` (major refactor)

1. Replace 5-phase sequential execution with ReAct loop:
   - `_think`: LLM analyzes current state, generates hypothesis
   - `_select_action`: Choose best tool based on hypothesis
   - `_execute_action`: Run selected tool
   - `_observe_result`: Process tool output, update observations
   - `_reflect`: Analyze whether action produced useful results
   - Loop until convergence or max iterations

#### P4: Evidence-Guided Tree Search / LATS (24h)

**File:** `src/agents/planner_mcts.py` (full implementation)

1. Replace skeleton with real LATS:
   - MCTSNode: visit_count, value, children
   - Selection: UCB1 formula
   - Expansion: LLM generates 3-5 possible next actions
   - Simulation: Quick rollout
   - Backpropagation: Update node values

2. Integrate with ReAct loop: use LATS in `_select_action`

#### P6: Context Compaction for Longer Runs (8h)

**New file:** `src/agents/context.py`

1. **ContextManager** class:
   - Sliding window of recent observations/findings
   - Compacts older findings into LLM-generated summaries
   - Preserves: confirmed findings, active hypotheses, session state
   - Discards: raw HTTP responses, failed attempts (keep only failure reasons)

#### P7: Wire Bayesian Hypothesis Tracking (8h)

**Files:** `src/agents/tools/memory.py`, `src/agents/pentester.py`

1. Connect BayesianHypothesisTracker to ReAct loop:
   - After each observation, update hypotheses
   - Call `get_top_hypotheses()` in action selection to prioritize
   - Generate initial hypotheses from target surface at scan start

2. Hypothesis-driven tool selection:
   - "XSS likely" -> run XSSPipeline
   - "SQLi likely" -> run SQLiPipeline
   - "auth bypass likely" -> run AuthTester

---

## Execution Order

1. P0: Fix validation bugs (2h)
2. P5: Session sharing (6h)
3. P8: POST/body/cookie/header fuzzing (8h)
4. P9: Endpoint-aware testing (6h)
5. Run benchmarks, verify Phase 1 gains
6. P1: Vulnerability-specific pipelines (16h)
7. P3: Adversarial debate (12h)
8. Run benchmarks, verify Phase 2 gains
9. P2: ReAct loop (20h)
10. P4: LATS tree search (24h)
11. P6: Context compaction (8h)
12. P7: Bayesian wiring (8h)
13. Run benchmarks, verify Phase 3 gains
14. Final benchmark report and comparison charts

## File Summary

| File | Action | Phase |
|------|--------|-------|
| `src/agents/validation.py` | Fix 5 validation methods | P0 |
| `src/agents/tools/session.py` | New: SharedSessionManager | P5 |
| `src/agents/tools/fuzzer.py` | Add POST/cookie/header fuzzing | P8 |
| `src/agents/tools/idor_validator.py` | Accept discovered endpoints | P9 |
| `src/agents/tools/timing_analyzer.py` | Accept discovered endpoints/params | P9 |
| `src/agents/pentester.py` | Pass endpoints/params to tools | P9 |
| `src/agents/tools/vuln_pipelines.py` | New: XSS/SQLi/SSRF/CmdI pipelines | P1 |
| `src/agents/adversarial.py` | New: Adversarial debate validation | P3 |
| `src/agents/pentester.py` | Major: Replace pipeline with ReAct loop | P2 |
| `src/agents/planner_mcts.py` | Full LATS implementation | P4 |
| `src/agents/context.py` | New: Context compaction | P6 |
| `src/agents/tools/memory.py` | Wire Bayesian into ReAct | P7 |

## Verification Checkpoints

After each phase, run the full benchmark suite and compare:

1. **Phase 1 complete**: expect F1 > 87%
2. **Phase 2 complete**: expect F1 > 90%
3. **Phase 3 complete**: expect F1 > 93%

Generate comparison charts after each phase:
```
uv run python -m src.benchmark.cli chart --run-id <latest> --chart-type bar
uv run python -m src.benchmark.cli chart --run-id <latest> --chart-type radar
```