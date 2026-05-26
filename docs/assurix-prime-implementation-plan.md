# Assurix Prime: Deep Comparative Analysis & Implementation Plan

## 1. Comparative Validation of Research Proposals

### 1.1 Evaluation Framework

Each research is scored across 7 metrics (1-10 scale):

| Metric | Description |
|--------|-------------|
| **Zero-Day Discovery** | Ability to find novel vulnerabilities unknown to the target |
| **Codebase Fit** | How well it integrates with current Assurix architecture |
| **Compute Efficiency** | Resource cost relative to finding quality |
| **False Positive Control** | Mechanisms to suppress noise and validate findings |
| **Web App Focus** | Suitability for web application testing (Assurix's domain) |
| **Implementation Risk** | Likelihood of delivery failure (lower = safer) |
| **Transferability** | Can findings/methods generalize across targets |

### 1.2 Research-by-Research Analysis

#### Research 1: Tri-Modal Reasoning + Suspicious Points

**Strengths:**
- Suspicious Point (SP) abstraction is elegant — marks "interesting" code/data locations for targeted deep analysis rather than brute-force scanning
- HPTSA (Hierarchical Plan-Then-Search-Attack) multi-agent planning maps well to our existing planner → investigator pipeline
- Executable PoC pipeline (find → verify → exploit → document) is production-grade thinking
- Causal inference via `dowhy` adds scientific rigor to "is this really a vulnerability?" validation

**Weaknesses:**
- **I/O stubbing wall**: Symbolic execution requires stubbing external dependencies (DB, network, APIs). For web apps this means stubbing HTTP requests, session state, CSRF tokens — a massive engineering challenge that grows with every target
- **Binary-centric SP model**: Suspicious Points were designed for binary analysis (instruction-level taint). Adapting them to web apps requires redefining "point" from "instruction address" to "DOM element + handler + network endpoint" — feasible but significant redesign
- **Fuzzing as primary method**: Fuzzing web apps hits auth walls immediately. Without valid sessions, fuzzers can't reach authenticated endpoints where real vulns live
- **Causal inference overhead**: `dowhy` requires a causal DAG model. Who builds this DAG? The LLM? That introduces hallucination risk at the structural level

**Score:** Zero-Day: 7 | Codebase Fit: 5 | Compute: 4 | FP Control: 7 | Web Focus: 4 | Risk: 6 | Transfer: 5

#### Research 2: Neuro-Symbolic + Cognitive Memory

**Strengths:**
- **ACC (Agent Cognitive Compressor)** is the single most important idea across all four proposals. Long-running browser agents WILL exhaust context windows. ACC's bounded-memory approach (compress old findings, keep active hypotheses) solves a real, production-blocking problem
- AHFE (Autonomous Hypothesis Falsification Engine) with Bayesian updating is the correct epistemology for security testing: generate hypothesis → test → update beliefs → falsify or confirm
- SIESN (Self-Improving Exploit Synthesis Network) with RL feedback is the path to actual autonomous improvement — finding bugs the LLM couldn't find at first attempt
- Causal Attack Graph Reasoner chains findings into exploit paths, which is exactly what our reasoner agent does but with more rigor

**Weaknesses:**
- **RL training data problem**: SIESN needs successful/failed exploit trajectories to learn from. Where does this training data come from? We'd need a corpus of verified exploits, which is a bootstrapping problem
- **Bayesian falsification requires priors**: AHFE needs prior probability distributions for vulnerability hypotheses. Cold-start problem: where do priors come from for a never-seen target?
- **Symbolic program reasoning for minified JS**: The proposal mentions "semantic program reasoning" but minified/bundled JavaScript (webpack, Vite, etc.) is essentially opaque. Symbolic reasoning over `vendor.a1b2c3.js` is impractical
- **Compute cost**: Running multiple falsification rounds per hypothesis is expensive in LLM tokens

**Score:** Zero-Day: 8 | Codebase Fit: 8 | Compute: 3 | FP Control: 9 | Web Focus: 7 | Risk: 5 | Transfer: 7

#### Research 3: Code Semantic Graph + MCTS + Adversarial Validation

**Strengths:**
- **"Missing Code" detection** is brilliant for web apps. A login form without rate-limiting, a password reset without email verification, an API without auth middleware — these are bugs defined by ABSENCE. No scanner currently detects this
- **MCTS (Monte Carlo Tree Search)** for investigation planning is the right formalism. Our current planner uses a single LLM call — MCTS explores multiple investigation paths, evaluates them, and allocates compute to the most promising ones
- **Adversarial Validation Engine (Red/Blue/Judge)** is the best FP control mechanism proposed. Red agent argues "this is a real vulnerability", Blue agent argues "this is a false positive", Judge decides. This is how expert pentesters think (play devil's advocate)
- **Tiered oracle validation** (cheap checks first, expensive LLM calls only for promising leads) is compute-efficient

**Weaknesses:**
- **Code Semantic Graph construction**: Building CSGs from web apps requires parsing rendered DOM, network traffic, AND JavaScript execution traces. This is a research-grade problem — building CSGs from minified React bundles is harder than the paper suggests
- **MCTS requires a good value function**: Without accurate evaluation of intermediate states, MCTS explores randomly. Our current Ollama models may not be reliable enough for node evaluation
- **Three-agent adversarial system triples LLM costs**: Each finding goes through Red + Blue + Judge = 3x token cost
- **Self-reflective reasoning loop**: Can get stuck in loops where agents endlessly argue. Needs a circuit breaker

**Score:** Zero-Day: 9 | Codebase Fit: 7 | Compute: 4 | FP Control: 10 | Web Focus: 9 | Risk: 4 | Transfer: 8

#### Research 4: Differential Testing + ZCAT

**Strengths:**
- **NVRE (Neurosymbolic Vulnerability Reasoning Engine)** with Trust Graphs is the most mature formal verification approach. Assigning confidence scores to each reasoning step enables graceful degradation
- **ML-Guided Differential Fuzzing** comparing "what the code does" vs "what the spec says" is powerful for API testing — find mismatches between OpenAPI spec and actual behavior
- **Causal Vulnerability Inference** using treatment/outcome framework is theoretically sound
- **ZCAT (Zero-Shot Cross-Application Transfer)** with Vulnerability Pattern Language is the most ambitious idea: learn patterns from one app and apply to unseen apps without retraining. If it works, it's a force multiplier

**Weaknesses:**
- **ZCAT cold-start problem**: VPL needs a base vocabulary of vulnerability patterns. Where does this come from? Manually curated? LLM-generated? Both have quality issues
- **Differential fuzzing requires specs**: Most web apps don't have formal specs. You'd need to infer specs from behavior, which makes the comparison circular
- **Trust Graph complexity**: Building and maintaining trust scores for every reasoning step adds significant engineering overhead. Scores can drift without careful calibration
- **Over-engineering risk**: The most complex proposal with the most novel components. Highest risk of partial delivery

**Score:** Zero-Day: 8 | Codebase Fit: 5 | Compute: 5 | FP Control: 8 | Web Focus: 6 | Risk: 3 | Transfer: 10

### 1.3 Aggregate Comparison

| Research | Zero-Day | Fit | Compute | FP Control | Web Focus | Risk (inv) | Transfer | **Total** |
|----------|----------|------|---------|------------|-----------|------------|----------|-----------|
| R1       | 7        | 5    | 4       | 7          | 4         | 4          | 5        | **36**    |
| R2       | 8        | 8    | 3       | 9          | 7         | 5          | 7        | **47**    |
| R3       | 9        | 7    | 4       | 10         | 9         | 6          | 8        | **53**    |
| R4       | 8        | 5    | 5       | 8          | 6         | 7          | 10       | **49**    |

**Winner: Research 3** for web application zero-day discovery, with Research 2's ACC as a mandatory cross-cutting component.

### 1.4 Synthesis Decision: What Goes Into Assurix Prime

| Component | Source | Rationale |
|-----------|--------|-----------|
| Agent Cognitive Compressor (ACC) | R2 | Solves real context window limitation. Mandatory. |
| Missing Code Detection | R3 | Novel capability no scanner has. High impact for web apps. |
| MCTS Investigation Planning | R3 | Better than single LLM call for directing investigations. |
| Adversarial Validation (Red/Blue/Judge) | R3 | Best FP control mechanism. Essential for confidence. |
| Suspicious Point Abstraction | R1 | Adapted to web: DOM elements, endpoints, handlers as "points". |
| Executable PoC Pipeline | R1 | Find → verify → document chain. Practical value. |
| Causal Attack Graph | R2 | Chains findings into real exploit paths. Upgrades reasoner. |
| Tiered Oracle Validation | R3 | Cheap checks first, expensive LLM only for promising leads. |
| ZCAT Pattern Library | R4 | Long-term: cross-app vulnerability patterns. Start small. |
| Trust-Weighted Reasoning | R4 | Confidence scores on reasoning steps. Complements adversarial validation. |

**What we explicitly DO NOT adopt:**
- R1's symbolic execution for web apps (I/O stubbing wall)
- R2's SIESN RL framework (training data bootstrapping problem)
- R4's full NVRE pipeline (over-engineered for current needs)
- R4's differential fuzzing (requires specs most targets don't have)

---

## 2. Architecture: Assurix Prime

### 2.1 New Pipeline

```
Planner (MCTS-enhanced)
  | produces investigation tree, not flat directives
  v
Recon (ACC-compressed memory, Suspicious Points)
  | surface map + SP candidates
  v
Webapp Investigators (parallel, SP-targeted)
  |- Missing Code Detector (new)
  |- XSS Hunter (SP-guided)
  |- Auth Tester (SP-guided)
  +- API Discoverer (SP-guided)
  | raw findings + SP evidence
  v
Reasoner (Adversarial Validation)
  |- Red Agent: argues finding is real
  |- Blue Agent: argues finding is false positive
  +- Judge: decides with confidence score
  | validated findings + attack paths (Causal Attack Graph)
  v
Reporter (MD report with PoC pipeline)
```

### 2.2 New Components Map

| Component | New File | Modifies |
|-----------|----------|----------|
| ACC (Agent Cognitive Compressor) | `src/agents/browser/acc.py` | `ai_operator.py`, `memory.py` |
| Suspicious Point system | `src/agents/browser/suspicious_points.py` | `recon.py`, `webapp.py` |
| MCTS Planner | `src/agents/planner_mcts.py` | `planner.py` (replaced) |
| Missing Code Detector | `src/agents/browser/missing_code.py` | `webapp.py` |
| Adversarial Validator | `src/agents/adversarial.py` | `reasoner.py` |
| Causal Attack Graph | `src/graph/attack_graph.py` | `graph/store.py`, `reasoner.py` |
| PoC Pipeline | `src/agents/browser/poc_pipeline.py` | `security_tools.py` |
| Trust Scorer | `src/reasoning/trust.py` | new module |
| Tiered Oracle | `src/reasoning/oracle.py` | `reasoner.py` |
| ZCAT Pattern Library | `src/patterns/library.py` | new module (Phase 4) |

---

## 3. Phased Implementation Plan

### Phase 1: Foundation — ACC + Suspicious Points (Week 1)

**Goal:** Solve the context window problem and add targeted analysis capability.

#### 1.1 Agent Cognitive Compressor

**File:** `src/agents/browser/acc.py` (~150 lines)

```python
"""Agent Cognitive Compressor — bounded memory for long-running browser agents."""

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    """An active investigation hypothesis with evidence tracking."""
    description: str
    confidence: float = 0.5
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    tested: bool = False


class AgentCognitiveCompressor:
    """Compresses agent history to fit within token budgets.

    Architecture:
    - Active buffer: recent steps (full fidelity)
    - Compressed buffer: older findings (summarized)
    - Hypothesis tracker: active investigation hypotheses with evidence weights
    - Investigated set: already-checked items (prevents re-investigation)
    """

    def __init__(self, token_budget: int = 4000, max_hypotheses: int = 10):
        self.token_budget = token_budget
        self.max_hypotheses = max_hypotheses
        self.active_buffer: list[dict] = []
        self.compressed_buffer: list[str] = []
        self.hypotheses: list[Hypothesis] = []
        self.investigated: set[str] = set()
        self._step_count = 0

    def add_step(self, step: dict) -> None:
        """Add a new step. Compress when budget exceeded."""
        self._step_count += 1
        self.active_buffer.append(step)
        self._maybe_compress()

    def add_finding(self, finding: dict) -> None:
        """Add a finding and check against hypotheses."""
        title = finding.get("title", "")
        for h in self.hypotheses:
            if self._finding_supports_hypothesis(finding, h):
                h.evidence_for.append(title)
                h.confidence = min(1.0, h.confidence + 0.1)
            elif self._finding_contradicts_hypothesis(finding, h):
                h.evidence_against.append(title)
                h.confidence = max(0.0, h.confidence - 0.15)

    def add_hypothesis(self, description: str, confidence: float = 0.5) -> None:
        """Add a new investigation hypothesis."""
        if len(self.hypotheses) >= self.max_hypotheses:
            # Remove lowest-confidence hypothesis
            self.hypotheses.sort(key=lambda h: h.confidence, reverse=True)
            removed = self.hypotheses.pop()
            logger.debug("Dropped hypothesis: %s (confidence: %.2f)", removed.description, removed.confidence)
        self.hypotheses.append(Hypothesis(description=description, confidence=confidence))

    def mark_investigated(self, item: str) -> None:
        """Mark a suspicious point as already investigated."""
        self.investigated.add(item)

    def is_investigated(self, item: str) -> bool:
        """Check if a suspicious point has been investigated."""
        return item in self.investigated

    def get_context(self) -> str:
        """Return compressed + active context for LLM prompt."""
        parts = []
        if self.compressed_buffer:
            parts.append("## Previous Investigation Summary\n")
            for summary in self.compressed_buffer[-3:]:
                parts.append(f"- {summary}")
        if self.active_buffer:
            parts.append("\n## Recent Steps\n")
            for step in self.active_buffer[-10:]:
                parts.append(self._format_step(step))
        if self.hypotheses:
            parts.append("\n## Active Hypotheses\n")
            for h in sorted(self.hypotheses, key=lambda h: h.confidence, reverse=True):
                parts.append(f"- [{h.confidence:.0%}] {h.description}")
        if self.investigated:
            parts.append(f"\n## Already Investigated: {len(self.investigated)} items")
        return "\n".join(parts)

    def _maybe_compress(self) -> None:
        """Compress oldest active steps into summaries when budget exceeded."""
        if self._estimate_tokens() > self.token_budget:
            split = len(self.active_buffer) // 2
            to_compress = self.active_buffer[:split]
            self.active_buffer = self.active_buffer[split:]
            summary = self._summarize(to_compress)
            self.compressed_buffer.append(summary)

    def _estimate_tokens(self) -> int:
        """Rough token estimate: ~4 chars per token."""
        text = json.dumps(self.active_buffer, default=str)
        return len(text) // 4

    def _summarize(self, steps: list[dict]) -> str:
        """Summarize a batch of steps into a single sentence."""
        urls = set()
        actions = set()
        for s in steps:
            if url := s.get("url"):
                urls.add(url)
            if action := s.get("action"):
                actions.add(str(action)[:80])
        parts = []
        if urls:
            parts.append(f"Visited {len(urls)} URLs")
        if actions:
            parts.append(f"{len(actions)} actions taken")
        return "; ".join(parts) if parts else f"{len(steps)} steps completed"

    @staticmethod
    def _format_step(step: dict) -> str:
        url = step.get("url", "")
        action = step.get("action", "")
        content = step.get("content", "")[:100]
        return f"- {action or 'navigate'}: {url} {content}".strip()

    @staticmethod
    def _finding_supports_hypothesis(finding: dict, hypothesis: Hypothesis) -> bool:
        title = finding.get("title", "").lower()
        desc = hypothesis.description.lower()
        keywords = desc.split()
        return any(kw in title for kw in keywords if len(kw) > 3)

    @staticmethod
    def _finding_contradicts_hypothesis(finding: dict, hypothesis: Hypothesis) -> bool:
        title = finding.get("title", "").lower()
        contra = ["false positive", "not vulnerable", "no evidence", "safe"]
        return any(c in title for c in contra)
```

**Integration points:**
- `AIBrowserOperator` creates an ACC per investigation and feeds step data
- `FindingMemory` writes compressed summaries to `memory/compressed.md`
- `ReasonerAgent` reads ACC context for deduplication

#### 1.2 Suspicious Points

**File:** `src/agents/browser/suspicious_points.py` (~200 lines)

Key classes:
- `SuspiciousPoint`: dataclass with `sp_type` (dom_element, endpoint, handler, state, missing), `location`, `reason`, `confidence`
- `SuspiciousPointDetector`: heuristic + LLM detection of suspicious targets from surface data

Heuristic rules for web-specific SPs:
- `form_without_csrf` → missing, confidence 0.8
- `input_without_validation` → dom_element, confidence 0.5
- `onclick_handler` → handler, confidence 0.6
- `document_write` → handler, confidence 0.7
- `eval_usage` → handler, confidence 0.8
- `api_without_auth` → endpoint, confidence 0.7
- `redirect_endpoint` → endpoint, confidence 0.6
- `session_in_url` → state, confidence 0.9
- `no_rate_limiting` → missing, confidence 0.6
- `no_cors_validation` → missing, confidence 0.5

**Integration:**
- `ReconAgent` runs `SuspiciousPointDetector.detect(surface)` after surface mapping
- SPs are passed to `PlannerAgent` for investigation prioritization
- SPs are stored in `FindingMemory` for cross-iteration deduplication

#### 1.3 Config Updates

Add to `src/core/config.py`:
```python
# Agent Cognitive Compressor
acc_token_budget: int = Field(default=4000, ge=1000, le=16000)
acc_max_hypotheses: int = Field(default=10, ge=1, le=50)

# Suspicious Points
sp_confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
sp_max_points: int = Field(default=30, ge=5, le=100)
```

---

### Phase 2: MCTS Planner + Missing Code Detector (Week 2)

**Goal:** Upgrade planner from single LLM call to tree-search investigation planning. Add the novel "missing code" detection capability.

#### 2.1 MCTS-Enhanced Planner

**File:** `src/agents/planner_mcts.py` (~250 lines)

Instead of a single LLM call producing flat directives, MCTS:
1. Generates multiple candidate investigation paths
2. Simulates each path (cheap: LLM evaluates expected value)
3. Expands the most promising paths (expensive: LLM deep analysis)
4. Backpropagates scores to update parent node values
5. Returns the investigation tree as prioritized directives

Key classes:
- `MCTSNode`: tree node with state, visits, value, children
- `InvestigationState`: target URL, surface, suspicious points, investigated set, findings
- `MCTSPlannerAgent`: replaces current `PlannerAgent`

Config additions:
```python
mcts_iterations: int = Field(default=20, ge=5, le=100)
mcts_exploration_weight: float = Field(default=1.414, ge=0.1, le=5.0)
mcts_max_depth: int = Field(default=5, ge=2, le=10)
```

#### 2.2 Missing Code Detector

**File:** `src/agents/browser/missing_code.py` (~180 lines)

Detects absent security controls — vulnerabilities defined by what's NOT there:
- Login form without rate limiting → CWE-307
- API endpoint without auth middleware → CWE-306
- Password reset without email verification → CWE-306
- File upload without size/type validation → CWE-434
- No Content-Security-Policy → CWE-693
- No CORS policy / wildcard CORS → CWE-942

Two-tier detection:
1. **Heuristic tier**: Pattern match against surface data (fast, no LLM cost)
2. **LLM tier**: Ask the model "what security controls should be present but are missing?" (expensive, high coverage)

**Integration:** Called from `WebappAgent` after HTTP-level checks, before AI browser investigation.

---

### Phase 3: Adversarial Validation + Causal Attack Graphs (Week 3)

**Goal:** Slash false positives and produce real exploit chains instead of isolated findings.

#### 3.1 Adversarial Validator

**File:** `src/agents/adversarial.py` (~200 lines)

For each finding:
1. **Red Agent** argues the finding IS a real vulnerability (with evidence)
2. **Blue Agent** argues it's a FALSE POSITIVE (with reasoning)
3. **Judge** weighs both arguments and assigns final confidence

Config addition:
```python
adversarial_validation: bool = Field(default=True)
adversarial_min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
```

Only validates findings with confidence > threshold. Batches findings to reduce LLM calls.

**Integration:** `ReasonerAgent` calls `AdversarialValidator.validate_finding()` for each finding. Only validated findings proceed to the report.

#### 3.2 Causal Attack Graph

**File:** `src/graph/attack_graph.py` (~180 lines)

Builds causal attack graphs that chain findings into exploit paths:
- **Node**: a finding or security condition
- **Edge**: causal relationship (enables, requires, exacerbates)
- **Path**: chain of nodes from entry point to impact

Example chain:
```
Missing CORS (node) → enables → XSS (node) → enables →
Cookie theft (node) → leads to → Account takeover (impact)
```

**Integration:** `ReasonerAgent` calls `AttackGraphBuilder.build_graph()` after deduplication. Attack paths are included in the final report.

---

### Phase 4: Trust Scoring + PoC Pipeline + ZCAT Seeds (Week 4)

**Goal:** Add confidence calibration, executable proof-of-concept generation, and seed the vulnerability pattern library.

#### 4.1 Trust Scorer

**File:** `src/reasoning/trust.py` (~120 lines)

Assigns confidence scores to each reasoning step, not just final findings. Enables graceful degradation when evidence is weak.

Trust factors:
- Evidence quality (screenshot, DOM, network) → +0.2
- LLM confidence → weighted
- Adversarial validation result → ±0.1
- Cross-iteration consistency → +0.1

#### 4.2 PoC Pipeline

**File:** `src/agents/browser/poc_pipeline.py` (~150 lines)

Generates executable proof-of-concept for validated findings:
- XSS → curl command or browser script that demonstrates reflection
- Missing header → curl command showing absence
- CSRF → HTML form that auto-submits
- Info disclosure → curl command revealing data

#### 4.3 ZCAT Pattern Library

**File:** `src/patterns/library.py` (~100 lines)

Seed with common vulnerability patterns extracted from OWASP Top 10:
- Pattern: `LoginForm_WithoutRateLimit` → CWE-307
- Pattern: `API_WithoutAuth` → CWE-306
- Pattern: `XSS_Reflected_Unsanitized` → CWE-79
- Pattern: `CSRF_NoToken` → CWE-352
- Pattern: `CORS_Wildcard` → CWE-942

These patterns enable future cross-application transfer without retraining.

---

## 4. Implementation Order & File Changes

### Week 1: ACC + Suspicious Points
| Action | File | Lines Changed |
|--------|------|---------------|
| CREATE | `src/agents/browser/acc.py` | ~150 |
| CREATE | `src/agents/browser/suspicious_points.py` | ~200 |
| MODIFY | `src/core/config.py` | +15 |
| MODIFY | `src/agents/browser/ai_operator.py` | +30 (ACC integration) |
| MODIFY | `src/agents/browser/memory.py` | +20 (compressed buffer) |
| MODIFY | `src/agents/recon.py` | +25 (SP detection) |
| CREATE | `tests/unit/test_acc.py` | ~80 |
| CREATE | `tests/unit/test_suspicious_points.py` | ~100 |

### Week 2: MCTS Planner + Missing Code
| Action | File | Lines Changed |
|--------|------|---------------|
| CREATE | `src/agents/planner_mcts.py` | ~250 |
| CREATE | `src/agents/browser/missing_code.py` | ~180 |
| MODIFY | `src/core/config.py` | +10 |
| MODIFY | `src/agents/webapp.py` | +30 (missing code integration) |
| MODIFY | `src/orchestrator/engine.py` | +10 (wire new planner) |
| MODIFY | `src/orchestrator/state.py` | +5 (SP flow) |
| CREATE | `tests/unit/test_mcts_planner.py` | ~100 |
| CREATE | `tests/unit/test_missing_code.py` | ~80 |

### Week 3: Adversarial Validation + Attack Graphs
| Action | File | Lines Changed |
|--------|------|---------------|
| CREATE | `src/agents/adversarial.py` | ~200 |
| CREATE | `src/graph/attack_graph.py` | ~180 |
| MODIFY | `src/agents/reasoner.py` | +40 (adversarial + attack graph) |
| MODIFY | `src/agents/reporter.py` | +20 (attack paths in report) |
| MODIFY | `src/reporting/md_report.py` | +30 (attack graph section) |
| CREATE | `tests/unit/test_adversarial.py` | ~100 |
| CREATE | `tests/unit/test_attack_graph.py` | ~80 |

### Week 4: Trust + PoC + ZCAT Seeds
| Action | File | Lines Changed |
|--------|------|---------------|
| CREATE | `src/reasoning/trust.py` | ~120 |
| CREATE | `src/agents/browser/poc_pipeline.py` | ~150 |
| CREATE | `src/patterns/library.py` | ~100 |
| CREATE | `src/patterns/__init__.py` | ~10 |
| MODIFY | `src/agents/reasoner.py` | +20 (trust scoring) |
| MODIFY | `src/agents/browser/security_tools.py` | +30 (PoC tools) |
| CREATE | `tests/unit/test_trust.py` | ~60 |
| CREATE | `tests/unit/test_poc_pipeline.py` | ~80 |

---

## 5. Risk Mitigation

| Risk | Mitigation |
|------|-------------|
| MCTS LLM costs (3x calls per iteration) | Tiered oracle: cheap heuristic first, LLM only for expansion. Cap at 20 iterations. |
| Adversarial validation triples reasoner cost | Only validate findings above confidence 0.5. Batch findings into single Red/Blue/Judge calls. |
| Missing code heuristics produce noise | Start conservative (high threshold). Only flag what's clearly absent. |
| ACC compression loses critical details | Keep full-fidelity active buffer for last N steps. Only compress history. |
| ZCAT patterns don't transfer | Start with manually curated OWASP patterns. Measure transfer accuracy before expanding. |
| Browser-use agent instability | Keep scripted fallback (current BrowserOperator) for all new features. |
| LLM JSON parsing failures | All LLM responses go through robust JSON extraction (strip fences, find braces). |

---

## 6. Success Metrics

| Metric | Current | Target (Phase 4) |
|--------|---------|-------------------|
| True positive rate | ~60% | >85% |
| False positive rate | ~40% | <15% |
| Novel vuln classes detected | 5 (header, cookie, CSP, XSS, info) | 10+ (add missing code, attack chains, auth gaps) |
| Attack path coverage | None (isolated findings) | Chained exploit paths |
| Context window utilization | Unbounded (fails on long sessions) | Bounded (ACC) |
| Investigation efficiency | Flat directives | MCTS-prioritized tree |
| Cross-target learning | None | ZCAT pattern library (seeded) |

---

## 7. What Makes This Better Than Mythos

| Capability | Mythos | Assurix Prime |
|-----------|--------|---------------|
| **Missing code detection** | No | Yes — detects absent security controls |
| **Adversarial validation** | Single LLM pass | Red/Blue/Judge eliminates false positives |
| **Investigation planning** | Flat checklist | MCTS tree search allocates compute wisely |
| **Context management** | Unbounded | ACC compressed memory for long sessions |
| **Attack path chaining** | Isolated findings | Causal attack graphs chain vulnerabilities |
| **Targeted investigation** | Scan everything | Suspicious Points focus compute on interesting targets |
| **Cross-target learning** | None | ZCAT pattern library (seeded for growth) |
| **PoC generation** | Descriptions only | Executable proof-of-concept commands |