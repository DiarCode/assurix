"""Agent Cognitive Compressor — bounded memory for long-running browser agents.

Solves the context window problem: as agents take more steps, the context
grows unbounded until it exceeds the LLM token limit. ACC keeps a bounded
context by compressing older steps into summaries while retaining recent
steps at full fidelity and tracking active investigation hypotheses.
"""

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

    Three-tier memory:
    1. Active buffer — recent steps at full fidelity
    2. Compressed buffer — older steps as summaries
    3. Hypothesis tracker — active investigation hypotheses with evidence weights
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
            self.hypotheses.sort(key=lambda h: h.confidence, reverse=True)
            removed = self.hypotheses.pop()
            logger.debug(
                "Dropped hypothesis: %s (confidence: %.2f)",
                removed.description,
                removed.confidence,
            )
        self.hypotheses.append(Hypothesis(description=description, confidence=confidence))

    def mark_investigated(self, item: str) -> None:
        """Mark a suspicious point as already investigated."""
        self.investigated.add(item)

    def is_investigated(self, item: str) -> bool:
        """Check if a suspicious point has been investigated."""
        return item in self.investigated

    def get_context(self) -> str:
        """Return compressed + active context for LLM prompt."""
        parts: list[str] = []
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
            for item in list(self.investigated)[-10:]:
                parts.append(f"  - {item}")
        return "\n".join(parts)

    def get_hypotheses_summary(self) -> list[dict]:
        """Return hypotheses as serializable dicts."""
        return [
            {
                "description": h.description,
                "confidence": h.confidence,
                "evidence_for": h.evidence_for,
                "evidence_against": h.evidence_against,
                "tested": h.tested,
            }
            for h in self.hypotheses
        ]

    def _maybe_compress(self) -> None:
        """Compress oldest active steps into summaries when budget exceeded."""
        if self._estimate_tokens() > self.token_budget:
            split = max(1, len(self.active_buffer) // 2)
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
        urls: set[str] = set()
        actions: set[str] = set()
        findings_count = 0
        for s in steps:
            if url := s.get("url"):
                urls.add(url)
            if action := s.get("action"):
                actions.add(str(action)[:80])
            if s.get("finding"):
                findings_count += 1
        parts: list[str] = []
        if urls:
            parts.append(f"Visited {len(urls)} URLs")
        if actions:
            parts.append(f"{len(actions)} actions taken")
        if findings_count:
            parts.append(f"{findings_count} findings")
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