"""Context compaction for long-running agent loops.

Provides a sliding window over observations so the LLM prompt doesn't
grow unboundedly. Older observations are compacted into a summary;
confirmed findings are always preserved.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_SIZE = 30


class ContextManager:
    """Manages context window for ReAct loop iterations.

    Keeps a sliding window of recent observations, compacts older ones
    into summaries, and preserves confirmed findings indefinitely.
    """

    def __init__(self, window_size: int = DEFAULT_WINDOW_SIZE) -> None:
        self.window_size = window_size
        self._observations: list[dict[str, Any]] = []
        self._compacted_summary: str = ""
        self._confirmed_findings: list[dict[str, Any]] = []
        self._failed_attempts: list[dict[str, Any]] = []
        self._semantic_compact_pending: bool = False

    def add_observation(self, observation: dict[str, Any]) -> None:
        """Add a new observation to the sliding window."""
        self._observations.append(observation)
        self._maybe_compact()

    def confirm_finding(self, finding: dict[str, Any]) -> None:
        """Add a confirmed finding — these are never compacted away."""
        self._confirmed_findings.append(finding)

    def record_failed_attempt(self, action_type: str, url: str, reason: str = "") -> None:
        """Record a failed attempt to avoid repeating it."""
        self._failed_attempts.append({"action": action_type, "url": url, "reason": reason})

    def is_failed_attempt(self, action_type: str, url: str) -> bool:
        """Check if this action was already tried and failed."""
        return any(
            f["action"] == action_type and f["url"] == url
            for f in self._failed_attempts
        )

    def get_context_for_llm(self) -> str:
        """Build the LLM-ready context string from current state."""
        parts: list[str] = []

        if self._compacted_summary:
            parts.append(f"## Prior Context (compacted)\n{self._compacted_summary}")

        if self._confirmed_findings:
            parts.append("## Confirmed Findings")
            for f in self._confirmed_findings:
                parts.append(f"- [{f.get('severity', '?')}] {f.get('title', 'unknown')}: {f.get('evidence', '')[:200]}")

        if self._failed_attempts:
            parts.append("## Failed Attempts (do not repeat)")
            for f in self._failed_attempts[-10:]:
                parts.append(f"- {f['action']} on {f['url']}: {f.get('reason', 'failed')}")

        if self._observations:
            parts.append("## Recent Observations")
            for obs in self._observations:
                action = obs.get("action", "unknown")
                url = obs.get("url", "")
                result_summary = obs.get("result_summary", str(obs.get("result", ""))[:300])
                parts.append(f"- [{action}] {url}: {result_summary}")

        return "\n\n".join(parts) if parts else "No context yet."

    def get_recent_observations(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return recent observations within the sliding window."""
        n = limit or self.window_size
        return self._observations[-n:]

    def get_confirmed_findings(self) -> list[dict[str, Any]]:
        return list(self._confirmed_findings)

    def get_failed_attempts(self) -> list[dict[str, Any]]:
        return list(self._failed_attempts)

    def _maybe_compact(self) -> None:
        """Compact older observations when window overflows.

        Performs basic string-based compaction immediately and sets
        a flag requesting semantic compaction when an LLM client
        becomes available.
        """
        if len(self._observations) <= self.window_size:
            return

        overflow = self._observations[: -self.window_size]
        self._observations = self._observations[-self.window_size :]

        compacted = self._compact_observations(overflow)
        if self._compacted_summary:
            self._compacted_summary = f"{self._compacted_summary}\n{compacted}"
        else:
            self._compacted_summary = compacted

        # Keep compacted summary bounded
        if len(self._compacted_summary) > 4000:
            self._compacted_summary = self._compacted_summary[-3000:]

        # Signal that semantic compaction would improve the summary
        self._semantic_compact_pending = True

    @staticmethod
    def _compact_observations(observations: list[dict[str, Any]]) -> str:
        """Summarize a batch of older observations."""
        summaries: list[str] = []
        for obs in observations:
            action = obs.get("action", "unknown")
            url = obs.get("url", "")
            result = obs.get("result_summary", str(obs.get("result", ""))[:150])
            summaries.append(f"[{action}] {url}: {result}")
        return "; ".join(summaries)

    async def llm_compact(self, llm_client: Any) -> None:
        """Use LLM to generate a higher-quality summary of compacted observations."""
        if not self._compacted_summary:
            return
        try:
            from src.llm.frontier_client import UnifiedLLMClient

            if not isinstance(llm_client, UnifiedLLMClient):
                llm_client = UnifiedLLMClient()
            response = await llm_client.chat(
                messages=[
                    {
                        "role": "system",
                        "content": "Summarize these security observations concisely, preserving key findings and URLs.",
                    },
                    {"role": "user", "content": self._compacted_summary[:6000]},
                ],
                task_type="context_compaction",
                max_tokens=2048,
            )
            if response and len(response) < len(self._compacted_summary):
                self._compacted_summary = response
        except Exception as exc:
            logger.warning("LLM compaction failed, keeping rule-based summary: %s", exc)

    async def semantic_compact(self, llm_client: Any) -> None:
        """Use LLM to generate a structured security summary preserving critical context.

        Unlike basic llm_compact which just shortens text, semantic_compact
        preserves the structure and semantics of security findings, active
        hypotheses, failed attempts, and target technology profiles.
        Uses task_type='context_compaction' with max_tokens=2048.
        """
        if not self._compacted_summary and not self._confirmed_findings and not self._failed_attempts:
            return

        try:
            from src.llm.frontier_client import UnifiedLLMClient

            if not isinstance(llm_client, UnifiedLLMClient):
                llm_client = UnifiedLLMClient()

            # Build structured context sections for the LLM
            findings_section = "No confirmed findings yet."
            if self._confirmed_findings:
                finding_lines = [
                    f"- [{f.get('severity', '?')}] {f.get('title', 'unknown')}: "
                    f"{f.get('evidence', '')[:150]} (CWE: {f.get('cwe_id', 'N/A')})"
                    for f in self._confirmed_findings[:10]
                ]
                findings_section = "\n".join(finding_lines)

            failed_section = "No failed attempts recorded."
            if self._failed_attempts:
                failed_lines = [
                    f"- {f['action']} on {f['url']}: {f.get('reason', 'failed')}"
                    for f in self._failed_attempts[-10:]
                ]
                failed_section = "\n".join(failed_lines)

            prior_section = self._compacted_summary[:3000] if self._compacted_summary else "No prior context."

            prompt = (
                "Generate a structured security assessment summary from the following data.\n"
                "Preserve these categories:\n"
                "## Active Attack Hypotheses\n"
                "## Confirmed Vulnerabilities\n"
                "## Failed Attempts (do not repeat)\n"
                "## Target Technology Profile\n\n"
                f"### Confirmed Findings:\n{findings_section}\n\n"
                f"### Failed Attempts:\n{failed_section}\n\n"
                f"### Prior Compacted Context:\n{prior_section}"
            )

            response = await llm_client.chat(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security assessment summarizer. Preserve all vulnerability "
                            "details, attack hypotheses, and technology fingerprints. Remove "
                            "redundant observations but keep every confirmed finding and "
                            "failed attempt pattern."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                task_type="context_compaction",
                max_tokens=2048,
            )

            if response and len(response) < len(self._compacted_summary):
                self._compacted_summary = response
                self._semantic_compact_pending = False
        except Exception as exc:
            logger.warning("Semantic compaction failed, keeping existing summary: %s", exc)

    @property
    def needs_semantic_compact(self) -> bool:
        """Whether semantic compaction is pending and would be beneficial."""
        return self._semantic_compact_pending

    def reset(self) -> None:
        """Clear all context state."""
        self._observations.clear()
        self._compacted_summary = ""
        self._confirmed_findings.clear()
        self._failed_attempts.clear()
        self._semantic_compact_pending = False

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    @property
    def finding_count(self) -> int:
        return len(self._confirmed_findings)

    @property
    def has_compacted_data(self) -> bool:
        return bool(self._compacted_summary)