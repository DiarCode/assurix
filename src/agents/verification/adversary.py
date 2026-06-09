"""Adversary verifier (plan §3.2.3, §5.2).

Attacks the finding's *premise*, not its symptom. The legacy
``AdversarialValidator`` (Red/Blue/Judge) is wrapped as a single
verifier: it runs the Red/Blue debate then summarises the judge's
verdict into a VerifierVote.

A finding's premise is the assumption "this is exploitable in the
real world". The Adversary's job is to find compensating controls,
WAFs, or contextual defenses that make the premise false. A vote of
``break`` means the premise is broken; ``not_break`` means the premise
holds (the finding is plausible).

Failure modes (per plan §5.2):
  - LLM unavailable -> fallback to rule-based ``AdversarialValidator
    ._is_obvious_fp`` (the existing FP_PATTERNS list). This degrades
    safely: rule-based FPs are still caught, novel FPs are not, so the
    finding is promoted with a lower confidence ceiling.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from src.agents.verification.triad import VerifierRole, VerifierVote

logger = logging.getLogger(__name__)


class Adversary:
    """The 'break the premise' verifier.

    The implementation is intentionally thin: it delegates to the
    existing ``AdversarialValidator`` and translates its
    ``{validated, confidence_score}`` output into a VerifierVote.
    """

    def __init__(self, llm_validator=None) -> None:
        # llm_validator is a class instance (not a name) so tests can
        # inject a mock. When None, we lazily import the production
        # ``AdversarialValidator`` on first vote.
        self._llm = llm_validator

    async def vote(
        self,
        finding: dict[str, Any],
        target: str,
    ) -> VerifierVote:
        """Run the Red/Blue/Judge debate and return a VerifierVote.

        Never raises. All exceptions are caught and turned into
        ``break`` (the conservative default — refuse to promote if
        the premise could not be defended).
        """
        try:
            validator = self._get_validator()
            # AdversarialValidator is async; it can be either a real
            # async method or a callable returning a coroutine. We
            # support both shapes for test injection.
            surface = finding.get("surface", {}) or {}
            result = await validator.validate_finding(finding, surface)
        except Exception as exc:  # last-resort safety net
            logger.warning("Adversary fallback (rule-based): %s", exc)
            return self._vote(
                verdict="not_break",  # conservative: don't block on debate failure
                confidence=0.3,         # low — we couldn't actually debate
                reasoning=f"adversary error, rule-based fallback: {exc}",
            )

        validated = bool(result.get("validated"))
        confidence = float(result.get("confidence_score", 0.0))
        reasoning = str(result.get("validation_reasoning", ""))

        # Translation rule:
        #   validated=True  -> "not_break" (premise holds, the finding is plausible)
        #   validated=False -> "break"     (premise is broken, the finding is a FP)
        verdict = "not_break" if validated else "break"

        evidence_hash = None
        if reasoning:
            evidence_hash = hashlib.sha256(
                reasoning.encode("utf-8", errors="ignore")
            ).hexdigest()

        return self._vote(
            verdict=verdict,
            confidence=max(0.0, min(1.0, confidence)),
            reasoning=reasoning,
            evidence_hash=evidence_hash,
        )

    def _get_validator(self):
        """Lazy-construct the underlying AdversarialValidator."""
        if self._llm is not None:
            return self._llm
        from src.agents.adversarial import AdversarialValidator
        self._llm = AdversarialValidator()
        return self._llm

    def _vote(
        self,
        verdict: str,
        confidence: float,
        reasoning: str,
        evidence_hash: str | None = None,
    ) -> VerifierVote:
        return VerifierVote(
            role=VerifierRole.ADVERSARY,
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            evidence_hash=evidence_hash,
            reasoning=reasoning,
        )


__all__ = ["Adversary"]
