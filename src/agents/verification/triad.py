"""Triad orchestrator + shared types (plan §3.2.3, §5.2).

The orchestrator fires Reproducer + Adversary + Validator in parallel
via ``asyncio.gather``. Each verifier returns a ``VerifierVote``; the
orchestrator tallies them into a ``TriadResult`` and decides whether
``final_validated`` is True (all three votes are positive).

Consensus rule (per plan §3.1.1 "BL-5 explicit fix"):
  - Reproducer: ``reproduce``  with confidence >= REPRODUCER_MIN_CONFIDENCE
  - Adversary:  ``not_break`` with confidence >= ADVERSARY_MIN_CONFIDENCE
  - Validator:  ``accept``     with confidence >= VALIDATOR_MIN_CONFIDENCE

If any of the three fails, the finding is NOT promoted to ``VALIDATED``
and the failure reason is recorded in ``TriadResult.reason``. The
hypothesis state machine (see ``src/reasoning/state_machine.py``)
reads the TriadResult to decide the next transition.

Failure modes (plan §5.2):
  - Reproducer HTTP timeout  -> ``not_reproduce`` (default low confidence)
  - Adversary LLM unavailable -> fallback to rule-based FP check
  - Validator dedup unavailable -> skip dedup, mark chain_eligible=True
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

logger = logging.getLogger(__name__)


# --- Thresholds (calibrated in Week 4 via ThresholdCalibrator) --------
REPRODUCER_MIN_CONFIDENCE = 0.5
ADVERSARY_MIN_CONFIDENCE = 0.4
VALIDATOR_MIN_CONFIDENCE = 0.5


class VerifierRole(str, Enum):
    """Which of the three verifiers produced a vote."""

    REPRODUCER = "reproducer"
    ADVERSARY = "adversary"
    VALIDATOR = "validator"


Verdict = Literal[
    "reproduce", "not_reproduce",  # Reproducer
    "break", "not_break",          # Adversary
    "accept", "reject", "chainable",  # Validator
]


@dataclass
class VerifierVote:
    """A single verifier's verdict on a candidate finding.

    The triad consensus rule is:
      * Reproducer: verdict == "reproduce"   AND confidence >= REPRODUCER_MIN_CONFIDENCE
      * Adversary:  verdict == "not_break"   AND confidence >= ADVERSARY_MIN_CONFIDENCE
      * Validator:  verdict in ("accept", "chainable") AND confidence >= VALIDATOR_MIN_CONFIDENCE
    """

    role: VerifierRole
    verdict: Verdict
    confidence: float
    evidence_hash: str | None = None
    reasoning: str = ""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def is_positive(self) -> bool:
        """Whether this vote is a "yes" for its role."""
        if self.role is VerifierRole.REPRODUCER:
            return self.verdict == "reproduce"
        if self.role is VerifierRole.ADVERSARY:
            return self.verdict == "not_break"
        if self.role is VerifierRole.VALIDATOR:
            return self.verdict in ("accept", "chainable")
        return False

    def meets_threshold(self) -> bool:
        """Whether the vote passes the per-role confidence floor."""
        if self.role is VerifierRole.REPRODUCER:
            return self.confidence >= REPRODUCER_MIN_CONFIDENCE
        if self.role is VerifierRole.ADVERSARY:
            return self.confidence >= ADVERSARY_MIN_CONFIDENCE
        if self.role is VerifierRole.VALIDATOR:
            return self.confidence >= VALIDATOR_MIN_CONFIDENCE
        return False


@dataclass
class TriadResult:
    """The full triadic verdict on a single finding.

    Persisted to the ``verifier_runs`` table by the call site. The
    ``final_validated`` flag is the single source of truth the
    ResearchLoopAgent reads to decide whether to transition the
    hypothesis state machine to ``VALIDATED``.
    """

    reproducer: VerifierVote
    adversary: VerifierVote
    validator: VerifierVote
    final_validated: bool
    reason: str
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialise for storage in ``verifier_runs`` (JSON column)."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "final_validated": self.final_validated,
            "reason": self.reason,
            "reproducer": {
                "run_id": self.reproducer.run_id,
                "verdict": self.reproducer.verdict,
                "confidence": self.reproducer.confidence,
                "evidence_hash": self.reproducer.evidence_hash,
                "reasoning": self.reproducer.reasoning,
            },
            "adversary": {
                "run_id": self.adversary.run_id,
                "verdict": self.adversary.verdict,
                "confidence": self.adversary.confidence,
                "evidence_hash": self.adversary.evidence_hash,
                "reasoning": self.adversary.reasoning,
            },
            "validator": {
                "run_id": self.validator.run_id,
                "verdict": self.validator.verdict,
                "confidence": self.validator.confidence,
                "evidence_hash": self.validator.evidence_hash,
                "reasoning": self.validator.reasoning,
            },
        }


class TriadError(Exception):
    """Raised when a vote cannot be produced for a non-recoverable reason."""


# --- Scope policy (minimal placeholder; full impl in Week 2) -----------

@dataclass
class ScopePolicy:
    """In-scope host regexes and excluded paths. Used by Validator.

    The full scope policy is owned by the engagement record. This
    minimal dataclass captures what the Validator needs to vote.
    """

    allowed_host_patterns: tuple[str, ...] = ("*",)  # default allow-all
    excluded_paths: tuple[str, ...] = ()
    require_https: bool = False

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL matches the allowed host patterns.

        Substring match on host patterns (a real impl would compile to
        regex). Empty patterns mean "deny all".
        """
        if not self.allowed_host_patterns:
            return False
        if self.allowed_host_patterns == ("*",):
            return True
        return any(p in url for p in self.allowed_host_patterns)


class TriadOrchestrator:
    """Fires all three verifiers in parallel and tallies the result.

    Usage:
        triad = TriadOrchestrator(scope=scope_policy, existing_findings=existing)
        result = await triad.run(finding, target=target_url)
        if result.final_validated:
            # promote hypothesis to VALIDATED
            ...
    """

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        existing_findings: list[dict[str, Any]] | None = None,
    ) -> None:
        self.scope = scope or ScopePolicy()
        self.existing_findings = list(existing_findings or [])
        # Verifier instances are constructed lazily so tests can patch
        # individual verifiers without re-instantiating the orchestrator.
        self._reproducer: Reproducer | None = None
        self._adversary: Adversary | None = None
        self._validator: Validator | None = None

    @property
    def reproducer(self) -> Reproducer:
        if self._reproducer is None:
            from src.agents.verification.reproducer import Reproducer
            self._reproducer = Reproducer()
        return self._reproducer

    @property
    def adversary(self) -> Adversary:
        if self._adversary is None:
            from src.agents.verification.adversary import Adversary
            self._adversary = Adversary()
        return self._adversary

    @property
    def validator(self) -> Validator:
        if self._validator is None:
            from src.agents.verification.validator import Validator
            self._validator = Validator(
                scope=self.scope,
                existing_findings=self.existing_findings,
            )
        return self._validator

    async def run(
        self,
        finding: dict[str, Any],
        target: str,
    ) -> TriadResult:
        """Run all three verifiers in parallel and return a TriadResult.

        The target URL is the live target the finding was reported
        against. The validators treat ``target`` as authoritative for
        the re-execution / scope check.
        """
        findings_for_v = (
            *self.existing_findings,
            finding,  # include the candidate itself for the dedup self-check
        )
        # Fire all three in parallel. asyncio.gather returns results in
        # submission order even if they complete out of order. Any
        # exception in a single verifier is caught by that verifier and
        # returned as a negative vote, so the gather never raises here.
        repro, adv, val = await asyncio.gather(
            self.reproducer.vote(finding, target=target),
            self.adversary.vote(finding, target=target),
            self.validator.vote(finding, scope=self.scope, existing=list(findings_for_v)),
            return_exceptions=False,
        )

        final_validated, reason = self._tally(repro, adv, val)
        return TriadResult(
            reproducer=repro,
            adversary=adv,
            validator=val,
            final_validated=final_validated,
            reason=reason,
        )

    @staticmethod
    def _tally(
        repro: VerifierVote,
        adv: VerifierVote,
        val: VerifierVote,
    ) -> tuple[bool, str]:
        """Apply the consensus rule and return (validated, reason)."""
        failures: list[str] = []

        if not repro.is_positive:
            failures.append(
                f"Reproducer voted {repro.verdict!r} "
                f"(confidence={repro.confidence:.2f})"
            )
        elif not repro.meets_threshold():
            failures.append(
                f"Reproducer confidence {repro.confidence:.2f} "
                f"below {REPRODUCER_MIN_CONFIDENCE}"
            )

        if not adv.is_positive:
            failures.append(
                f"Adversary voted {adv.verdict!r} "
                f"(confidence={adv.confidence:.2f})"
            )
        elif not adv.meets_threshold():
            failures.append(
                f"Adversary confidence {adv.confidence:.2f} "
                f"below {ADVERSARY_MIN_CONFIDENCE}"
            )

        if not val.is_positive:
            failures.append(
                f"Validator voted {val.verdict!r} "
                f"(confidence={val.confidence:.2f})"
            )
        elif not val.meets_threshold():
            failures.append(
                f"Validator confidence {val.confidence:.2f} "
                f"below {VALIDATOR_MIN_CONFIDENCE}"
            )

        if failures:
            return False, "; ".join(failures)
        return True, "All three verifiers voted positive"


__all__ = [
    "TriadOrchestrator",
    "TriadResult",
    "VerifierVote",
    "VerifierRole",
    "TriadError",
    "ScopePolicy",
    "REPRODUCER_MIN_CONFIDENCE",
    "ADVERSARY_MIN_CONFIDENCE",
    "VALIDATOR_MIN_CONFIDENCE",
]
