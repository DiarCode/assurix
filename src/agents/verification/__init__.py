"""Adversarial verifier triad (plan §3.2.3, §5.2).

The triad is the structural fix for hallucinations: a finding cannot
reach ``VALIDATED`` unless THREE independent verifiers all vote "yes":

  1. **Reproducer** — re-executes the candidate exploit against the
     live target with the exact request from the evidence chain. If
     the response matches the expected behavior, vote ``reproduce``.

  2. **Adversary** — attacks the finding's *premise*, not its symptom.
     Uses the existing ``AdversarialValidator`` (Red/Blue/Judge) to
     produce a debate trace. Votes ``break`` (premise is wrong) or
     ``not_break`` (premise holds).

  3. **Validator** — runs the scope policy (the finding targets an
     in-scope asset), the dedup check (no semantically-similar
     finding already exists), and the chain-eligibility check. Votes
     ``accept`` / ``reject`` plus a sub-vote ``chainable`` if the
     finding could be a node in an exploit chain.

The triad is wrapped by ``TriadOrchestrator.run()`` which fires all
three votes in parallel via ``asyncio.gather`` and returns a
``TriadResult`` with the consensus verdict.

Backward compatibility: the existing ``AdversarialValidator`` continues
to be reachable as ``Adversary`` (the old debate becomes one of three
verifiers). The single-verifier ``ValidationAgent.execute()`` is
replaced by ``TriadOrchestrator.run()`` for new findings, but the
legacy methods (``_validate_idor`` etc.) live on as the Reproducer's
re-execution hooks.
"""
from __future__ import annotations

from src.agents.verification.reproducer import Reproducer
from src.agents.verification.adversary import Adversary
from src.agents.verification.validator import Validator
from src.agents.verification.triad import (
    TriadOrchestrator,
    TriadResult,
    VerifierVote,
    VerifierRole,
    TriadError,
)

__all__ = [
    "Reproducer",
    "Adversary",
    "Validator",
    "TriadOrchestrator",
    "TriadResult",
    "VerifierVote",
    "VerifierRole",
    "TriadError",
]
