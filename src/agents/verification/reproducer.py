"""Reproducer verifier (plan §3.2.3, §5.2).

Re-executes the candidate exploit against the live target using the
exact request the original finding reported. If the response matches
the expected behavior, vote ``reproduce``; otherwise ``not_reproduce``.

The Reproducer is the cheapest of the three verifiers (one HTTP call,
no LLM), but also the most decisive: a reproducer failure is a HARD
"not validated" regardless of how strongly the Adversary argues in
favor. This is by design — we won't promote a finding we can't
reproduce end-to-end.

The existing ``_validate_idor``, ``_validate_xss``, etc. in
``src/agents/validation.py`` are reused via the ``hook`` callable
parameter so the legacy single-validator behavior remains reachable.
If no hook matches the finding class, the Reproducer falls back to
"try the URL with the payload as a query parameter" — a generic
catch-all that catches obvious echo / 200-bias FPs.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import urllib.parse
from typing import Any, Awaitable, Callable

import httpx

from src.agents.verification.triad import VerifierRole, VerifierVote

logger = logging.getLogger(__name__)


# A reproducer hook takes (finding, target, client) and returns
# ``{"reproduced": bool, "evidence": str, "confidence": float}``.
ReproducerHook = Callable[
    [dict[str, Any], str, httpx.AsyncClient],
    Awaitable[dict[str, Any]],
]


class Reproducer:
    """Re-executes the exploit and verifies the live behavior matches."""

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        hooks: dict[str, ReproducerHook] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        # Map of finding class -> async hook. The orchestrator does
        # NOT inject hooks by default; the legacy ValidationAgent
        # methods can be passed in from the call site.
        self.hooks: dict[str, ReproducerHook] = dict(hooks or {})

    async def vote(
        self,
        finding: dict[str, Any],
        target: str,
    ) -> VerifierVote:
        """Run the reproducer. Always returns a VerifierVote, never raises.

        Failure modes (per plan §5.2):
          - HTTP timeout -> not_reproduce, confidence 0.2
          - Connection error -> not_reproduce, confidence 0.1
          - 5xx response -> not_reproduce, confidence 0.3
        """
        try:
            async with httpx.AsyncClient(
                verify=False,  # pentest scope; cert pinning is the target's job
                timeout=self.timeout_seconds,
                follow_redirects=False,
            ) as client:
                finding_class = (finding.get("class") or "").lower()
                hook = self.hooks.get(finding_class)
                if hook is not None:
                    result = await hook(finding, target, client)
                else:
                    result = await self._generic_replay(finding, target, client)
        except httpx.TimeoutException as exc:
            logger.warning("Reproducer timeout for %s: %s", target, exc)
            return self._vote("not_reproduce", confidence=0.2, reasoning=f"timeout: {exc}")
        except httpx.HTTPError as exc:
            logger.warning("Reproducer HTTP error for %s: %s", target, exc)
            return self._vote("not_reproduce", confidence=0.1, reasoning=f"http error: {exc}")
        except Exception as exc:  # last-resort safety net
            logger.exception("Reproducer unexpected error")
            return self._vote("not_reproduce", confidence=0.1, reasoning=f"error: {exc}")

        reproduced = bool(result.get("reproduced"))
        evidence = str(result.get("evidence", ""))
        confidence = float(result.get("confidence", 0.0))
        verdict = "reproduce" if reproduced else "not_reproduce"
        return self._vote(
            verdict=verdict,
            confidence=max(0.0, min(1.0, confidence)),
            reasoning=evidence or f"reproduced={reproduced}",
            evidence_hash=hashlib.sha256(evidence.encode("utf-8", errors="ignore")).hexdigest()
            if evidence
            else None,
        )

    async def _generic_replay(
        self,
        finding: dict[str, Any],
        target: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        """Generic replay when no class-specific hook is registered.

        Strategy: GET the target URL with the finding's primary payload
        attached as a query parameter. If the response status is 2xx
        and the response body contains an echo of the payload, vote
        ``reproduce``. Otherwise ``not_reproduce``.

        This is a *defensive* default — most real findings will route
        through a class-specific hook (set up by the call site). The
        generic replay only catches obvious echo / 200-bias FPs and is
        deliberately low-confidence.
        """
        payload = finding.get("payload")
        if not payload or not target:
            return {"reproduced": False, "evidence": "no payload/target", "confidence": 0.0}

        try:
            response = await client.get(target, params={"q": str(payload)[:256]})
        except httpx.HTTPError as exc:
            return {"reproduced": False, "evidence": f"http error: {exc}", "confidence": 0.0}

        if response.status_code >= 500:
            return {
                "reproduced": False,
                "evidence": f"server error {response.status_code}",
                "confidence": 0.0,
            }

        body = response.text or ""
        echoed = str(payload)[:64] in body
        if response.status_code == 200 and echoed:
            return {
                "reproduced": True,
                "evidence": f"payload echoed in 200 response ({len(body)} bytes)",
                "confidence": 0.6,  # low — generic, not class-specific
            }
        return {
            "reproduced": False,
            "evidence": f"no echo (status={response.status_code}, body_len={len(body)})",
            "confidence": 0.0,
        }

    def _vote(
        self,
        verdict: str,
        confidence: float,
        reasoning: str,
        evidence_hash: str | None = None,
    ) -> VerifierVote:
        return VerifierVote(
            role=VerifierRole.REPRODUCER,
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            evidence_hash=evidence_hash,
            reasoning=reasoning,
        )


__all__ = ["Reproducer", "ReproducerHook"]
