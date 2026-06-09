"""Validator verifier (plan §3.2.3, §5.2).

The Validator runs three sub-checks on the candidate finding:

  1. **Scope** — the finding targets an in-scope host/path.
  2. **Dedup** — no semantically-similar finding (by SimHash on the
     canonical title+description) is already in ``existing_findings``.
  3. **Chain eligibility** — the finding could be a node in an exploit
     chain (e.g. it grants a capability, it links to an entry point,
     or it has a known chain pattern match).

All three sub-checks are run; the Validator returns a single vote
that combines them. The consensus is:
  - accept: all three pass
  - chainable: scope+dedup pass, AND chain-eligible
  - reject: any check fails

Failure modes (per plan §5.2):
  - Dedup unavailable (SimHash backend missing) -> skip dedup, mark
    chain_eligible=True. This is the "degrade safely" path: we don't
    block a real finding just because the dedup index is down.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Sequence

from src.agents.verification.triad import ScopePolicy, VerifierRole, VerifierVote

logger = logging.getLogger(__name__)


# Capability tokens (plan §5.4.bis vocabulary). These are the closed
# set the Validator uses to decide whether a finding could be a chain
# node. Keep in sync with src/graph/capabilities.py::CAPABILITY_VOCABULARY
# (the 11 canonical capability strings).
_CHAIN_CAPABILITY_TOKENS = (
    "session_hijack", "auth_bypass", "lfi_primitive", "sqli_primitive",
    "cloud_meta_access", "ssrf_primitive", "rce_primitive", "file_write",
    "open_redirect", "graphql_introspection", "privilege_escalation",
)

# Cap the dedup pass to a small prefix to avoid quadratic SimHash work
# on a 10k-finding engagement.
_MAX_DEDUP_COMPARE = 200


def _normalize_for_simhash(text: str) -> list[str]:
    """Tokenise text for SimHash. Lowercased alphanumeric tokens."""
    if not text:
        return []
    return re.findall(r"[a-z0-9]{2,}", text.lower())


def _simhash(tokens: Sequence[str]) -> int:
    """A tiny 64-bit SimHash. Suitable for short texts (titles).

    NOT cryptographically secure — used only for approximate dedup.
    """
    if not tokens:
        return 0
    bits = 64
    counters = [0] * bits
    for tok in tokens:
        h = hashlib.md5(tok.encode("utf-8", errors="ignore")).digest()
        # Use 8 bytes -> 64 bits
        for i in range(bits):
            byte = h[i // 8]
            bit = (byte >> (i % 8)) & 1
            counters[i] += 1 if bit else -1
    out = 0
    for i, c in enumerate(counters):
        if c > 0:
            out |= 1 << i
    return out


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# Threshold for "similar enough" — a SimHash distance of <=10/64 is
# widely cited as "near-duplicate" for short texts.
_SIMHASH_NEAR_DUP_THRESHOLD = 10


class Validator:
    """The scope + dedup + chain-eligibility verifier."""

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        existing_findings: list[dict[str, Any]] | None = None,
    ) -> None:
        self.scope = scope or ScopePolicy()
        # Snapshot the findings list at construction time so vote() is
        # pure with respect to its inputs.
        self._existing: tuple[dict[str, Any], ...] = tuple(existing_findings or [])

    async def vote(
        self,
        finding: dict[str, Any],
        scope: ScopePolicy | None = None,
        existing: list[dict[str, Any]] | None = None,
    ) -> VerifierVote:
        """Run scope + dedup + chain eligibility checks.

        Never raises. All exceptions are caught and turned into a
        ``reject`` with low confidence.
        """
        try:
            effective_scope = scope or self.scope
            existing_list = list(existing) if existing is not None else list(self._existing)

            scope_ok, scope_reason = self._check_scope(finding, effective_scope)
            if not scope_ok:
                return self._vote(
                    verdict="reject",
                    confidence=0.0,
                    reasoning=scope_reason,
                )

            is_dup, dup_reason, dup_ev_hash = self._check_dedup(finding, existing_list)
            if is_dup:
                return self._vote(
                    verdict="reject",
                    confidence=0.95,  # high confidence: we have a near-dup
                    reasoning=dup_reason,
                    evidence_hash=dup_ev_hash,
                )

            chainable, chain_reason = self._check_chainable(finding)
            if chainable:
                verdict = "chainable"
                reasoning = (
                    f"scope+dedup ok; chain-eligible: {chain_reason}"
                )
                confidence = 0.7
            else:
                verdict = "accept"
                reasoning = "scope+dedup ok; not chain-eligible"
                confidence = 0.6

            # Use a hash of the dedup-pass + scope check as the evidence
            # anchor. A real implementation would hash the full
            # canonical evidence blob.
            evidence = f"{scope_reason} | {dup_reason or 'no_dup'}"
            ev_hash = hashlib.sha256(
                evidence.encode("utf-8", errors="ignore")
            ).hexdigest()
            return self._vote(
                verdict=verdict,  # type: ignore[arg-type]
                confidence=confidence,
                reasoning=reasoning,
                evidence_hash=ev_hash,
            )
        except Exception as exc:
            logger.exception("Validator error")
            return self._vote(
                verdict="reject",
                confidence=0.0,
                reasoning=f"validator error: {exc}",
            )

    # --- Sub-checks -----------------------------------------------------

    def _check_scope(
        self,
        finding: dict[str, Any],
        scope: ScopePolicy,
    ) -> tuple[bool, str]:
        """Check the finding's URL is in scope."""
        url = (
            finding.get("url")
            or finding.get("target_url")
            or finding.get("evidence_url")
            or ""
        )
        if not url:
            # No URL to check — be conservative but not blocking.
            return True, "no url to scope-check"
        if scope.excluded_paths and any(p in url for p in scope.excluded_paths):
            return False, f"url matches excluded path: {url}"
        if not scope.is_in_scope(url):
            return False, f"url not in scope: {url}"
        return True, f"in scope: {url}"

    def _check_dedup(
        self,
        finding: dict[str, Any],
        existing: list[dict[str, Any]],
    ) -> tuple[bool, str, str | None]:
        """Check for semantically-similar existing findings.

        Returns (is_dup, reason, evidence_hash). Skips silently on
        malformed candidates (treated as no-dup, per "degrade safely").
        """
        candidate_text = " ".join(
            str(finding.get(k, "")) for k in ("title", "description", "url")
        )
        candidate_tokens = _normalize_for_simhash(candidate_text)
        if not candidate_tokens:
            return False, "no candidate tokens to dedup", None
        candidate_hash = _simhash(candidate_tokens)

        # Compare against the first N existing findings to keep this
        # O(N) in dedup work, not O(N^2). N=200 is generous for the
        # typical 5-20 finding engagement.
        window = existing[:_MAX_DEDUP_COMPARE]
        for ex in window:
            ex_text = " ".join(
                str(ex.get(k, "")) for k in ("title", "description", "url")
            )
            ex_tokens = _normalize_for_simhash(ex_text)
            if not ex_tokens:
                continue
            ex_hash = _simhash(ex_tokens)
            dist = _hamming(candidate_hash, ex_hash)
            if dist <= _SIMHASH_NEAR_DUP_THRESHOLD:
                ev = f"near-dup at hamming={dist}: {ex_text[:120]}"
                ev_hash = hashlib.sha256(
                    ev.encode("utf-8", errors="ignore")
                ).hexdigest()
                return True, ev, ev_hash
        return False, f"no near-dup in {len(window)} existing", None

    def _check_chainable(
        self,
        finding: dict[str, Any],
    ) -> tuple[bool, str]:
        """Heuristic: could this finding be a node in an exploit chain?

        Returns (chainable, reason). The check is intentionally simple:
        a finding is chainable if it grants one of the closed-set
        capability tokens (see ``src/graph/capabilities.py``) or if
        its title/description contains a known chain-hub word.

        Per plan §5.4.bis, this is the first-class capability vocab.
        """
        # 1. Explicit capability grant in metadata.
        caps = finding.get("capabilities") or finding.get("grants_capabilities") or []
        if isinstance(caps, (list, tuple)):
            for cap in caps:
                if isinstance(cap, str) and cap in _CHAIN_CAPABILITY_TOKENS:
                    return True, f"grants capability: {cap}"

        # 2. Heuristic on text — a real finding that grants a primitive
        #    tends to mention it. False positives here just promote
        #    the finding to "chainable" (still validated) — safe.
        text = " ".join(
            str(finding.get(k, "")) for k in ("title", "description", "class")
        ).lower()
        hub_words = (
            "ssrf", "rce", "lfi", "xss", "ssti", "deserialization",
            "auth bypass", "admin", "file read", "file inclusion",
            "command injection", "code execution", "credential",
        )
        for word in hub_words:
            if word in text:
                return True, f"contains chain-hub token: {word}"
        return False, "no chain-hub token matched"

    def _vote(
        self,
        verdict: str,
        confidence: float,
        reasoning: str,
        evidence_hash: str | None = None,
    ) -> VerifierVote:
        return VerifierVote(
            role=VerifierRole.VALIDATOR,
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            evidence_hash=evidence_hash,
            reasoning=reasoning,
        )


__all__ = ["Validator"]
