"""DepthPassAgent — bounded post-reporter depth pass.

Executes six sequential phases that go beyond the default linear scan
(subdomain enumeration, JS source crawl, auth brute-force, IDOR, WAF
bypass + retry, chain assembly). Hard-budgeted by wall-time, invocation
count, and first state-change detection.

The class is intentionally scaffolded here — the WAF rotator, LLM-backed
in-run reflection, and cross-run technique memory are filled in by
worker-2 (self-improvement). Worker-3 (tests) exercises the budget and
state-change abort logic. This file imports cleanly and returns a
well-formed result dict from each phase stub.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any
from urllib.parse import quote, quote_plus

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.core.audit import log_action

logger = logging.getLogger(__name__)


DEFAULT_BUDGET_MINUTES = 30
DEFAULT_MAX_INVOCATIONS = 200
DEFAULT_REFLECTION_CAP = 50
DEFAULT_WAF_TOP_TECHNIQUES = 5

# Attack categories the WAF rotator knows how to mutate. New categories
# fall back to the 6-strategy sequence with a generic payload template.
WAF_STRATEGY_CATEGORIES: tuple[str, ...] = (
    "xss",
    "sqli",
    "ssrf",
    "cmdi",
    "path_traversal",
    "auth_bypass",
)


# ----------------------------------------------------------------------
# WAF bypass rotator
# ----------------------------------------------------------------------


class WAFBypassRotator:
    """Six-strategy rotator for WAF-bypass probes.

    Each strategy is a *callable* ``(payload, method, headers) -> mutated``
    so the rotator works for any probe shape (GET, POST, header injection,
    …). Strategies are deterministic and pure — the same input always
    produces the same mutated output, which keeps tests reproducible.
    """

    NAME = "waf_bypass_rotator"

    def __init__(self) -> None:
        self._strategies: list[tuple[str, Any]] = [
            ("url_encode", self._url_encode),
            ("double_encode", self._double_encode),
            ("unicode_normalize", self._unicode_normalize),
            ("chunked_transfer", self._chunked_transfer),
            ("header_injection", self._header_injection),
            ("alt_verb", self._alt_verb),
        ]
        # In-memory technique memory for the current run. Each entry is
        # ``(strategy_name, success: bool)``. We use this to bias the
        # next ``rotate()`` call: techniques that already worked for
        # this target are emitted first. The cross-run memory lives in
        # the ``technique_memory`` DB table (see ``_record_technique_
        # outcome``); this dict is the *current run* only.
        self._run_outcomes: dict[str, dict[str, int]] = {
            name: {"success": 0, "total": 0} for name, _ in self._strategies
        }

    @property
    def strategy_names(self) -> list[str]:
        """Return the public names of all 6 strategies (in rotation order)."""
        return [name for name, _ in self._strategies]

    def record_outcome(self, strategy: str, *, success: bool) -> None:
        """Record the outcome of one probe under ``strategy``.

        The rotator uses this to bias future ``rotate()`` calls toward
        techniques that have already succeeded for this target. Unknown
        ``strategy`` names are ignored (defensive — a typo or a new
        strategy from a different version of the rotator should not
        crash the depth pass).
        """
        if strategy not in self._run_outcomes:
            return
        self._run_outcomes[strategy]["total"] += 1
        if success:
            self._run_outcomes[strategy]["success"] += 1

    def top_k_strategies(self, k: int = 3) -> list[str]:
        """Return up to ``k`` strategy names with the highest success
        ratio in the current run.

        Tie-breaking is stable: when two strategies have the same
        success ratio, the one declared first in ``__init__`` wins.
        Strategies with zero probes (no evidence) are excluded — we
        cannot rank what we have not tried.
        """
        if k <= 0:
            return []
        ranked: list[tuple[float, int, str]] = []
        for idx, (name, _) in enumerate(self._strategies):
            stats = self._run_outcomes[name]
            total = stats["total"]
            if total <= 0:
                continue
            ranked.append((stats["success"] / total, idx, name))
        # Sort by ratio desc, then by original index ASC (earlier
        # declaration wins ties — more stable + the public order is
        # the documented contract).
        ranked.sort(key=lambda r: (-r[0], r[1]))
        return [name for _, _, name in ranked[:k]]

    def rotate(
        self,
        payload: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return a list of 6 mutated probe dicts, one per strategy.

        Each result has the shape::

            {
                "strategy": "<name>",
                "method": "GET"|"POST"|...,
                "payload": "...",
                "headers": {...},
            }

        Callers iterate, send the probe, observe the response, and
        call :meth:`WAFBypassRotator.record_outcome` so the technique
        memory is updated.

        Ordering: if the rotator has any run-time outcome data, the
        techniques with the highest success ratio are emitted first
        (so the caller tests the most likely winner before burning
        budget on low-probability strategies). Strategies with no
        recorded outcomes fall through in their original declaration
        order.
        """
        results: list[dict[str, Any]] = []
        base_headers = dict(headers or {})
        # Bias the ordering by run-time success ratio. We never drop
        # a strategy — all 6 still get emitted — we only reorder.
        top = self.top_k_strategies(k=len(self._strategies))
        order: list[tuple[str, Any]]
        if top:
            by_name = dict(self._strategies)
            seen: set[str] = set()
            ordered: list[tuple[str, Any]] = []
            for name in top:
                if name in by_name and name not in seen:
                    ordered.append((name, by_name[name]))
                    seen.add(name)
            for name, fn in self._strategies:
                if name not in seen:
                    ordered.append((name, fn))
                    seen.add(name)
            order = ordered
        else:
            order = self._strategies
        for name, fn in order:
            mutated = fn(payload, method=method, headers=dict(base_headers))
            # Each strategy returns a *new* dict — callers must not
            # mutate the input.
            results.append({
                "strategy": name,
                "method": mutated.get("method", method),
                "payload": mutated.get("payload", payload),
                "headers": mutated.get("headers", base_headers),
            })
        return results

    # ------------------------------------------------------------------
    # Strategies — each is a pure (payload, method, headers) -> dict.
    # ------------------------------------------------------------------

    @staticmethod
    def _url_encode(
        payload: str, *, method: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Strategy 1: standard URL encoding (percent-encode special chars).

        Encodes ``< > " ' ; ( )`` — the chars most WAFs look for in
        XSS/SQLi/CMDi probes. Safe for query strings and form bodies.
        """
        encoded = quote(payload, safe="")
        return {"method": method, "payload": encoded, "headers": headers}

    @staticmethod
    def _double_encode(
        payload: str, *, method: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Strategy 2: double-URL encoding (encode the percent signs too).

        Many WAFs decode once, then re-check the decoded string — this
        defeats that pattern. Best for WAFs that only do one round of
        normalisation.
        """
        once = quote(payload, safe="")
        twice = quote(once, safe="")
        return {"method": method, "payload": twice, "headers": headers}

    @staticmethod
    def _unicode_normalize(
        payload: str, *, method: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Strategy 3: unicode normalisation (full-width / homoglyph).

        Replaces ASCII ``<``, ``>``, ``"``, ``'`` with their full-width
        unicode equivalents (U+FF1C, U+FF1E, U+FF02, U+FF07). The
        browser decodes these back to ASCII at render time, but naive
        WAFs do not.
        """
        table = str.maketrans({
            "<": "＜",  # full-width less-than
            ">": "＞",  # full-width greater-than
            '"': "＂",  # full-width double quote
            "'": "＇",  # full-width single quote
            "(": "（",  # full-width left paren
            ")": "）",  # full-width right paren
        })
        return {
            "method": method,
            "payload": payload.translate(table),
            "headers": headers,
        }

    @staticmethod
    def _chunked_transfer(
        payload: str, *, method: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Strategy 4: chunked transfer-encoding header (HTTP/1.1).

        Splits the payload into 1-byte chunks and sets
        ``Transfer-Encoding: chunked`` so the WAF sees a streaming
        request — many WAFs only inspect the first chunk.
        """
        chunks = "".join(f"{len(c):x}\r\n{c}\r\n" for c in payload)
        chunks += "0\r\n\r\n"
        new_headers = dict(headers)
        new_headers["Transfer-Encoding"] = "chunked"
        # Send the chunked body as the payload; the caller is expected
        # to know the request shape (POST body or query string).
        return {"method": method, "payload": chunks, "headers": new_headers}

    @staticmethod
    def _header_injection(
        payload: str, *, method: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Strategy 5: header injection — smuggle the payload via headers.

        Adds ``X-Forwarded-For``, ``X-Original-URL``, and
        ``X-Rewrite-URL`` headers carrying the payload. Some WAFs
        forward headers verbatim to the backend, bypassing the URL
        filter.
        """
        new_headers = dict(headers)
        new_headers["X-Forwarded-For"] = payload
        new_headers["X-Original-URL"] = payload
        new_headers["X-Rewrite-URL"] = payload
        return {"method": method, "payload": payload, "headers": new_headers}

    @staticmethod
    def _alt_verb(
        payload: str, *, method: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        """Strategy 6: alternative HTTP verb.

        Swaps ``GET`` → ``POST``, or vice versa. Many WAFs only have
        rules for the most common verb, so flipping the verb bypasses
        the rule and the backend accepts both.
        """
        alt = "POST" if method.upper() == "GET" else "GET"
        return {"method": alt, "payload": payload, "headers": headers}


class StateChangeDetector:
    """Inspects tool responses for evidence of successful state change.

    Three independent triggers — the first match aborts the depth pass
    (state change = the bar is met, no need to keep producing):

    1. New ``Set-Cookie`` header appears in a tool response (session
       promotion — the target issued a new authenticated session).
    2. A database write tool returns a non-empty row count (data was
       persisted server-side).
    3. A seeded exfiltration marker appears in a response body (data
       left the trust boundary).
    """

    EXFIL_MARKERS = (
        "assurix_exfil_",
        "assurix_canary_",
        "assurix_xss_",
    )

    def __init__(self) -> None:
        self._baseline_cookies: set[str] = set()
        self._triggered: dict[str, Any] | None = None

    def snapshot_baseline_cookies(self, cookies: set[str]) -> None:
        """Record the cookie jar before depth probing begins."""
        self._baseline_cookies = {c for c in cookies}

    def inspect(
        self,
        *,
        response_headers: dict[str, str] | None = None,
        response_body: str | None = None,
        db_row_count: int | None = None,
    ) -> dict[str, Any] | None:
        """Return a state-change record on first trigger, else None.

        The detector is single-shot: once it fires, subsequent calls
        keep returning the same record (idempotent) so the caller can
        log the abort without worrying about race conditions between
        concurrent phases.
        """
        if self._triggered is not None:
            return self._triggered

        headers = response_headers or {}

        # Trigger 1: new Set-Cookie.
        new_cookies: set[str] = set()
        set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
        if set_cookie:
            for raw in set_cookie.split("\n"):
                name = raw.split("=", 1)[0].strip()
                if name and name not in self._baseline_cookies:
                    new_cookies.add(name)
        if new_cookies:
            self._triggered = {
                "trigger": "new_session_cookie",
                "cookies": sorted(new_cookies),
                "headers": dict(headers),
            }
            return self._triggered

        # Trigger 2: DB write with non-empty row count.
        if db_row_count is not None and db_row_count > 0:
            self._triggered = {
                "trigger": "db_write_persisted",
                "row_count": db_row_count,
            }
            return self._triggered

        # Trigger 3: seeded exfil marker in response body.
        body = response_body or ""
        for marker in self.EXFIL_MARKERS:
            if marker in body:
                self._triggered = {
                    "trigger": "exfil_marker_reflected",
                    "marker": marker,
                    "body_excerpt": body[:512],
                }
                return self._triggered

        return None

    @property
    def triggered(self) -> dict[str, Any] | None:
        return self._triggered


class DepthPassAgent(BaseAgent):
    """Bounded post-reporter depth pass.

    Runs after the default linear scan and the reporter. Six sequential
    phases, each a stub today — worker-2 fills in the WAF rotator, the
    in-run reflection loop, and the cross-run technique memory lookup.
    Worker-3 verifies the budget + state-change abort path.

    Configuration (all optional; defaults are defensive):

    * ``depth_pass_budget_minutes`` — wall-time cap (default 30, min 5,
      max 120 per plan §Acceptance Criteria).
    * ``depth_pass_max_invocations`` — atomic counter cap (default 200).
    * ``depth_pass_started_at`` — set by ``start_engagement`` to make
      the run idempotent (per plan §Risks, "Idempotency lock").
    * ``depth_pass_cancelled`` — set by ``cancel_engagement`` to abort
      cleanly mid-phase.
    """

    name = "depth_pass"

    def __init__(self) -> None:
        self._state_change = StateChangeDetector()
        self._invocations = 0
        self._wall_start: float = 0.0
        self._reflection_count = 0
        self._phase_results: dict[str, dict[str, Any]] = {}
        self._aborted_reason: str | None = None
        # Lock for the atomic invocation counter — phases may run
        # concurrently if the engine ever fan-outs; the counter must
        # remain exact so the budget is enforced.
        self._inv_lock = asyncio.Lock()
        # WAF rotator instance — one per agent run is fine; the
        # rotator is stateless (pure functions).
        self._waf_rotator = WAFBypassRotator()
        # Cache for the engagement-scoped target signature; computed
        # once at the top of ``execute`` and reused by every phase.
        self._target_signature: str = ""
        # Per-engagement reflection counter — capped at
        # ``DEFAULT_REFLECTION_CAP`` (50). 1 reflection per probe.
        self._reflection_lock = asyncio.Lock()

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        """Run the six phases under the depth-pass budget.

        Returns a dict with the shape described in the plan §Step 2:
        ``findings``, ``chains``, ``state_change``, ``invocations_used``,
        ``wall_time_seconds``, ``phase_results``, ``aborted_reason``,
        plus ``depth_pass_complete=True`` so the engine can transition
        the engagement to COMPLETED on the next routing pass.
        """
        engagement_id = payload.get("engagement_id", "")
        # Persist on self so ``_check_cancellation`` (and any other
        # internal helper that needs to look the engagement up by id)
        # can read it. Previously this was missing — the cancel probe
        # saw an empty engagement_id, ``session.get(Engagement, "")``
        # returned None, and ``depth_pass_cancelled`` was silently
        # ignored (operator cancel never aborted the run).
        self._engagement_id = engagement_id
        target_url = payload.get("target_url", "")
        config = payload.get("config", {}) or {}

        budget_minutes = max(5, min(120, int(config.get("depth_pass_budget_minutes", DEFAULT_BUDGET_MINUTES))))
        max_invocations = int(config.get("depth_pass_max_invocations", DEFAULT_MAX_INVOCATIONS))
        # Persist on self so phase methods (notably phase 5) can read
        # the cap and apply a per-phase sub-budget without having to
        # thread it through every signature.
        self._max_invocations = max_invocations

        if config.get("depth_pass_cancelled"):
            self._aborted_reason = "cancelled_before_start"
            return self._finalize([], [], wall_time=0.0)

        self._wall_start = time.monotonic()
        wall_time_budget = budget_minutes * 60.0

        # Compute the engagement-scoped target signature once, up
        # front, so every phase can use it for technique-memory
        # lookups. Per plan §Self-Improvement: the signature is a
        # sha256(normalized_base_url + tech_fingerprint_json)[:16] —
        # a second run against the same target gets the top
        # previously-successful techniques ranked #1.
        tech_fingerprint = payload.get("tech_fingerprint", {}) or {}
        self._target_signature = compute_target_signature(
            target_url, tech_fingerprint
        )

        logger.info(
            "depth_pass starting engagement=%s target=%s budget_min=%d max_inv=%d",
            engagement_id, target_url, budget_minutes, max_invocations,
        )

        await log_action(
            session=session,
            action="depth_pass_started",
            actor="depth_pass",
            payload={
                "engagement_id": engagement_id,
                "budget_minutes": budget_minutes,
                "max_invocations": max_invocations,
            },
        )

        # Six sequential phases. The wall-time check is performed at the
        # top of each iteration so we never start a phase we cannot
        # finish; the invocation counter is checked inside ``_bump_inv``
        # so concurrent phases cannot exceed the cap.
        phases = [
            ("subdomain_enum", self._phase_1_subdomain_enum),
            ("js_source_crawl", self._phase_2_js_source_crawl),
            ("auth_brute_force", self._phase_3_auth_brute_force),
            ("idor", self._phase_4_idor),
            ("waf_bypass_retry", self._phase_5_waf_bypass_retry),
            ("chain_assembly", self._phase_6_chain_assembly),
        ]

        async def _run_under_wall_timeout(coro: Any) -> Any:
            """Run a phase with the wall-time budget as ``wait_for`` ceiling."""
            elapsed = time.monotonic() - self._wall_start
            remaining = max(0.0, wall_time_budget - elapsed)
            if remaining <= 0.0:
                self._aborted_reason = "wall_time_exceeded"
                return None
            try:
                return await asyncio.wait_for(coro, timeout=remaining)
            except asyncio.TimeoutError:
                self._aborted_reason = "wall_time_exceeded"
                return None

        all_findings: list[dict[str, Any]] = []
        all_chains: list[dict[str, Any]] = []

        try:
            for phase_name, phase_fn in phases:
                if self._aborted_reason is not None:
                    break
                if await self._check_cancellation(session):
                    self._aborted_reason = "cancelled_mid_phase"
                    break

                logger.info("depth_pass entering phase=%s", phase_name)
                phase_result = await _run_under_wall_timeout(
                    phase_fn(target_url=target_url, session=session)
                )
                if phase_result is None:
                    # Either wall-time exceeded or the phase returned
                    # ``None`` to signal a clean abort (e.g. state
                    # change fired). Either way, stop scheduling.
                    if self._aborted_reason is None:
                        self._aborted_reason = f"{phase_name}_returned_none"
                    break

                self._phase_results[phase_name] = phase_result
                all_findings.extend(phase_result.get("findings", []))
                all_chains.extend(phase_result.get("chains", []))

                # State change check is run at the end of every phase —
                # once it fires, we stop producing more probes.
                if self._state_change.triggered is not None:
                    if self._aborted_reason is None:
                        self._aborted_reason = "state_change_detected"
                    break
        except Exception as exc:  # pragma: no cover — defensive
            logger.exception("depth_pass crashed: %s", exc)
            self._aborted_reason = f"exception:{type(exc).__name__}"
        finally:
            wall_time = time.monotonic() - self._wall_start

        await log_action(
            session=session,
            action="depth_pass_completed",
            actor="depth_pass",
            payload={
                "engagement_id": engagement_id,
                "invocations_used": self._invocations,
                "wall_time_seconds": wall_time,
                "aborted_reason": self._aborted_reason,
                "phases_run": list(self._phase_results.keys()),
                "findings_count": len(all_findings),
                "chains_count": len(all_chains),
                "state_change": self._state_change.triggered,
            },
        )

        return self._finalize(all_findings, all_chains, wall_time=wall_time)

    # ------------------------------------------------------------------
    # Budget helpers
    # ------------------------------------------------------------------

    async def _bump_inv(self) -> bool:
        """Atomically increment the invocation counter.

        Returns ``True`` if the increment is within budget, ``False``
        if the cap has been reached. The caller must stop probing on
        ``False``.
        """
        async with self._inv_lock:
            if self._invocations >= DEFAULT_MAX_INVOCATIONS:
                if self._aborted_reason is None:
                    self._aborted_reason = "invocation_cap_reached"
                return False
            self._invocations += 1
            return True

    async def _check_cancellation(self, session: AsyncSession) -> bool:
        """Check ``engagement.config.depth_pass_cancelled``.

        The plan §Risks requires a clean abort path when an operator
        cancels mid-phase. We re-read the engagement on every check so
        the flag is picked up promptly without holding a long-lived
        session.
        """
        try:
            from src.db.models import Engagement
            eng = await session.get(Engagement, getattr(self, "_engagement_id", "") or "")
        except Exception as exc:
            # Swallow real DB errors (connection lost, transaction
            # aborted, etc.) but log them — a silent return leaves
            # operators wondering why their cancel command had no
            # effect. We still treat the error as "not cancelled" so
            # a transient DB hiccup doesn't abort an otherwise-healthy
            # depth pass.
            logger.warning("depth_pass cancel check failed: %s", exc)
            return False
        if eng is None:
            return False
        if (eng.config or {}).get("depth_pass_cancelled"):
            return True
        return False

    # ------------------------------------------------------------------
    # Phase stubs — filled in by worker-2 (WAF rotator + reflection)
    # and worker-3 (tests). Each stub returns a phase-result dict with
    # ``findings`` and ``chains`` lists so the aggregator works.
    # ------------------------------------------------------------------

    async def _phase_1_subdomain_enum(
        self, *, target_url: str, session: AsyncSession,
    ) -> dict[str, Any]:
        """Phase 1 — discover subdomains adjacent to the target.

        Stub: returns no findings. Worker-2 wires in
        ``SubdomainEnumerator`` from ``src.agents.tools``.
        """
        return {"findings": [], "chains": [], "phase": "subdomain_enum"}

    async def _phase_2_js_source_crawl(
        self, *, target_url: str, session: AsyncSession,
    ) -> dict[str, Any]:
        """Phase 2 — crawl JS bundles for hidden endpoints / API keys.

        Stub: returns no findings.
        """
        return {"findings": [], "chains": [], "phase": "js_source_crawl"}

    async def _phase_3_auth_brute_force(
        self, *, target_url: str, session: AsyncSession,
    ) -> dict[str, Any]:
        """Phase 3 — credential brute-force against discovered login forms.

        Stub: returns no findings.
        """
        return {"findings": [], "chains": [], "phase": "auth_brute_force"}

    async def _phase_4_idor(
        self, *, target_url: str, session: AsyncSession,
    ) -> dict[str, Any]:
        """Phase 4 — IDOR via differential testing of resource IDs.

        Stub: returns no findings.
        """
        return {"findings": [], "chains": [], "phase": "idor"}

    async def _phase_5_waf_bypass_retry(
        self, *, target_url: str, session: AsyncSession,
    ) -> dict[str, Any]:
        """Phase 5 — WAF bypass via 6-strategy rotator + reflection.

        Per plan §Self-Improvement:

        1. Load the top-5 successful techniques per attack_category
           from :class:`TechniqueMemory` (main DB) and try them first.
        2. Auto-rotate through the 6 strategies in
           :class:`WAFBypassRotator` for the remaining probes.
        3. On failure, reflect: invoke the LLM once ("why did this
           fail? what mutation next?"). Cap 1 reflection per probe,
           50 max per engagement.

        Each probe outcome is recorded to ``TechniqueMemory`` via
        :meth:`_record_technique_outcome` so cross-run memory stays
        current.
        """
        findings: list[dict[str, Any]] = []
        chains: list[dict[str, Any]] = []

        # Load previously-successful techniques (top 5 per category).
        # This is the "warm start" from cross-run memory.
        top_techniques = await self._load_top_techniques_from_memory(
            session, limit=DEFAULT_WAF_TOP_TECHNIQUES
        )

        # Pick a small, fixed set of probe payloads per attack category.
        # The actual probe execution is left to the caller; this phase
        # decides *what* to try and *what* to do on failure.
        probe_plan = self._build_waf_probe_plan(target_url, top_techniques)

        # Per-phase invocation cap (FIX 4). The full 200-invocation
        # budget is split roughly in half so phase 5 can never starve
        # phases 1-4. Without this, ``probe_plan`` can have up to
        # ``len(top_techniques) + 6`` items, and each failing probe
        # burns 1 (initial) + 6 (rotated) + 1 (reflection) = 8
        # invocations — 11 probes × 8 = 88, leaving 112 for the rest
        # of the agent. With a large historical-warm-start this can
        # exhaust the entire budget inside phase 5.
        phase_5_cap = max(1, int(getattr(self, "_max_invocations", DEFAULT_MAX_INVOCATIONS) // 2))

        for probe in probe_plan:
            if self._invocations >= phase_5_cap:
                # Per-phase sub-budget exhausted — stop cleanly and
                # record why so the operator can see the abort reason
                # in the engagement log.
                if self._aborted_reason is None:
                    self._aborted_reason = "phase_5_budget_exhausted"
                break
            if not await self._bump_inv():
                break  # invocation cap reached — stop cleanly

            category = probe["category"]
            payload = probe["payload"]
            method = probe.get("method", "GET")
            headers = probe.get("headers", {}) or {}

            # Try the historical top-5 first, then rotate the 6
            # strategies. ``outcome`` is set by the helper that would
            # actually fire the HTTP request (intentionally stubbed
            # here — the plan says "wire in existing tools in a
            # follow-up"; worker-3 tests the rotation logic with
            # mocks).
            outcome = await self._attempt_waf_probe(
                payload=payload,
                method=method,
                headers=headers,
                category=category,
                probe_meta=probe,
            )

            # Record every attempt so technique memory stays accurate,
            # even on failures.
            await self._record_technique_outcome(
                session=session,
                technique=str(probe.get("technique_name") or payload),
                attack_category=category,
                success=bool(outcome.get("success")),
                confidence=float(outcome.get("confidence", 0.0) or 0.0),
            )

            if outcome.get("success"):
                findings.append(self._build_finding_from_outcome(
                    outcome, probe, strategy_used=probe.get("strategy_name", "historical"),
                ))
            else:
                # Try the 6-strategy rotation for the failing probe.
                rotated = self._waf_rotator.rotate(
                    payload, method=method, headers=headers
                )
                for rotated_probe in rotated:
                    if self._invocations >= phase_5_cap:
                        if self._aborted_reason is None:
                            self._aborted_reason = "phase_5_budget_exhausted"
                        break
                    if not await self._bump_inv():
                        break
                    rotated_outcome = await self._attempt_waf_probe(
                        payload=rotated_probe["payload"],
                        method=rotated_probe["method"],
                        headers=rotated_probe["headers"],
                        category=category,
                        probe_meta={**probe, "strategy_name": rotated_probe["strategy"]},
                    )
                    # Feed the rotator's in-run technique memory so
                    # the *next* rotate() call biases toward
                    # strategies that already worked for this target.
                    # The cross-run memory write below persists the
                    # same outcome for future engagements.
                    self._waf_rotator.record_outcome(
                        rotated_probe["strategy"],
                        success=bool(rotated_outcome.get("success")),
                    )
                    await self._record_technique_outcome(
                        session=session,
                        technique=f"{rotated_probe['strategy']}:{payload}",
                        attack_category=category,
                        success=bool(rotated_outcome.get("success")),
                        confidence=float(rotated_outcome.get("confidence", 0.0) or 0.0),
                    )
                    if rotated_outcome.get("success"):
                        findings.append(self._build_finding_from_outcome(
                            rotated_outcome, probe,
                            strategy_used=rotated_probe["strategy"],
                        ))
                        break
                else:
                    # All 6 strategies failed for this probe → reflect.
                    reflection = await self._reflect_on_failure(
                        session=session,
                        payload=payload,
                        category=category,
                        last_response=outcome.get("response_summary", ""),
                    )
                    if reflection:
                        # One last attempt with the LLM-suggested mutation
                        # is out of scope for this scaffold; we log the
                        # reflection so a future iteration can wire it in.
                        logger.info(
                            "waf_bypass_retry reflection category=%s suggestion=%s",
                            category, reflection.get("next_mutation", ""),
                        )

        return {
            "findings": findings,
            "chains": chains,
            "phase": "waf_bypass_retry",
            "top_techniques_loaded": len(top_techniques),
            "probes_attempted": len(probe_plan),
        }

    # ------------------------------------------------------------------
    # Phase 5 helpers
    # ------------------------------------------------------------------

    async def _load_top_techniques_from_memory(
        self,
        session: AsyncSession,
        *,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Read top-``limit`` successful techniques per attack category.

        Reads from the main DB ``technique_memory`` table via
        :class:`src.agents.meta_learning.TechniqueMemory`. Best-effort:
        any failure (table missing, DB locked) is logged at INFO and
        treated as "no historical data" — the depth pass still runs
        with the 6-strategy rotator.
        """
        try:
            from src.agents.meta_learning import TechniqueMemory
        except Exception as exc:  # pragma: no cover — defensive import
            logger.info("TechniqueMemory import failed: %s", exc)
            return []

        memory = TechniqueMemory()
        try:
            results: list[dict[str, Any]] = []
            sig = {
                "target_signature": self._target_signature,
                "url": getattr(self, "_last_target_url", ""),
            }
            for category in WAF_STRATEGY_CATEGORIES:
                rows = await memory.query(category, sig, limit=limit)
                for row in rows:
                    if float(row.get("success_rate", 0.0)) > 0.0:
                        row["_category"] = category
                        results.append(row)
            # Sort: highest success_rate first, then by use_count.
            results.sort(
                key=lambda r: (
                    -float(r.get("success_rate", 0.0)),
                    -int(r.get("use_count", 0)),
                )
            )
            return results[:limit * len(WAF_STRATEGY_CATEGORIES)]
        except Exception as exc:  # pragma: no cover — DB-side failure
            logger.info("TechniqueMemory query failed (non-fatal): %s", exc)
            return []
        finally:
            try:
                await memory.close()
            except Exception:
                pass

    @staticmethod
    def _build_waf_probe_plan(
        target_url: str,
        top_techniques: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build the ordered list of probes to try in the WAF phase.

        Probes from ``top_techniques`` come first (warm start); the
        rest are generic XSS/SQLi/SSRF/CMDi payloads to feed the
        rotator. Returns a list of probe dicts, each with a unique
        ``probe_id`` for tracing and the engagement's real ``target_url``
        so the dedup key (computed in
        :meth:`_build_finding_from_outcome`) is stable across runs.
        """
        plan: list[dict[str, Any]] = []
        for row in top_techniques:
            plan.append({
                "probe_id": f"hist-{len(plan)}",
                "target_url": target_url,
                "category": row.get("_category", "xss"),
                "payload": row.get("technique", ""),
                "method": "GET",
                "headers": {},
                "technique_name": row.get("technique", ""),
                "strategy_name": "historical",
                "source": "technique_memory",
            })

        # Generic probe templates — one per category. These give the
        # 6-strategy rotator something concrete to mutate when there
        # is no historical data.
        generic = {
            "xss": "<script>alert(1)</script>",
            "sqli": "' OR '1'='1",
            "ssrf": "http://169.254.169.254/latest/meta-data/",
            "cmdi": "; id",
            "path_traversal": "../../../../etc/passwd",
            "auth_bypass": "admin' --",
        }
        for category, payload in generic.items():
            plan.append({
                "probe_id": f"gen-{len(plan)}",
                "target_url": target_url,
                "category": category,
                "payload": payload,
                "method": "GET",
                "headers": {},
                "technique_name": payload,
                "strategy_name": "rotator",
                "source": "generic_template",
            })
        return plan

    async def _attempt_waf_probe(
        self,
        *,
        payload: str,
        method: str,
        headers: dict[str, str],
        category: str,
        probe_meta: dict[str, Any],
    ) -> dict[str, Any]:
        """Run a single WAF probe and return an outcome dict.

        This is a *scaffold* — the real HTTP request is left to the
        follow-up that wires the depth pass into the actual HTTP
        client (httpx/aiohttp). For now we return a deterministic
        "not bypassed" outcome so the rotator + memory loop can be
        tested in isolation.
        """
        # ``probe_meta`` is kept for the real implementation; the
        # scaffold ignores it.  State-change detection still runs on
        # whatever the real call returns.
        self._state_change.inspect(
            response_headers={"X-Assurix-Waf-Probe": category},
            response_body=payload,
        )
        return {
            "success": False,
            "confidence": 0.0,
            "response_summary": f"WAF block (scaffold) category={category}",
        }

    async def _record_technique_outcome(
        self,
        *,
        session: AsyncSession,
        technique: str,
        attack_category: str,
        success: bool,
        confidence: float,
    ) -> None:
        """Persist the outcome of one WAF-bypass attempt to TechniqueMemory.

        Writes to the main DB ``technique_memory`` table (per plan
        §Self-Improvement: the legacy filesystem path is no longer
        used). Best-effort: any failure is logged at INFO and
        swallowed so a DB hiccup never breaks the depth pass.
        """
        try:
            from src.agents.meta_learning import TechniqueMemory
        except Exception as exc:  # pragma: no cover
            logger.info("TechniqueMemory import failed during record: %s", exc)
            return

        memory = TechniqueMemory()
        try:
            await memory.record(
                technique=technique,
                vuln_class=attack_category,
                target_signature={
                    "target_signature": self._target_signature,
                },
                success=success,
                confidence=confidence,
                tier=2,
            )
        except Exception as exc:  # pragma: no cover
            logger.info("TechniqueMemory.record failed (non-fatal): %s", exc)
        finally:
            try:
                await memory.close()
            except Exception:
                pass

    async def _reflect_on_failure(
        self,
        *,
        session: AsyncSession,
        payload: str,
        category: str,
        last_response: str,
    ) -> dict[str, Any] | None:
        """Ask the LLM why a probe failed and what to try next.

        Caps:

        * 1 reflection per probe (caller responsibility).
        * 50 reflections per engagement (enforced here via
          ``_reflection_count`` and ``_reflection_lock``).

        Returns ``None`` when the cap is hit or the LLM call fails
        (the rotator already tried 6 strategies; reflection is a
        best-effort improvement on top).
        """
        async with self._reflection_lock:
            if self._reflection_count >= DEFAULT_REFLECTION_CAP:
                return None
            self._reflection_count += 1

        # Keep the call short: a stub "no LLM configured" path is the
        # default; real deployments inject an LLM client.
        try:
            from src.llm.router import get_llm_router  # type: ignore
        except Exception:
            return None

        try:
            router = get_llm_router()
            prompt = (
                f"A {category} probe failed after 6 WAF-bypass "
                f"strategies. Payload: {payload!r}. Last response: "
                f"{last_response[:200]!r}. Suggest one concrete "
                "mutation to try next."
            )
            response = await router.generate(prompt)
            return {
                "next_mutation": str(response)[:500],
                "category": category,
            }
        except Exception as exc:  # pragma: no cover
            logger.info("Reflection LLM call failed (non-fatal): %s", exc)
            return None

    @staticmethod
    def _build_finding_from_outcome(
        outcome: dict[str, Any],
        probe: dict[str, Any],
        *,
        strategy_used: str,
    ) -> dict[str, Any]:
        """Build a finding dict from a successful WAF-bypass outcome.

        Computes the dedup key via
        :func:`JSONReportGenerator._compute_dedup_key` (sha256 of
        url|category|payload[:16]) so dedup at report time is
        consistent across agents.

        Note: the ``url`` argument must be the *real* target URL (taken
        from ``probe["target_url"]``) — NOT the synthetic ``probe_id``
        like ``"hist-3"`` or ``"gen-5"``. Using ``probe_id`` here would
        give a different dedup key on every run and bypass the
        report-time dedup entirely.
        """
        try:
            from src.reporting.json_report import JSONReportGenerator
            dedup_key = JSONReportGenerator._compute_dedup_key(
                url=probe.get("target_url", "") or probe.get("probe_id", ""),
                attack_category=probe.get("category", ""),
                param=probe.get("payload", ""),
            )
        except Exception:
            dedup_key = None

        return {
            "title": f"WAF bypass via {strategy_used} ({probe.get('category', 'unknown')})",
            "description": (
                f"Payload {probe.get('payload', '')!r} bypassed WAF using "
                f"strategy {strategy_used}."
            ),
            "severity": "high",
            "confidence_score": float(outcome.get("confidence", 0.5) or 0.5),
            "source_agent": "depth_pass",
            "dedup_key": dedup_key,
            "owasp_category": "WAF-BYPASS",
            "finding_metadata": {
                "attack_category": probe.get("category"),
                "strategy": strategy_used,
                "waf_bypass": True,
                "poc": probe.get("payload", ""),
                "request_response": outcome.get("response_summary", ""),
            },
        }

    async def _phase_6_chain_assembly(
        self, *, target_url: str, session: AsyncSession,
    ) -> dict[str, Any]:
        """Phase 6 — assemble multi-step attack chains from prior findings.

        Stub: returns no chains.
        """
        return {"findings": [], "chains": [], "phase": "chain_assembly"}

    # ------------------------------------------------------------------
    # Result shaping
    # ------------------------------------------------------------------

    def _finalize(
        self,
        findings: list[dict[str, Any]],
        chains: list[dict[str, Any]],
        *,
        wall_time: float,
    ) -> dict[str, Any]:
        """Shape the final return dict per plan §Step 2 spec."""
        return {
            "findings": findings,
            "chains": chains,
            "state_change": self._state_change.triggered,
            "invocations_used": self._invocations,
            "wall_time_seconds": wall_time,
            "phase_results": dict(self._phase_results),
            "aborted_reason": self._aborted_reason,
            # Marker for the engine: when this comes back from depth_pass
            # the routing block (engine.py:471 area) sees
            # ``result.get("depth_pass_complete")`` and transitions the
            # engagement to COMPLETED.
            "depth_pass_complete": True,
        }


# ----------------------------------------------------------------------
# Helpers exported for worker-3 tests
# ----------------------------------------------------------------------


def compute_target_signature(base_url: str, tech_fingerprint: dict[str, Any]) -> str:
    """Stable signature used to look up cross-run technique memory.

    Per plan §Self-Improvement: ``target_signature = sha256(
    normalized_base_url + tech_fingerprint_json)[:16]``. Returns a 16-char
    hex digest so a second run against the same target gets the top
    successful techniques ranked #1.
    """
    import json
    normalized = (base_url or "").strip().rstrip("/").lower()
    fp_json = json.dumps(tech_fingerprint or {}, sort_keys=True, default=str)
    payload = f"{normalized}|{fp_json}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]
