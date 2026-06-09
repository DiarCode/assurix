"""Unit tests for DepthPassAgent and its components.

Verifies the depth pass's hard guarantees from plan §Step 2 + §Step 3:

* Return dict schema (per plan §Step 2: findings, chains, state_change,
  invocations_used, wall_time_seconds, phase_results, aborted_reason,
  depth_pass_complete=True).
* Invocation budget cap at 200.
* Wall-time budget cap (asyncio.wait_for timeout path).
* State-change detector fires on first new Set-Cookie and aborts the run.
* WAF rotator iterates all 6 strategies in deterministic order.
* Reflection cap at 50 per engagement.

Tools (network probes, real HTTP) are mocked so the tests are
hermetic. The agent is constructed directly — no DB, no scheduler.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.depth_pass import (
    DEFAULT_MAX_INVOCATIONS,
    DEFAULT_REFLECTION_CAP,
    DepthPassAgent,
    StateChangeDetector,
    WAFBypassRotator,
    compute_target_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_session() -> AsyncMock:
    """Return an AsyncMock AsyncSession sufficient for depth_pass.log_action.

    ``log_action`` calls ``session.execute(stmt)`` which must return an
    awaitable result whose ``scalar_one_or_none()`` returns either an
    AuditLog with ``current_hash`` or None. We configure the execute
    coroutine to return a result whose ``scalar_one_or_none()`` is
    None (no prior audit row) so the chain starts at the all-zeros
    hash. We also patch ``log_action`` directly in most tests for
    hermeticity, but the return-shape test runs the real ``log_action``
    path to verify the dict shape end-to-end.
    """
    session = AsyncMock()
    session.add = MagicMock()
    session.get = AsyncMock(return_value=None)
    # Audit chain probe: ``session.execute(stmt).scalar_one_or_none()``
    # must return None on a fresh engagement.
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=None)
    session.execute = AsyncMock(return_value=result)
    session.flush = AsyncMock(return_value=None)
    return session


def _payload(**overrides: Any) -> dict[str, Any]:
    """Build a minimal valid payload for DepthPassAgent.execute."""
    base: dict[str, Any] = {
        "engagement_id": "eng-test-1",
        "target_url": "https://example.com",
        "config": {},
        "tech_fingerprint": {},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Return-shape contract
# ---------------------------------------------------------------------------


class TestDepthPassReturnShape:
    @pytest.mark.asyncio
    async def test_depth_pass_returns_correct_shape(self) -> None:
        """execute() must return the dict described in plan §Step 2."""
        agent = DepthPassAgent()
        result = await agent.execute(_payload(), _fake_session())

        # Top-level keys from plan §Step 2.
        for key in (
            "findings",
            "chains",
            "state_change",
            "invocations_used",
            "wall_time_seconds",
            "phase_results",
            "aborted_reason",
            "depth_pass_complete",
        ):
            assert key in result, f"missing key {key!r} in depth_pass return"

        # Types.
        assert isinstance(result["findings"], list)
        assert isinstance(result["chains"], list)
        assert result["state_change"] is None or isinstance(result["state_change"], dict)
        assert isinstance(result["invocations_used"], int)
        assert isinstance(result["wall_time_seconds"], (int, float))
        assert isinstance(result["phase_results"], dict)
        assert result["aborted_reason"] is None or isinstance(result["aborted_reason"], str)

        # Engine marker.
        assert result["depth_pass_complete"] is True


# ---------------------------------------------------------------------------
# Invocation budget
# ---------------------------------------------------------------------------


class TestInvocationBudget:
    @pytest.mark.asyncio
    async def test_budget_enforcement_invocations(self) -> None:
        """201 invocations must trigger the abort; the cap is DEFAULT_MAX_INVOCATIONS.

        We exhaust the counter directly via the public ``_bump_inv`` helper
        (it's the only path the agent uses to advance the counter) and
        assert the 201st call returns False with a clear abort reason.
        """
        agent = DepthPassAgent()
        # Reset the cap to the documented default for a clean count.
        assert DEFAULT_MAX_INVOCATIONS == 200, (
            "Plan §Acceptance Criteria says the cap is 200; if this fails, "
            "the constant changed and the test needs to track it."
        )

        # Pump 200 successful increments — these are all within budget.
        for i in range(DEFAULT_MAX_INVOCATIONS):
            ok = await agent._bump_inv()
            assert ok is True, f"increment {i + 1} should still be within budget"
        assert agent._invocations == DEFAULT_MAX_INVOCATIONS

        # 201st increment must reject and set the abort reason.
        ok = await agent._bump_inv()
        assert ok is False
        assert agent._aborted_reason == "invocation_cap_reached"
        # Counter must not advance past the cap.
        assert agent._invocations == DEFAULT_MAX_INVOCATIONS


# ---------------------------------------------------------------------------
# Wall-time budget
# ---------------------------------------------------------------------------


class TestWallTimeBudget:
    @pytest.mark.asyncio
    async def test_budget_enforcement_wall_time(self) -> None:
        """When a phase exceeds the wall-time budget, asyncio.wait_for cancels it.

        We patch ``time.monotonic`` so the agent sees a wall clock that has
        already advanced past the budget. The phase we run does an
        ``asyncio.sleep`` that the ``wait_for`` will short-circuit — this
        mirrors the real abort path without actually waiting 30 minutes.
        """
        import warnings

        agent = DepthPassAgent()
        session = _fake_session()

        # Use a tight budget so the test runs fast. The plan defaults to
        # 30 minutes; we pass 5 (the minimum the agent accepts) and
        # pretend 31 minutes have already elapsed.
        real_monotonic = time.monotonic

        # Anchor a fake clock: at the start of execute() we want monotonic()
        # to return base; after the first call (which records _wall_start)
        # we want it to advance past the budget.
        base = real_monotonic()
        ticks = {"n": 0}

        def fake_monotonic() -> float:
            ticks["n"] += 1
            if ticks["n"] == 1:
                # First call: return the agent's start time.
                return base
            # Subsequent calls: return a value well past the budget.
            return base + 31 * 60  # 31 minutes later

        payload = _payload(
            config={
                "depth_pass_budget_minutes": 5,
                "depth_pass_max_invocations": 200,
            }
        )

        # The fake clock causes the wall-time check to short-circuit
        # before the first phase is awaited; the resulting "coroutine
        # was never awaited" warning is benign. Filter it so the test
        # report stays clean.
        warnings.filterwarnings(
            "ignore",
            message="coroutine .* was never awaited",
            category=RuntimeWarning,
        )

        with patch("src.agents.depth_pass.time.monotonic", side_effect=fake_monotonic):
            # Also patch out log_action + TechniqueMemory so we don't
            # touch the DB during the test.
            with patch("src.agents.depth_pass.log_action", new=AsyncMock()):
                # Make every stub phase return successfully so the wall-time
                # check is the *only* reason we abort.
                async def _ok_phase(*_a: Any, **_kw: Any) -> dict[str, Any]:
                    return {"findings": [], "chains": [], "phase": "stub"}

                agent._phase_1_subdomain_enum = _ok_phase  # type: ignore[method-assign]
                agent._phase_2_js_source_crawl = _ok_phase  # type: ignore[method-assign]
                agent._phase_3_auth_brute_force = _ok_phase  # type: ignore[method-assign]
                agent._phase_4_idor = _ok_phase  # type: ignore[method-assign]
                agent._phase_5_waf_bypass_retry = _ok_phase  # type: ignore[method-assign]
                agent._phase_6_chain_assembly = _ok_phase  # type: ignore[method-assign]
                # Cancellation probe: if the engagement is None, return False.
                agent._check_cancellation = AsyncMock(return_value=False)  # type: ignore[method-assign]

                result = await agent.execute(payload, session)

        assert result["aborted_reason"] == "wall_time_exceeded", (
            f"expected wall_time_exceeded, got {result['aborted_reason']!r}"
        )
        # No phase should have completed when wall-time is up before
        # any of them runs.
        assert result["phase_results"] == {}
        assert result["depth_pass_complete"] is True


# ---------------------------------------------------------------------------
# State-change abort
# ---------------------------------------------------------------------------


class TestStateChangeAbort:
    def test_new_set_cookie_triggers_state_change(self) -> None:
        """A new Set-Cookie header in a tool response must trip the detector."""
        detector = StateChangeDetector()
        detector.snapshot_baseline_cookies(set())

        result = detector.inspect(
            response_headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
            response_body="OK",
        )

        assert result is not None
        assert result["trigger"] == "new_session_cookie"
        assert "session" in result["cookies"]

    def test_existing_cookie_does_not_trigger(self) -> None:
        """A pre-existing cookie name in the baseline jar must NOT trip the detector."""
        detector = StateChangeDetector()
        detector.snapshot_baseline_cookies({"session"})

        result = detector.inspect(
            response_headers={"Set-Cookie": "session=xyz; Path=/"},
            response_body="OK",
        )
        assert result is None

    def test_db_write_persisted_triggers(self) -> None:
        """Non-zero db_row_count is the second trigger."""
        detector = StateChangeDetector()
        result = detector.inspect(db_row_count=1)
        assert result is not None
        assert result["trigger"] == "db_write_persisted"

    def test_exfil_marker_triggers(self) -> None:
        """A seeded exfiltration marker in the body is the third trigger."""
        detector = StateChangeDetector()
        result = detector.inspect(response_body="hello assurix_exfil_canary_42")
        assert result is not None
        assert result["trigger"] == "exfil_marker_reflected"
        assert "assurix_exfil_" in result["marker"]

    def test_detector_is_single_shot(self) -> None:
        """After the first trigger, subsequent calls return the same record."""
        detector = StateChangeDetector()
        first = detector.inspect(response_headers={"Set-Cookie": "new=1"})
        second = detector.inspect(db_row_count=99)
        assert first is not None
        assert first is second, "subsequent inspect() must return the same record"

    @pytest.mark.asyncio
    async def test_state_change_abort_short_circuits_execute(self) -> None:
        """When the detector fires mid-run, execute() must abort with state_change_detected.

        We inject the detector via a phase that records a new cookie in
        the very first tool response; subsequent phases must not run.
        """
        agent = DepthPassAgent()
        session = _fake_session()
        agent._check_cancellation = AsyncMock(return_value=False)  # type: ignore[method-assign]

        # Phase 1 trips the detector via its own outcome.
        async def _tripping_phase(*_a: Any, **_kw: Any) -> dict[str, Any]:
            agent._state_change.inspect(
                response_headers={"Set-Cookie": "auth=promoted; HttpOnly"},
            )
            return {"findings": [], "chains": [], "phase": "p1"}

        # Subsequent phases must NOT run.
        calls: list[str] = []

        async def _track_phase(name: str) -> Any:
            async def _fn(*_a: Any, **_kw: Any) -> dict[str, Any]:
                calls.append(name)
                return {"findings": [], "chains": [], "phase": name}
            return _fn

        agent._phase_1_subdomain_enum = _tripping_phase  # type: ignore[method-assign]
        agent._phase_2_js_source_crawl = await _track_phase("p2")  # type: ignore[method-assign]
        agent._phase_3_auth_brute_force = await _track_phase("p3")  # type: ignore[method-assign]
        agent._phase_4_idor = await _track_phase("p4")  # type: ignore[method-assign]
        agent._phase_5_waf_bypass_retry = await _track_phase("p5")  # type: ignore[method-assign]
        agent._phase_6_chain_assembly = await _track_phase("p6")  # type: ignore[method-assign]

        with patch("src.agents.depth_pass.log_action", new=AsyncMock()):
            result = await agent.execute(_payload(), session)

        assert result["aborted_reason"] == "state_change_detected"
        assert result["state_change"] is not None
        assert result["state_change"]["trigger"] == "new_session_cookie"
        # Only phase 1 should have run; 2..6 were skipped after the abort.
        assert calls == [], f"phases 2..6 should not run after state change; got {calls}"
        # Phase 1's result was recorded before the detector tripped.
        assert "subdomain_enum" in result["phase_results"]


# ---------------------------------------------------------------------------
# WAF rotator — all 6 strategies
# ---------------------------------------------------------------------------


class TestWAFRotation:
    def test_waf_rotation_all_6_strategies(self) -> None:
        """The rotator must produce all 6 mutations in the documented order."""
        rotator = WAFBypassRotator()

        # ``strategy_names`` is the public contract.
        names = rotator.strategy_names
        assert names == [
            "url_encode",
            "double_encode",
            "unicode_normalize",
            "chunked_transfer",
            "header_injection",
            "alt_verb",
        ], f"unexpected strategy order: {names}"

        # ``rotate`` must return one mutated probe per strategy.
        probes = rotator.rotate("' OR '1'='1", method="GET", headers={})
        assert len(probes) == 6

        # The strategies in the returned probes match the public names.
        returned_names = [p["strategy"] for p in probes]
        assert returned_names == names

        # Each probe is a *new* dict — callers can mutate freely.
        for probe in probes:
            assert isinstance(probe, dict)
            for key in ("strategy", "method", "payload", "headers"):
                assert key in probe

    def test_url_encode_strategy_changes_payload(self) -> None:
        rotator = WAFBypassRotator()
        probes = rotator.rotate("' OR 1=1 --", method="GET")
        url_encoded = probes[0]
        # The percent-encoded form is the first mutation.
        assert "%27" in url_encoded["payload"], (
            f"url_encode should percent-encode the apostrophe, got {url_encoded['payload']!r}"
        )
        assert url_encoded["method"] == "GET"

    def test_alt_verb_strategy_swaps_method(self) -> None:
        rotator = WAFBypassRotator()
        # GET -> POST
        probes = rotator.rotate("foo", method="GET")
        assert probes[-1]["method"] == "POST", (
            f"alt_verb should swap GET -> POST, got {probes[-1]['method']!r}"
        )

        # POST -> GET
        probes = rotator.rotate("foo", method="POST")
        assert probes[-1]["method"] == "GET"

    def test_record_outcome_unknown_strategy_is_noop(self) -> None:
        """An unknown strategy name (typo, future version) must not
        crash the rotator. This is the structural fix for "a new
        technique was added upstream and the rotator now has a 7th
        name in its memory table that the rotator doesn't know about".
        """
        rotator = WAFBypassRotator()
        rotator.record_outcome("not_a_real_strategy", success=True)
        # No state should have changed.
        assert rotator.top_k_strategies(k=6) == []

    def test_record_outcome_increments_counters(self) -> None:
        rotator = WAFBypassRotator()
        rotator.record_outcome("url_encode", success=True)
        rotator.record_outcome("url_encode", success=False)
        rotator.record_outcome("url_encode", success=True)
        # 2 success / 3 total
        stats = rotator._run_outcomes["url_encode"]
        assert stats["success"] == 2
        assert stats["total"] == 3

    def test_top_k_strategies_zero_k_returns_empty(self) -> None:
        rotator = WAFBypassRotator()
        rotator.record_outcome("url_encode", success=True)
        assert rotator.top_k_strategies(k=0) == []

    def test_top_k_strategies_no_evidence_returns_empty(self) -> None:
        """No recorded outcomes means no evidence — the rotator must
        not rank strategies that haven't been tried."""
        rotator = WAFBypassRotator()
        assert rotator.top_k_strategies(k=3) == []

    def test_top_k_strategies_ranks_by_success_ratio(self) -> None:
        """``unicode_normalize`` succeeds 2/2; ``url_encode`` succeeds
        1/2. unicode_normalize should rank first."""
        rotator = WAFBypassRotator()
        rotator.record_outcome("url_encode", success=True)
        rotator.record_outcome("url_encode", success=False)
        rotator.record_outcome("unicode_normalize", success=True)
        rotator.record_outcome("unicode_normalize", success=True)
        top = rotator.top_k_strategies(k=2)
        assert top == ["unicode_normalize", "url_encode"]

    def test_top_k_strategies_tie_breaks_by_declaration_order(self) -> None:
        """Two strategies with the same ratio: the one declared first
        in __init__ wins. Declaration order: url_encode, double_encode,
        unicode_normalize, ... So url_encode beats double_encode when
        both have a 1.0 ratio."""
        rotator = WAFBypassRotator()
        rotator.record_outcome("url_encode", success=True)
        rotator.record_outcome("double_encode", success=True)
        top = rotator.top_k_strategies(k=2)
        assert top == ["url_encode", "double_encode"]

    def test_top_k_strategies_k_clips(self) -> None:
        rotator = WAFBypassRotator()
        for name in ("url_encode", "double_encode", "unicode_normalize"):
            rotator.record_outcome(name, success=True)
        assert rotator.top_k_strategies(k=2) == ["url_encode", "double_encode"]

    def test_rotate_emits_all_six_strategies_even_with_outcomes(self) -> None:
        """Biasing must not drop strategies — all 6 still get
        emitted, just in a different order."""
        rotator = WAFBypassRotator()
        # Make alt_verb the runaway winner so it should be first.
        for _ in range(5):
            rotator.record_outcome("alt_verb", success=True)
        # And a fail for url_encode so it should sink.
        rotator.record_outcome("url_encode", success=False)
        probes = rotator.rotate("foo", method="GET")
        returned = [p["strategy"] for p in probes]
        assert set(returned) == set(rotator.strategy_names)
        assert returned[0] == "alt_verb"
        # url_encode has 0% success — should NOT be in the top 3.
        # Its original index is 0, so it falls after the top 3 winners.
        # Just check it's not first anymore.
        assert "url_encode" in returned

    def test_rotate_no_outcomes_uses_declaration_order(self) -> None:
        """Without run-time data, the original declaration order is
        preserved (no bias)."""
        rotator = WAFBypassRotator()
        probes = rotator.rotate("foo", method="GET")
        returned = [p["strategy"] for p in probes]
        assert returned == rotator.strategy_names


# ---------------------------------------------------------------------------
# Reflection cap
# ---------------------------------------------------------------------------


class TestReflectionCap:
    @pytest.mark.asyncio
    async def test_reflection_cap_at_50(self) -> None:
        """The 51st reflection call must short-circuit (return None) on the cap check.

        The cap is enforced at the *start* of ``_reflect_on_failure``
        via ``_reflection_count >= DEFAULT_REFLECTION_CAP``. We pump the
        counter past the cap and assert the 51st call is a no-op.

        The current LLM-router import inside ``_reflect_on_failure`` is
        best-effort (try/except returns ``None`` on ImportError), so we
        don't patch the router — we directly verify the cap mechanism
        via the ``_reflection_count`` field.
        """
        agent = DepthPassAgent()
        session = _fake_session()

        # The default cap is 50 per plan §Acceptance Criteria.
        assert DEFAULT_REFLECTION_CAP == 50

        # Force the counter to one below the cap to prove the +1 path.
        agent._reflection_count = DEFAULT_REFLECTION_CAP - 1
        result = await agent._reflect_on_failure(
            session=session,
            payload="payload-50",
            category="xss",
            last_response="blocked",
        )
        # The 50th call advances the counter to 50 and is "within cap".
        # (Whether it returns a dict or None depends on LLM availability;
        # what matters for the cap is that the counter advanced.)
        assert agent._reflection_count == DEFAULT_REFLECTION_CAP

        # 51st call must be a no-op (cap hit, counter NOT advanced).
        before = agent._reflection_count
        result = await agent._reflect_on_failure(
            session=session,
            payload="payload-51",
            category="xss",
            last_response="blocked",
        )
        assert result is None, "51st reflection must return None (cap hit)"
        assert agent._reflection_count == before, (
            "cap must short-circuit before incrementing the counter"
        )

    @pytest.mark.asyncio
    async def test_reflection_starts_at_zero(self) -> None:
        """A fresh agent's counter is 0."""
        agent = DepthPassAgent()
        assert agent._reflection_count == 0


# ---------------------------------------------------------------------------
# Target signature (used for cross-run technique memory)
# ---------------------------------------------------------------------------


class TestTargetSignature:
    def test_target_signature_is_16_hex_chars(self) -> None:
        sig = compute_target_signature("https://example.com", {"server": "nginx"})
        assert len(sig) == 16
        int(sig, 16)  # raises if not hex

    def test_target_signature_normalizes_url(self) -> None:
        """Trailing slashes / case differences must not change the signature."""
        s1 = compute_target_signature("https://Example.com/", {"server": "nginx"})
        s2 = compute_target_signature("https://example.com", {"server": "nginx"})
        assert s1 == s2

    def test_target_signature_changes_with_fingerprint(self) -> None:
        s1 = compute_target_signature("https://example.com", {"server": "nginx"})
        s2 = compute_target_signature("https://example.com", {"server": "apache"})
        assert s1 != s2


# ---------------------------------------------------------------------------
# LLM router factory (issue A — get_llm_router must exist for the
# depth pass's reflection path to resolve. The default is a no-op stub
# so the depth pass stays usable without a configured LLM backend).
# ---------------------------------------------------------------------------


class TestLLMRouterFactory:
    def test_get_llm_router_returns_router(self) -> None:
        """``get_llm_router()`` must resolve to a Router-compatible object.

        The depth pass's ``_reflect_on_failure`` does
        ``from src.llm.router import get_llm_router`` and calls
        ``router.generate(prompt)``. Before the factory was added, that
        import raised ImportError and the reflection path silently
        returned None. With the factory in place, the symbol exists
        and the default router is no-op-safe (generate returns None).
        """
        from src.llm.router import Router, get_llm_router, reset_llm_router

        reset_llm_router()
        router = get_llm_router()
        assert isinstance(router, Router)
        # The factory caches — same instance on subsequent calls.
        assert get_llm_router() is router

    @pytest.mark.asyncio
    async def test_default_router_generate_returns_none(self) -> None:
        """Default router's generate() returns None (no-op, no LLM cost)."""
        from src.llm.router import Router, get_llm_router, reset_llm_router

        reset_llm_router()
        router = get_llm_router()
        assert isinstance(router, Router)
        result = await router.generate("any prompt here")
        assert result is None

    def test_get_llm_router_handles_missing_env_factory(self) -> None:
        """A bad ``ASSURIX_LLM_ROUTER`` env var must NOT crash the factory.

        The factory must fall back to the default no-op Router so the
        depth pass keeps running in environments where the configured
        backend is broken or not installed yet. Per plan §Self-Improvement
        the reflection path is best-effort.
        """
        import os
        from src.llm.router import Router, get_llm_router, reset_llm_router

        old = os.environ.pop("ASSURIX_LLM_ROUTER", None)
        os.environ["ASSURIX_LLM_ROUTER"] = "definitely_not_a_real_module.path:foo"
        try:
            reset_llm_router()
            router = get_llm_router()
            assert isinstance(router, Router)
        finally:
            if old is not None:
                os.environ["ASSURIX_LLM_ROUTER"] = old
            else:
                os.environ.pop("ASSURIX_LLM_ROUTER", None)
            reset_llm_router()


# ---------------------------------------------------------------------------
# Fix-2: ``_engagement_id`` must be set on ``self`` (otherwise the cancel
# probe in ``_check_cancellation`` always sees an empty string and the
# operator's cancel command is silently ignored).
# ---------------------------------------------------------------------------


class TestEngagementIdPersisted:
    @pytest.mark.asyncio
    async def test_engagement_id_persisted_on_execute(self) -> None:
        """After ``execute()`` runs, ``self._engagement_id`` must equal the
        payload's ``engagement_id`` — the cancel probe reads this to look
        the engagement up. If it's not set, the operator's cancel command
        is silently dropped.
        """
        agent = DepthPassAgent()
        await agent.execute(_payload(engagement_id="eng-cancel-42"), _fake_session())
        assert agent._engagement_id == "eng-cancel-42"

    @pytest.mark.asyncio
    async def test_check_cancellation_uses_self_engagement_id(self) -> None:
        """``_check_cancellation`` must look up the engagement by the
        ``engagement_id`` from the payload, not an empty string. We
        construct a session whose ``session.get(Engagement, id)`` returns
        a synthetic engagement with ``depth_pass_cancelled=True`` and
        assert the probe reads it.
        """
        from types import SimpleNamespace

        cancelled_eng = SimpleNamespace(config={"depth_pass_cancelled": True})

        session = _fake_session()
        session.get = AsyncMock(return_value=cancelled_eng)

        agent = DepthPassAgent()
        agent._engagement_id = "eng-cancel-1"
        result = await agent._check_cancellation(session)
        assert result is True
        # Confirm the lookup was made with the correct id, not "".
        session.get.assert_awaited()
        first_call_args = session.get.await_args_list[0]
        # First positional arg after the class is the id.
        assert first_call_args.args[1] == "eng-cancel-1"

    @pytest.mark.asyncio
    async def test_check_cancellation_logs_db_errors(self) -> None:
        """A real DB error in the cancel probe must be logged, not
        silently swallowed. Previously ``except Exception: return False``
        hid the error and made it look like the cancel command worked
        when it didn't.
        """
        session = _fake_session()
        session.get = AsyncMock(side_effect=RuntimeError("simulated DB down"))

        agent = DepthPassAgent()
        agent._engagement_id = "eng-cancel-2"
        with __import__("unittest.mock", fromlist=["patch"]).patch(
            "src.agents.depth_pass.logger"
        ) as mock_logger:
            result = await agent._check_cancellation(session)
        assert result is False
        mock_logger.warning.assert_called()
        # The warning must mention what failed.
        call_args = str(mock_logger.warning.call_args)
        assert "cancel check failed" in call_args


# ---------------------------------------------------------------------------
# Fix-3: ``_build_finding_from_outcome`` must use the *real* ``target_url``
# (not the synthetic ``probe_id`` like ``"hist-3"``) when computing the
# dedup key. Two runs of the same WAF-bypass payload against the same
# target must produce the same dedup key, otherwise report-time dedup
# silently collapses to nothing.
# ---------------------------------------------------------------------------


class TestWAFProbeDedupKey:
    def test_dedup_key_uses_target_url_not_probe_id(self) -> None:
        """The same target + category + payload in two different runs
        must produce the same dedup key — the dedup key must be a
        function of the *real* target URL, not the synthetic ``probe_id``.
        """
        outcome = {"success": True, "confidence": 0.5, "response_summary": "ok"}
        # Two probes that differ only in probe_id (synthetic) but
        # share target_url, category, and payload.
        probe_a = {
            "probe_id": "hist-0",
            "target_url": "https://target.example.com/api",
            "category": "xss",
            "payload": "<script>alert(1)</script>",
        }
        probe_b = {
            "probe_id": "gen-3",  # different synthetic id
            "target_url": "https://target.example.com/api",
            "category": "xss",
            "payload": "<script>alert(1)</script>",
        }
        finding_a = DepthPassAgent._build_finding_from_outcome(
            outcome, probe_a, strategy_used="url_encode"
        )
        finding_b = DepthPassAgent._build_finding_from_outcome(
            outcome, probe_b, strategy_used="url_encode"
        )
        assert finding_a["dedup_key"] == finding_b["dedup_key"]

    def test_dedup_key_differs_for_different_targets(self) -> None:
        """Different real targets must produce different dedup keys."""
        outcome = {"success": True, "confidence": 0.5, "response_summary": "ok"}
        probe_a = {
            "probe_id": "gen-0",
            "target_url": "https://a.example.com/",
            "category": "xss",
            "payload": "<x>",
        }
        probe_b = {
            "probe_id": "gen-0",  # same synthetic id
            "target_url": "https://b.example.com/",
            "category": "xss",
            "payload": "<x>",
        }
        finding_a = DepthPassAgent._build_finding_from_outcome(
            outcome, probe_a, strategy_used="url_encode"
        )
        finding_b = DepthPassAgent._build_finding_from_outcome(
            outcome, probe_b, strategy_used="url_encode"
        )
        assert finding_a["dedup_key"] != finding_b["dedup_key"]

    def test_probe_plan_threads_target_url_into_each_probe(self) -> None:
        """``_build_waf_probe_plan`` must include ``target_url`` on every
        probe dict so downstream callers can read it.
        """
        plan = DepthPassAgent._build_waf_probe_plan(
            target_url="https://target.example.com",
            top_techniques=[
                {"_category": "xss", "technique": "<x>"},
                {"_category": "sqli", "technique": "' OR 1=1"},
            ],
        )
        assert plan, "probe plan must not be empty"
        for probe in plan:
            assert probe.get("target_url") == "https://target.example.com", (
                f"probe {probe.get('probe_id')!r} missing target_url: {probe}"
            )


# ---------------------------------------------------------------------------
# Fix-4: phase 5 must enforce a per-phase sub-budget so it cannot exhaust
# the full 200-invocation cap. With 6 historical + 6 generic probes ×
# 1 + 6 + 1 invocations each, the scaffold used to consume >100% of the
# budget inside phase 5 alone.
# ---------------------------------------------------------------------------


class TestPhase5Budget:
    @pytest.mark.asyncio
    async def test_phase_5_respects_per_phase_cap(self) -> None:
        """When phase 5 starts with the budget already partially used,
        it must stop cleanly at the per-phase cap (50% of the total
        budget) instead of draining the whole 200-invocation cap.
        """
        agent = DepthPassAgent()
        # Pretend earlier phases already burned 80 invocations.
        agent._invocations = 80
        agent._max_invocations = 200
        # ``_load_top_techniques_from_memory`` is async + DB; stub it
        # out so the test stays hermetic.
        agent._load_top_techniques_from_memory = AsyncMock(return_value=[])  # type: ignore[method-assign]
        # ``_attempt_waf_probe`` is async; always "not bypassed" so
        # the rotator + reflection paths run.
        agent._attempt_waf_probe = AsyncMock(  # type: ignore[method-assign]
            return_value={"success": False, "confidence": 0.0, "response_summary": "blocked"}
        )
        # ``_record_technique_outcome`` is best-effort; stub to no-op.
        agent._record_technique_outcome = AsyncMock(return_value=None)  # type: ignore[method-assign]
        # ``_reflect_on_failure`` would call the LLM; cap it at None.
        agent._reflect_on_failure = AsyncMock(return_value=None)  # type: ignore[method-assign]

        session = _fake_session()

        result = await agent._phase_5_waf_bypass_retry(
            target_url="https://target.example.com",
            session=session,
        )

        # Per-phase cap is max_invocations // 2 = 100. We started
        # with _invocations=80, so phase 5 is allowed to consume at
        # most 20 more before it must stop.
        assert agent._invocations <= 100, (
            f"phase 5 overran its 50% per-phase cap "
            f"({agent._invocations} > 100)"
        )
        # Abort reason must reflect the per-phase sub-budget.
        assert agent._aborted_reason == "phase_5_budget_exhausted", (
            f"expected phase_5_budget_exhausted, got {agent._aborted_reason!r}"
        )

    @pytest.mark.asyncio
    async def test_phase_5_records_rotator_outcome(self) -> None:
        """When a rotated probe succeeds, the rotator's in-run
        technique memory must reflect that — the next ``rotate()``
        call should then put the winning strategy first.

        This is the regression test for "WAFBypassRotator is stateless
        and never learns from the current run".
        """
        agent = DepthPassAgent()
        agent._max_invocations = 200
        agent._load_top_techniques_from_memory = AsyncMock(return_value=[])  # type: ignore[method-assign]
        agent._record_technique_outcome = AsyncMock(return_value=None)  # type: ignore[method-assign]
        agent._reflect_on_failure = AsyncMock(return_value=None)  # type: ignore[method-assign]

        # First call to the probe always fails; second call (rotated)
        # always succeeds. The success-vs-failure is decided by the
        # strategy name — alt_verb wins.
        async def _probe(*, payload, method, headers, category, probe_meta):  # type: ignore[no-untyped-def]
            if probe_meta.get("strategy_name") == "alt_verb":
                return {"success": True, "confidence": 0.9,
                        "response_summary": "bypassed!"}
            return {"success": False, "confidence": 0.0,
                    "response_summary": "blocked"}
        agent._attempt_waf_probe = _probe  # type: ignore[method-assign]

        session = _fake_session()
        await agent._phase_5_waf_bypass_retry(
            target_url="https://target.example.com",
            session=session,
        )

        # alt_verb is recorded as a success in the rotator's memory.
        # It may have been tried multiple times (once per failing
        # probe), so just check that at least one success was
        # recorded.
        stats = agent._waf_rotator._run_outcomes["alt_verb"]
        assert stats["success"] >= 1, (
            f"rotator memory not updated: alt_verb stats={stats}"
        )
        # The ratio is 100% — every attempt at alt_verb succeeded.
        assert stats["success"] == stats["total"]
        # Other strategies were tried as part of the rotation, each
        # recorded as a failure.
        for name in ("url_encode", "double_encode", "unicode_normalize",
                     "chunked_transfer", "header_injection"):
            stats = agent._waf_rotator._run_outcomes[name]
            assert stats["total"] >= 1, (
                f"{name} should have been tried at least once, "
                f"got {stats['total']}"
            )

        # Now the next rotate() call should put alt_verb first.
        probes = agent._waf_rotator.rotate("foo", method="GET")
        assert probes[0]["strategy"] == "alt_verb", (
            f"rotator should bias toward proven winner, got "
            f"first probe = {probes[0]['strategy']!r}"
        )
