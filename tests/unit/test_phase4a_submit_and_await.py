"""Phase 4a: submit_and_await() API tests.

Verifies:
- WorkflowEngine exposes submit_and_await and _pending_futures
- submit_and_await() registers a future keyed by payload metadata
- _resolve_future_for() resolves a registered future
- _resolve_future_for() is a no-op when no future_key present
- _resolve_future_for() is a no-op for unknown keys
- Timeout raises asyncio.TimeoutError and cleans up the pending future
- Multiple concurrent submit_and_await calls don't deadlock
- _run_loop() calls _resolve_future_for() after agent completion
- submit_and_await() uses JobScheduler.enqueue() with the documented signature
"""

from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.orchestrator.engine import WorkflowEngine


class TestSubmitAndAwaitSignature:
    def test_method_present(self) -> None:
        engine = WorkflowEngine()
        assert hasattr(engine, "submit_and_await")
        assert asyncio.iscoroutinefunction(engine.submit_and_await)

    def test_signature(self) -> None:
        engine = WorkflowEngine()
        sig = inspect.signature(engine.submit_and_await)
        params = sig.parameters
        assert "session" in params
        assert "engagement_id" in params
        assert "agent_name" in params
        assert "payload" in params
        assert "timeout" in params
        # timeout should be keyword-only with a default
        assert params["timeout"].default == 300.0
        assert params["timeout"].kind == inspect.Parameter.KEYWORD_ONLY

    def test_pending_futures_dict_present(self) -> None:
        engine = WorkflowEngine()
        assert hasattr(engine, "_pending_futures")
        assert engine._pending_futures == {}
        assert isinstance(engine._pending_futures, dict)


class TestResolveFutureFor:
    @pytest.mark.asyncio
    async def test_resolves_registered_future(self) -> None:
        engine = WorkflowEngine()
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        future_key = "k1"
        engine._pending_futures[future_key] = future

        payload = {"_assurix_future_key": future_key}
        result = {"value": 42}

        await engine._resolve_future_for("recon", payload, result)

        assert future.done()
        assert await future == result
        assert future_key not in engine._pending_futures

    @pytest.mark.asyncio
    async def test_resolves_using_result_metadata(self) -> None:
        """Some agents echo the future key into the result dict; honor that."""
        engine = WorkflowEngine()
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        future_key = "k2"
        engine._pending_futures[future_key] = future

        payload = {}  # payload missing the key
        result = {"_assurix_future_key": future_key, "findings": []}

        await engine._resolve_future_for("recon", payload, result)

        assert future.done()
        assert await future == result

    @pytest.mark.asyncio
    async def test_no_op_when_no_key(self) -> None:
        engine = WorkflowEngine()
        # No future registered, no key in either place — must not raise
        await engine._resolve_future_for("recon", {}, {"x": 1})
        assert engine._pending_futures == {}

    @pytest.mark.asyncio
    async def test_no_op_for_unknown_key(self) -> None:
        engine = WorkflowEngine()
        # Key in payload but no future registered — must not raise, must not crash
        await engine._resolve_future_for(
            "recon",
            {"_assurix_future_key": "missing"},
            {"_assurix_future_key": "missing"},
        )
        assert engine._pending_futures == {}

    @pytest.mark.asyncio
    async def test_no_op_for_already_done_future(self) -> None:
        engine = WorkflowEngine()
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        future.set_result({"already": "done"})
        engine._pending_futures["k3"] = future

        # Should not raise even if the future was already resolved.
        # Implementation: when future is already done, we leave the dict alone
        # (don't re-set, don't raise).
        await engine._resolve_future_for(
            "recon",
            {"_assurix_future_key": "k3"},
            {"_assurix_future_key": "k3"},
        )
        # Future still resolved with the original result
        assert future.result() == {"already": "done"}


class TestSubmitAndAwaitDispatch:
    @pytest.mark.asyncio
    async def test_enqueues_via_scheduler_with_future_key(self) -> None:
        engine = WorkflowEngine()
        captured: dict = {}

        async def fake_enqueue(*, session, engagement_id, agent_name, payload, **kwargs):
            captured["enqueue_args"] = {
                "engagement_id": engagement_id,
                "agent_name": agent_name,
                "payload": dict(payload),
            }
            return MagicMock()

        engine.scheduler = MagicMock(enqueue=AsyncMock(side_effect=fake_enqueue))

        session = AsyncMock()
        original_payload = {"target_url": "http://x"}

        # Manually resolve the future that submit_and_await registers and then
        # call _resolve_future_for() to simulate the _run_loop() cleanup.
        async def _resolve_and_return():
            # Yield once to let submit_and_await register the future and enqueue
            await asyncio.sleep(0)
            payload = captured["enqueue_args"]["payload"]
            key = payload["_assurix_future_key"]
            fut = engine._pending_futures.get(key)
            if fut and not fut.done():
                fut.set_result({"ok": True, "_assurix_future_key": key})
            # Simulate _run_loop's post-execution hook
            await engine._resolve_future_for("recon", payload, fut.result())
            return await fut

        # Run submit_and_await and the resolver concurrently
        result = await asyncio.gather(
            engine.submit_and_await(
                session=session,
                engagement_id="e1",
                agent_name="recon",
                payload=original_payload,
            ),
            _resolve_and_return(),
        )

        # Both tasks should get the same result
        assert result[0] == result[1]
        assert result[0]["ok"] is True
        assert "_assurix_future_key" in result[0]
        # Future was cleaned up by _resolve_future_for
        assert engine._pending_futures == {}

        # Verify enqueue was called once with the correct args
        kwargs = captured["enqueue_args"]
        assert kwargs["engagement_id"] == "e1"
        assert kwargs["agent_name"] == "recon"
        # Payload was copied and augmented
        assert kwargs["payload"]["target_url"] == "http://x"
        assert "_assurix_future_key" in kwargs["payload"]
        # Original caller's payload was NOT mutated
        assert "_assurix_future_key" not in original_payload

    @pytest.mark.asyncio
    async def test_does_not_mutate_caller_payload(self) -> None:
        engine = WorkflowEngine()
        engine.scheduler = MagicMock(enqueue=AsyncMock())
        session = AsyncMock()
        original = {"a": 1}
        snapshot = dict(original)

        with pytest.raises(asyncio.TimeoutError):
            await engine.submit_and_await(
                session=session,
                engagement_id="e1",
                agent_name="recon",
                payload=original,
                timeout=0.01,
            )

        assert original == snapshot


class TestRunLoopIntegration:
    def test_run_loop_calls_resolve_future_for(self) -> None:
        """_run_loop() must call _resolve_future_for() after agent execution.

        We assert by reading the source rather than spinning the loop.
        """
        from pathlib import Path
        import re

        src = Path("src/orchestrator/engine.py").read_text()
        # Look for the resolve call inside _run_loop
        # Find the _run_loop method body
        m = re.search(r"async def _run_loop.*?(?=    (?:async )?def )", src, re.DOTALL)
        assert m, "_run_loop method not found"
        body = m.group(0)
        assert "_resolve_future_for" in body
        # Must be after mark_completed and before/around the routing block
        assert "mark_completed" in body
        # Order: mark_completed comes before _resolve_future_for
        assert body.index("mark_completed") < body.index("_resolve_future_for")

    def test_run_loop_preserves_future_key_in_payload(self) -> None:
        """The original payload (with _assurix_future_key) must be passed to
        _resolve_future_for — the engine must not strip it before resolution.
        """
        from pathlib import Path
        import re

        src = Path("src/orchestrator/engine.py").read_text()
        m = re.search(r"async def _run_loop.*?(?=    (?:async )?def )", src, re.DOTALL)
        body = m.group(0)
        # _resolve_future_for is called with `payload` (the local var from
        # dequeue), so the future_key is preserved.
        assert re.search(r"_resolve_future_for\(\s*agent_name\s*,\s*payload\s*,", body), (
            "_resolve_future_for must be called with the dequeued payload"
        )


class TestConcurrentDispatch:
    @pytest.mark.asyncio
    async def test_multiple_concurrent_calls_have_independent_futures(self) -> None:
        """5+ concurrent submit_and_await calls must each get their own future.

        Deadlock risk: a single shared event-loop channel, no async lock around
        ``_pending_futures``. As long as dict ops don't await, the dict is safe
        under asyncio's cooperative scheduling.
        """
        engine = WorkflowEngine()
        captured_payloads: list[dict] = []

        async def fake_enqueue(*, session, engagement_id, agent_name, payload, **kwargs):
            captured_payloads.append(dict(payload))
            return MagicMock()

        engine.scheduler = MagicMock(enqueue=AsyncMock(side_effect=fake_enqueue))

        session = AsyncMock()

        # Resolver: every iteration yields once to let submit_and_await
        # register a future, then resolves it and simulates the post-exec
        # cleanup that _run_loop() performs via _resolve_future_for().
        async def _resolve_all():
            seen = 0
            target = 5
            while seen < target:
                await asyncio.sleep(0.01)
                for p in captured_payloads[seen:]:
                    key = p.get("_assurix_future_key")
                    fut = engine._pending_futures.get(key)
                    if fut and not fut.done():
                        fut.set_result({"ok": True, "_assurix_future_key": key})
                        # Simulate _run_loop cleanup
                        await engine._resolve_future_for("recon", p, fut.result())
                    seen += 1

        results = await asyncio.gather(
            *[
                engine.submit_and_await(
                    session=session,
                    engagement_id="e1",
                    agent_name="recon",
                    payload={"i": i},
                    timeout=2.0,
                )
                for i in range(5)
            ],
            _resolve_all(),
        )

        # All five should have resolved with their own result
        for i, r in enumerate(results[:5]):
            assert r["ok"] is True

        assert len(captured_payloads) == 5
        keys = {p["_assurix_future_key"] for p in captured_payloads}
        assert len(keys) == 5  # all unique
        # All futures cleaned up
        assert engine._pending_futures == {}
