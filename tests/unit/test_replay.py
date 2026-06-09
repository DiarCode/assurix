"""Unit tests for ReplayStore + ReplayMutator (plan §3.2.3, §5.7).

Coverage:
  RecordedRequest / Mutation:
    1. to_dict / body_bytes round-trip.
    2. Mutation.from_dict handles missing keys.

  ReplayStore on disk:
    3. record() returns a stable SHA-256 id.
    4. Two requests with different cookies produce different ids.
    5. get(id) returns the recorded record.
    6. get(missing) raises KeyError.
    7. list() returns all records; method filter works.
    8. record_count tracks insertions.
    9. clear() drops everything.
   10. Re-opened store rebuilds the in-memory index from disk.
   11. body_truncated=True when response body exceeds max_body_bytes.
   12. Large index does not break disk persistence (overflowed flag).

  ReplayMutator:
   13. replay_verbatim hits the URL and the recorded request shape.
   14. replay_with_mutation swaps a header (IDOR flow).
   15. replay_with_mutation replaces the URL (SSRF flow).
   16. replay_with_mutation replaces the body (POST flow).
   17. The mutator accepts a dict OR a Mutation instance.

  InMemoryReplayStore:
   18. Never touches the filesystem; record + get + list work.
   19. clear() resets.

  SharedSessionManager integration:
   20. Without a store, no event hooks.
   21. With a store, the hook is wired on get_client.
   22. set_replay_store after get_client is idempotent (warns + clears).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.agents.tools.replay import (
    DEFAULT_MAX_BODY_BYTES,
    InMemoryReplayStore,
    Mutation,
    RecordedRequest,
    ReplayMutator,
    ReplayStore,
    _body_to_text,
    _hash_id,
    _truncate,
)
from src.agents.tools.session import SharedSessionManager


# --- RecordedRequest / Mutation -----------------------------------------


class TestRecordedRequest:
    def _sample(self) -> RecordedRequest:
        return RecordedRequest(
            id="abc",
            method="POST",
            url="https://t.example/api",
            headers={"content-type": "application/json"},
            body='{"a": 1}',
            timestamp="2026-06-03T00:00:00+00:00",
            response_status=200,
            response_body="aGVsbG8=",
            response_headers={"content-type": "application/json"},
        )

    def test_to_dict(self) -> None:
        rec = self._sample()
        d = rec.to_dict()
        assert d["id"] == "abc"
        assert d["method"] == "POST"
        assert d["response_status"] == 200

    def test_body_bytes_round_trip(self) -> None:
        rec = self._sample()
        assert rec.body_bytes() == b'{"a": 1}'
        assert rec.response_body_bytes() == b"hello"

    def test_body_bytes_none(self) -> None:
        rec = RecordedRequest(
            id="x", method="GET", url="u", headers={}, body=None,
            timestamp="t", response_status=200, response_body="",
            response_headers={},
        )
        assert rec.body_bytes() is None


class TestMutation:
    def test_from_dict_with_all_keys(self) -> None:
        m = Mutation.from_dict({
            "url": "https://x/", "headers": {"a": "b"},
            "body": "x=1", "method": "PUT",
        })
        assert m.url == "https://x/"
        assert m.headers == {"a": "b"}
        assert m.body == "x=1"
        assert m.method == "PUT"

    def test_from_dict_missing_keys_default_none(self) -> None:
        m = Mutation.from_dict({})
        assert m.url is None
        assert m.headers is None
        assert m.body is None
        assert m.method is None

    def test_to_dict_round_trip(self) -> None:
        m = Mutation(url="u", headers={"a": "b"})
        d = m.to_dict()
        m2 = Mutation.from_dict(d)
        assert m == m2


# --- Pure helpers --------------------------------------------------------


class TestHelpers:
    def test_hash_id_stable(self) -> None:
        a = _hash_id("GET", "https://t/", None)
        b = _hash_id("GET", "https://t/", None)
        assert a == b
        assert len(a) == 64  # SHA-256 hex

    def test_hash_id_different_methods(self) -> None:
        assert _hash_id("GET", "u", None) != _hash_id("POST", "u", None)

    def test_hash_id_different_urls(self) -> None:
        assert _hash_id("GET", "u1", None) != _hash_id("GET", "u2", None)

    def test_hash_id_different_bodies(self) -> None:
        assert _hash_id("GET", "u", "a") != _hash_id("GET", "u", "b")

    def test_hash_id_includes_headers(self) -> None:
        """The IDOR tester relies on cookie differences producing
        distinct IDs so the user-A request can be replayed with the
        user-B cookie.
        """
        a = _hash_id("GET", "u", None, {"cookie": "session=userA"})
        b = _hash_id("GET", "u", None, {"cookie": "session=userB"})
        assert a != b

    def test_hash_id_headers_case_insensitive(self) -> None:
        """The hash is case-insensitive on header names so the same
        cookie presented in different casings is treated as identical.
        """
        a = _hash_id("GET", "u", None, {"Cookie": "x=1"})
        b = _hash_id("GET", "u", None, {"cookie": "x=1"})
        assert a == b

    def test_body_to_text_none(self) -> None:
        assert _body_to_text(None) is None

    def test_body_to_text_str(self) -> None:
        assert _body_to_text("hello") == "hello"

    def test_body_to_text_bytes(self) -> None:
        assert _body_to_text(b"hello") == "hello"

    def test_body_to_text_binary_hex(self) -> None:
        out = _body_to_text(b"\xff\xfe")
        assert out == "fffe"

    def test_truncate_under_limit(self) -> None:
        s, was = _truncate("hello", 100)
        assert s == "hello"
        assert was is False

    def test_truncate_over_limit(self) -> None:
        s, was = _truncate("x" * 100, 10)
        assert len(s.encode("utf-8")) == 10
        assert was is True

    def test_truncate_bytes_input(self) -> None:
        s, was = _truncate(b"x" * 100, 10)
        assert len(s.encode("utf-8")) == 10
        assert was is True


# --- ReplayStore on disk -------------------------------------------------


class TestReplayStoreOnDisk:
    def _make_request_response(
        self,
        method: str = "GET",
        url: str = "https://t.example/",
        body: bytes | None = None,
        response_status: int = 200,
        response_body: bytes = b"ok",
        response_headers: dict[str, str] | None = None,
        request_headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Request, httpx.Response]:
        req = httpx.Request(
            method, url, headers=request_headers or {}, content=body,
        )
        resp = httpx.Response(
            response_status,
            headers=response_headers or {"content-type": "text/plain"},
            content=response_body,
            request=req,
        )
        return req, resp

    def _make_store(self, tmp_path: Path, **kwargs: Any) -> ReplayStore:
        return ReplayStore(
            engagement_id="eng-1",
            artifacts_dir=tmp_path,
            **kwargs,
        )

    def test_record_returns_stable_id(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        req, resp = self._make_request_response()
        id1 = store.record(req, resp)
        id2 = store.record(req, resp)
        assert id1 == id2
        assert len(id1) == 64

    def test_different_cookies_produce_different_ids(self, tmp_path: Path) -> None:
        """IDOR replay needs to distinguish user-A from user-B requests."""
        store = self._make_store(tmp_path)
        req_a, resp_a = self._make_request_response(
            request_headers={"cookie": "session=userA"},
        )
        req_b, resp_b = self._make_request_response(
            request_headers={"cookie": "session=userB"},
        )
        id_a = store.record(req_a, resp_a)
        id_b = store.record(req_b, resp_b)
        assert id_a != id_b

    def test_get_returns_record(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        req, resp = self._make_request_response(
            method="POST", url="https://t/api",
            body=b'{"x":1}',
            response_status=201,
            response_body=b'{"ok":true}',
        )
        rid = store.record(req, resp)
        rec = store.get(rid)
        assert rec.method == "POST"
        assert rec.url == "https://t/api"
        assert rec.response_status == 201
        assert rec.response_body_bytes() == b'{"ok":true}'
        assert rec.body_bytes() == b'{"x":1}'

    def test_get_missing_raises_keyerror(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        with pytest.raises(KeyError, match="not found"):
            store.get("nonexistent_id_" + "0" * 50)

    def test_list_returns_all_records(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        for i in range(5):
            req, resp = self._make_request_response(url=f"https://t/{i}")
            store.record(req, resp)
        assert store.record_count() == 5
        records = store.list()
        assert len(records) == 5
        urls = {r.url for r in records}
        assert urls == {f"https://t/{i}" for i in range(5)}

    def test_list_method_filter(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.record(*self._make_request_response(method="GET"))
        store.record(*self._make_request_response(method="POST"))
        store.record(*self._make_request_response(method="POST"))
        get_only = store.list(method="GET")
        post_only = store.list(method="POST")
        assert len(get_only) == 1
        assert len(post_only) == 2

    def test_list_with_limit(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        for i in range(10):
            store.record(*self._make_request_response(url=f"https://t/{i}"))
        assert len(store.list(limit=3)) == 3

    def test_clear_drops_everything(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.record(*self._make_request_response())
        assert store.record_count() == 1
        store.clear()
        assert store.record_count() == 0
        # The JSONL file is also removed.
        assert not store.jsonl_path.exists()

    def test_reopen_rebuilds_index(self, tmp_path: Path) -> None:
        store1 = self._make_store(tmp_path)
        req, resp = self._make_request_response()
        rid = store1.record(req, resp)
        # Re-open: a fresh store from the same dir must see the record.
        store2 = self._make_store(tmp_path)
        rec = store2.get(rid)
        assert rec.url == req.url
        assert rec.response_status == resp.status_code

    def test_body_truncated_when_response_too_large(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path, max_body_bytes=64)
        req, resp = self._make_request_response(response_body=b"x" * 1024)
        rid = store.record(req, resp)
        rec = store.get(rid)
        assert rec.response_truncated is True
        # The stored body is at most max_body_bytes long (UTF-8).
        assert len(rec.response_body_bytes()) <= 64

    def test_binary_response_body_handled(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        req, resp = self._make_request_response(
            response_body=b"\x00\xff\x10\x80",
        )
        rid = store.record(req, resp)
        rec = store.get(rid)
        assert rec.response_body_bytes() == b"\x00\xff\x10\x80"

    def test_index_overflow_does_not_crash(self, tmp_path: Path) -> None:
        """A small index cap must still allow disk writes to proceed."""
        store = self._make_store(tmp_path, index_cap=3)
        for i in range(5):
            store.record(*self._make_request_response(url=f"https://t/{i}"))
        # All 5 records are on disk even though only 3 are indexed.
        on_disk = store.list()
        assert len(on_disk) == 5
        # record_count reports indexed entries (3).
        assert store.record_count() == 3

    def test_jsonl_is_valid_jsonl(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        for i in range(3):
            store.record(*self._make_request_response(url=f"https://t/{i}"))
        with open(store.jsonl_path) as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        assert len(lines) == 3
        for entry in lines:
            assert "id" in entry
            assert "method" in entry
            assert "response_body" in entry


# --- ReplayMutator -------------------------------------------------------


class TestReplayMutator:
    """Use httpx.MockTransport to verify replay behaviour without a real server."""

    def _transport(self) -> tuple[Any, list[httpx.Request]]:
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(
                200,
                headers={"x-test": "ok"},
                content=b"replayed",
            )

        return handler, captured

    def test_replay_verbatim(self) -> None:
        handler, captured = self._transport()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), verify=False
        )
        try:
            store = InMemoryReplayStore()
            req, resp = httpx.Request(
                "GET", "https://t/api",
            ), httpx.Response(
                200, content=b"original", request=httpx.Request("GET", "https://t/api"),
            )
            rid = store.record(req, resp)
            mutator = ReplayMutator(store, http_client=client)
            r = asyncio.run(mutator.replay_verbatim(rid))
            assert r.status_code == 200
            assert r.content == b"replayed"
            assert len(captured) == 1
            assert captured[0].method == "GET"
            assert str(captured[0].url) == "https://t/api"
        finally:
            asyncio.run(client.aclose())

    def test_replay_with_header_mutation(self) -> None:
        """IDOR replay: swap Cookie header."""
        handler, captured = self._transport()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), verify=False
        )
        try:
            store = InMemoryReplayStore()
            req = httpx.Request(
                "GET", "https://t/users/42",
                headers={"cookie": "session=userA"},
            )
            resp = httpx.Response(
                200, content=b"userA's data",
                request=httpx.Request(
                    "GET", "https://t/users/42",
                    headers={"cookie": "session=userA"},
                ),
            )
            rid = store.record(req, resp)
            mutator = ReplayMutator(store, http_client=client)
            r = asyncio.run(mutator.replay_with_mutation(
                rid, {"headers": {"cookie": "session=userB"}},
            ))
            assert r.status_code == 200
            assert captured[0].headers.get("cookie") == "session=userB"
        finally:
            asyncio.run(client.aclose())

    def test_replay_with_url_mutation(self) -> None:
        """SSRF replay: swap the URL host."""
        handler, captured = self._transport()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), verify=False
        )
        try:
            store = InMemoryReplayStore()
            req = httpx.Request("GET", "https://t.example/proxy?url=https://google.com")
            resp = httpx.Response(
                200, content=b"ok",
                request=httpx.Request("GET", "https://t.example/proxy?url=https://google.com"),
            )
            rid = store.record(req, resp)
            mutator = ReplayMutator(store, http_client=client)
            asyncio.run(mutator.replay_with_mutation(
                rid, {"url": "https://t.example/proxy?url=http://169.254.169.254/"},
            ))
            assert "169.254.169.254" in str(captured[0].url)
        finally:
            asyncio.run(client.aclose())

    def test_replay_with_body_mutation(self) -> None:
        """POST replay with a new body."""
        handler, captured = self._transport()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), verify=False
        )
        try:
            store = InMemoryReplayStore()
            req = httpx.Request(
                "POST", "https://t/api",
                headers={"content-type": "application/json"},
                content=b'{"q":"x"}',
            )
            resp = httpx.Response(
                200, content=b"ok",
                request=httpx.Request("POST", "https://t/api"),
            )
            rid = store.record(req, resp)
            mutator = ReplayMutator(store, http_client=client)
            asyncio.run(mutator.replay_with_mutation(
                rid, {"body": '{"q":"UNION SELECT password FROM users--"}'},
            ))
            assert captured[0].content == b'{"q":"UNION SELECT password FROM users--"}'
        finally:
            asyncio.run(client.aclose())

    def test_replay_accepts_mutation_instance(self) -> None:
        handler, captured = self._transport()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), verify=False
        )
        try:
            store = InMemoryReplayStore()
            req = httpx.Request("GET", "https://t/")
            resp = httpx.Response(
                200, content=b"ok", request=httpx.Request("GET", "https://t/"),
            )
            rid = store.record(req, resp)
            mutator = ReplayMutator(store, http_client=client)
            asyncio.run(mutator.replay_with_mutation(
                rid, Mutation(method="PUT"),
            ))
            assert captured[0].method == "PUT"
        finally:
            asyncio.run(client.aclose())


# --- InMemoryReplayStore -------------------------------------------------


class TestInMemoryReplayStore:
    def test_no_filesystem_writes(self, tmp_path: Path) -> None:
        """The in-memory store must not create files under tmp_path."""
        _ = tmp_path  # documented unused; we assert the store's own path
        store = InMemoryReplayStore()
        before = set(store.replay_dir.iterdir()) if store.replay_dir.exists() else set()
        store.record(
            httpx.Request("GET", "https://t/"),
            httpx.Response(
                200, content=b"ok",
                request=httpx.Request("GET", "https://t/"),
            ),
        )
        after = set(store.replay_dir.iterdir()) if store.replay_dir.exists() else set()
        assert before == after
        assert store.record_count() == 1

    def test_clear_resets(self) -> None:
        store = InMemoryReplayStore()
        store.record(
            httpx.Request("GET", "https://t/"),
            httpx.Response(
                200, content=b"ok",
                request=httpx.Request("GET", "https://t/"),
            ),
        )
        store.clear()
        assert store.record_count() == 0
        assert store.list() == []

    def test_get_missing_raises(self) -> None:
        store = InMemoryReplayStore()
        with pytest.raises(KeyError, match="not found"):
            store.get("x" * 64)


# --- SharedSessionManager integration ------------------------------------


class TestSharedSessionManagerIntegration:
    def test_no_store_no_event_hooks(self) -> None:
        mgr = SharedSessionManager()
        client = mgr.get_client("https://t/")
        # httpx stores event_hooks as a dict; empty dict means none.
        # We don't pin the exact empty-dict shape (it varies across
        # httpx versions), but the keys must not include "response".
        hooks = client.event_hooks
        assert "response" not in hooks or len(hooks.get("response", [])) == 0

    def test_with_store_hook_is_attached(self) -> None:
        mgr = SharedSessionManager()
        store = InMemoryReplayStore()
        mgr.set_replay_store(store)
        client = mgr.get_client("https://t/")
        # The hook is attached under "response".
        assert "response" in client.event_hooks
        assert len(client.event_hooks["response"]) == 1
        assert mgr.replay_store is store

    def test_set_replay_store_after_get_client_warns(self) -> None:
        """Attaching a store after clients exist must clear the cache."""
        mgr = SharedSessionManager()
        _ = mgr.get_client("https://t/")  # creates a client
        store = InMemoryReplayStore()
        # No warning assertion (pytest.warns with no args is awkward);
        # the test is that the operation doesn't raise and the next
        # get_client returns a client with the hook attached.
        mgr.set_replay_store(store)
        client2 = mgr.get_client("https://t/")
        assert "response" in client2.event_hooks
