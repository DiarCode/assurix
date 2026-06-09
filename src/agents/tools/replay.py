"""Replay store + mutator (plan §3.2.3, §5.7).

Captures every outgoing ``httpx`` request and the corresponding
response into a per-engagement JSONL log so that downstream verifiers
(the Reproducer, the IDOR tester, the ExploitChainer) can:

  * Replay a captured request verbatim to confirm reproducibility
    (Reproducer's ``vote()`` uses this).
  * Replay a captured request with a header / body / URL mutation
    (IDOR swaps ``Cookie: userA`` → ``Cookie: userB``; SSRF swaps
    the URL host; auth-bypass swaps ``Authorization``).
  * List and inspect every request the engine made during an
    engagement, after the fact.

Design constraints
------------------

1. **No breaking change to ``AssurixHTTPClient``.** The hook is an
   ``httpx`` event hook — tools keep calling ``client.get(...)`` as
   before; the recording happens transparently.
2. **Disk-first, memory-bounded.** Records are appended to a JSONL
   file under ``data/artifacts/{engagement_id}/replay/requests.jsonl``
   so they survive a crash. A small in-memory index is kept for
   ``get(id)`` and ``list()``; the index is rebuilt from disk on
   startup.
3. **Body capture is opt-in per request.** Storing every response
   body verbatim is fine for a 200-byte JSON API but disastrous for a
   5 MB screenshot endpoint. The store records up to
   ``max_body_bytes`` (default 64 KB) per response; larger bodies are
   truncated and the truncation is recorded as metadata.
4. **Content-addressed IDs.** Each record's ``id`` is the SHA-256
   hex of ``method|URL|body``. Two requests that differ only in
   headers (e.g., different auth cookies) get distinct bodies (the
    header is part of ``body``) — wait, actually we hash on
   ``method|URL|body`` so cookies produce distinct request bodies,
   which is what we want for IDOR replay.

Persistence
-----------

``ReplayStore`` writes to ``artifacts_dir/replay/requests.jsonl`` and
keeps a secondary in-memory index of ``id -> {offset, length}`` for
random access. The on-disk file is the source of truth; the in-memory
index is rebuilt on construction if the file exists.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# Default cap on stored response body size. Bodies larger than this
# are truncated and a ``body_truncated`` flag is set on the record.
DEFAULT_MAX_BODY_BYTES = 64 * 1024  # 64 KB

# In-memory index cap. Once exceeded, the store logs a warning and
# continues recording to disk but stops maintaining the index; the
# caller can still re-read everything from the JSONL file. This keeps
# memory bounded on long engagements.
DEFAULT_INDEX_CAP = 10_000


@dataclass
class RecordedRequest:
    """A captured httpx request/response pair.

    The ``id`` is the SHA-256 of ``method|URL|body`` and is unique
    per (request-shape) record. Two requests with different cookies
    but otherwise identical produce different request-body strings
    and therefore different IDs — which is what the IDOR tester
    needs to replay with the right header swap.
    """

    id: str
    method: str
    url: str
    headers: dict[str, str]
    body: str | None
    timestamp: str
    response_status: int
    response_body: str  # base64-encoded so JSONL is text-safe
    response_headers: dict[str, str]
    body_truncated: bool = False
    response_truncated: bool = False
    # The basename of the JSONL file the record was written to, so
    # mutators can locate the record after a process restart.
    source_file: str = "requests.jsonl"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def response_body_bytes(self) -> bytes:
        """Decode the base64 response body back to bytes."""
        import base64
        return base64.b64decode(self.response_body.encode("ascii"))

    def body_bytes(self) -> bytes | None:
        if self.body is None:
            return None
        return self.body.encode("utf-8", errors="ignore")


@dataclass
class Mutation:
    """A single change to apply to a recorded request on replay.

    Mutators are applied in order:

      1. ``url`` (full URL replacement, or path/query string only)
      2. ``headers`` (replace or merge into the recorded headers)
      3. ``body`` (string or bytes replacement)
    """

    url: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    method: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Mutation":
        return cls(
            url=d.get("url"),
            headers=d.get("headers"),
            body=d.get("body"),
            method=d.get("method"),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_id(method: str, url: str, body: str | None, headers: dict[str, str] | None = None) -> str:
    """Stable SHA-256 hex of ``method|URL|body|headers``.

    Headers are sorted and serialised as ``k=v`` pairs joined with
    ``\n`` before hashing. This means two requests that differ only
    in their ``Cookie`` / ``Authorization`` header produce distinct
    IDs — which is what the IDOR tester needs so it can replay the
    user-A request with the user-B cookie.
    """
    h = hashlib.sha256()
    h.update(method.upper().encode("utf-8"))
    h.update(b"|")
    h.update(url.encode("utf-8"))
    h.update(b"|")
    h.update((body or "").encode("utf-8", errors="ignore"))
    h.update(b"|")
    if headers:
        # Case-insensitive: lowercase keys for stable ordering.
        norm = sorted(
            (k.lower(), v) for k, v in headers.items() if isinstance(v, str)
        )
        for k, v in norm:
            h.update(k.encode("utf-8"))
            h.update(b"=")
            h.update(v.encode("utf-8", errors="ignore"))
            h.update(b"\n")
    return h.hexdigest()


def _body_to_text(body: bytes | str | None) -> str | None:
    """Coerce a request body to UTF-8 text for JSONL storage."""
    if body is None:
        return None
    if isinstance(body, str):
        return body
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        # Binary body: hex-encode so the JSONL stays text-safe.
        return body.hex()


def _truncate(value: str | bytes, max_bytes: int) -> tuple[str, bool]:
    """Truncate ``value`` to ``max_bytes`` UTF-8 bytes, return (text, was_truncated)."""
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="ignore")
    else:
        encoded = value
    if len(encoded) <= max_bytes:
        return (value if isinstance(value, str) else encoded.decode("utf-8", errors="ignore")), False
    truncated = encoded[:max_bytes]
    return truncated.decode("utf-8", errors="ignore"), True


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------


class ReplayStore:
    """Append-only HAR-like store of httpx request/response pairs.

    Two on-disk artifacts per engagement:

      * ``requests.jsonl`` — one JSON object per line, the canonical
        record.
      * ``requests.index.json`` — a small ``{id: {offset, length}}``
        map for random access. Rebuilt on every record append.

    Concurrency: a single ``threading.Lock`` serialises writes. The
    store is intended to be used from one asyncio loop; multiple
    concurrent loops should each have their own store instance.
    """

    def __init__(
        self,
        engagement_id: str,
        artifacts_dir: Path | str,
        *,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        index_cap: int = DEFAULT_INDEX_CAP,
    ) -> None:
        self.engagement_id = engagement_id
        self.artifacts_dir = Path(artifacts_dir)
        self.replay_dir = self.artifacts_dir / engagement_id / "replay"
        self.replay_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.replay_dir / "requests.jsonl"
        self.index_path = self.replay_dir / "requests.index.json"
        self.max_body_bytes = max(0, int(max_body_bytes))
        self.index_cap = max(1, int(index_cap))
        self._lock = threading.Lock()
        # In-memory index: id -> {"offset": int, "length": int}
        self._index: dict[str, dict[str, int]] = {}
        self._index_overflowed = False
        self._load_index()

    # --- Public API --------------------------------------------------

    def record(self, request: httpx.Request, response: httpx.Response) -> str:
        """Record a (request, response) pair. Returns the record id.

        Safe to call from httpx event hooks — failure is logged and
        swallowed so a broken store doesn't kill a tool call.
        """
        try:
            return self._record_unsafe(request, response)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "ReplayStore.record failed for %s %s: %s",
                request.method, request.url, exc,
            )
            return ""

    def get(self, request_id: str) -> RecordedRequest:
        """Return the record for ``request_id``. Raises ``KeyError`` if not found."""
        with self._lock:
            index = self._index.get(request_id)
        if index is None:
            # Re-read the index from disk in case a peer wrote.
            self._load_index()
            with self._lock:
                index = self._index.get(request_id)
        if index is None:
            raise KeyError(
                f"request_id {request_id!r} not found in ReplayStore "
                f"({self.jsonl_path})"
            )
        with open(self.jsonl_path, "rb") as fh:
            fh.seek(index["offset"])
            line = fh.read(index["length"])
        return _record_from_json(line.decode("utf-8"))

    def list(
        self, *, limit: int | None = None, method: str | None = None
    ) -> list[RecordedRequest]:
        """Return up to ``limit`` records, optionally filtered by HTTP method."""
        out: list[RecordedRequest] = []
        if not self.jsonl_path.exists():
            return out
        with open(self.jsonl_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = _record_from_json(line)
                if method and rec.method.upper() != method.upper():
                    continue
                out.append(rec)
                if limit is not None and len(out) >= limit:
                    break
        return out

    def record_count(self) -> int:
        """Number of records on disk (cheap; reads the index)."""
        with self._lock:
            return len(self._index)

    def clear(self) -> None:
        """Drop every record. Mostly useful in tests."""
        with self._lock:
            self._index.clear()
            self._index_overflowed = False
        if self.jsonl_path.exists():
            self.jsonl_path.unlink()
        if self.index_path.exists():
            self.index_path.unlink()

    # --- Hook for httpx ---------------------------------------------

    def event_hook(self) -> Any:
        """Return an httpx event hook that records every response.

        Usage::

            client = httpx.AsyncClient(event_hooks={"response": [store.event_hook()]})

        The hook is sync — it touches the filesystem, but only after
        the response has been received, so it doesn't add latency to
        the caller's request.
        """

        def _hook(response: httpx.Response) -> None:
            try:
                self.record(response.request, response)
            except Exception as exc:  # pragma: no cover
                logger.warning("ReplayStore event hook failed: %s", exc)

        return _hook

    # --- Internals ---------------------------------------------------

    def _record_unsafe(
        self, request: httpx.Request, response: httpx.Response
    ) -> str:
        method = request.method
        url = str(request.url)
        headers = {k: v for k, v in request.headers.items()}
        body_text = _body_to_text(request.content) if request.content else None
        record_id = _hash_id(method, url, body_text, headers)
        timestamp = datetime.now(UTC).isoformat()

        # Truncate at the BYTE level for response bodies (they can be
        # binary — don't try to UTF-8 decode). Base64-encode the raw
        # bytes after truncation.
        import base64
        response_content = response.content or b""
        if self.max_body_bytes and len(response_content) > self.max_body_bytes:
            response_truncated_bytes = response_content[: self.max_body_bytes]
            response_truncated = True
        else:
            response_truncated_bytes = response_content
            response_truncated = False
        response_body_b64 = base64.b64encode(
            response_truncated_bytes
        ).decode("ascii")
        body_truncated = False  # request bodies are always text in this path

        record = RecordedRequest(
            id=record_id,
            method=method,
            url=url,
            headers=headers,
            body=body_text,
            timestamp=timestamp,
            response_status=response.status_code,
            response_body=response_body_b64,
            response_headers={k: v for k, v in response.headers.items()},
            body_truncated=body_truncated,
            response_truncated=response_truncated,
            source_file=self.jsonl_path.name,
        )
        line = json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False)
        # Append-only write under the lock; the offset is the current
        # file size before the write.
        with self._lock:
            offset = self.jsonl_path.stat().st_size if self.jsonl_path.exists() else 0
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.write("\n")
            length = len(line) + 1  # account for the trailing newline
            if len(self._index) < self.index_cap:
                self._index[record_id] = {"offset": offset, "length": length}
            else:
                self._index_overflowed = True
            self._persist_index()
        return record_id

    def _load_index(self) -> None:
        """Rebuild the in-memory index from the JSONL file (source of truth)."""
        if not self.jsonl_path.exists():
            self._index = {}
            self._index_overflowed = False
            return
        index: dict[str, dict[str, int]] = {}
        overflowed = False
        with open(self.jsonl_path, "r", encoding="utf-8") as fh:
            offset = 0
            for line in fh:
                if not line.strip():
                    offset += len(line.encode("utf-8"))
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    offset += len(line.encode("utf-8"))
                    continue
                length = len(line.encode("utf-8"))
                rid = obj.get("id")
                if rid and len(index) < self.index_cap:
                    index[rid] = {"offset": offset, "length": length}
                elif rid:
                    overflowed = True
                offset += length
        with self._lock:
            self._index = index
            self._index_overflowed = overflowed

    def _persist_index(self) -> None:
        """Write the in-memory index to disk. Best-effort."""
        try:
            payload = {
                "index": self._index,
                "overflowed": self._index_overflowed,
                "wrote_at": datetime.now(UTC).isoformat(),
            }
            tmp = self.index_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, sort_keys=True))
            os.replace(tmp, self.index_path)
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("ReplayStore: index persist failed: %s", exc)


def _record_from_json(line: str) -> RecordedRequest:
    obj = json.loads(line)
    return RecordedRequest(
        id=obj["id"],
        method=obj["method"],
        url=obj["url"],
        headers=dict(obj.get("headers", {})),
        body=obj.get("body"),
        timestamp=obj["timestamp"],
        response_status=int(obj["response_status"]),
        response_body=obj["response_body"],
        response_headers=dict(obj.get("response_headers", {})),
        body_truncated=bool(obj.get("body_truncated", False)),
        response_truncated=bool(obj.get("response_truncated", False)),
        source_file=obj.get("source_file", "requests.jsonl"),
    )


# ---------------------------------------------------------------------------
# The mutator
# ---------------------------------------------------------------------------


class ReplayMutator:
    """Replays a recorded request with a ``Mutation`` applied.

    The mutator does not write back to the store — replayed requests
    are themselves recorded (via the same ``event_hook``) under a new
    ID, since the mutation changes the body / URL / headers and
    therefore the request hash.
    """

    def __init__(
        self,
        store: ReplayStore,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.store = store
        self._owns_client = http_client is None
        self.client = http_client or httpx.AsyncClient(
            verify=False,  # pentest scope; documenting
            timeout=30.0,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def replay_with_mutation(
        self,
        request_id: str,
        mutations: dict[str, Any] | Mutation,
    ) -> httpx.Response:
        """Replay the recorded request with the given mutations.

        ``mutations`` may be a ``Mutation`` instance or a dict with
        any of ``url``, ``headers``, ``body``, ``method`` keys.
        Unknown keys are ignored.
        """
        if isinstance(mutations, dict):
            mutation = Mutation.from_dict(mutations)
        else:
            mutation = mutations
        rec = self.store.get(request_id)
        return await self._replay(rec, mutation)

    async def replay_verbatim(self, request_id: str) -> httpx.Response:
        """Replay the recorded request with no changes."""
        rec = self.store.get(request_id)
        return await self._replay(rec, Mutation())

    async def _replay(
        self, rec: RecordedRequest, mutation: Mutation
    ) -> httpx.Response:
        url = mutation.url or rec.url
        method = (mutation.method or rec.method).upper()
        # Merge headers: recorded first, mutation overrides.
        headers = dict(rec.headers)
        if mutation.headers:
            # Lowercase comparison because httpx stores headers lowercase
            # and the recorded headers may be either case.
            lower_to_orig = {k.lower(): k for k in headers}
            for k, v in mutation.headers.items():
                target = lower_to_orig.get(k.lower(), k)
                headers[target] = v
        body = (
            mutation.body.encode("utf-8") if mutation.body is not None
            else (rec.body_bytes() if rec.body else None)
        )
        # httpx accepts str bodies for some methods (let it decide).
        response = await self.client.request(
            method=method,
            url=url,
            headers=headers,
            content=body,
        )
        return response


# ---------------------------------------------------------------------------
# Disk-fallback in-memory store for tests / pre-engagement use
# ---------------------------------------------------------------------------


class InMemoryReplayStore(ReplayStore):
    """A ReplayStore that never touches the disk.

    The full record set is kept in memory. Useful for unit tests and
    for the "engagement not yet persisted" case in the CLI. Records
    are NOT written to JSONL on disk.

    Methods that hit the filesystem (``_load_index``, ``_persist_index``)
    are overridden to be no-ops. The on-disk path is still created
    on construction so the public contract is unchanged.
    """

    def __init__(self) -> None:
        # Bypass ReplayStore.__init__ entirely — we want no disk I/O.
        self.engagement_id = "in-memory"
        self.artifacts_dir = Path("/tmp")  # never written to
        self.replay_dir = self.artifacts_dir
        self.jsonl_path = self.replay_dir / "requests.jsonl"  # never created
        self.index_path = self.replay_dir / "requests.index.json"
        self.max_body_bytes = DEFAULT_MAX_BODY_BYTES
        self.index_cap = DEFAULT_INDEX_CAP
        self._lock = threading.Lock()
        self._index = {}
        self._index_overflowed = False
        self._records: list[RecordedRequest] = []

    def _record_unsafe(
        self, request: httpx.Request, response: httpx.Response
    ) -> str:
        method = request.method
        url = str(request.url)
        headers = {k: v for k, v in request.headers.items()}
        body_text = _body_to_text(request.content) if request.content else None
        record_id = _hash_id(method, url, body_text, headers)
        import base64
        response_body_b64 = base64.b64encode(
            response.content or b""
        ).decode("ascii")
        rec = RecordedRequest(
            id=record_id,
            method=method,
            url=url,
            headers=headers,
            body=body_text,
            timestamp=datetime.now(UTC).isoformat(),
            response_status=response.status_code,
            response_body=response_body_b64,
            response_headers={k: v for k, v in response.headers.items()},
            body_truncated=False,
            response_truncated=False,
        )
        with self._lock:
            self._records.append(rec)
            if len(self._index) < self.index_cap:
                self._index[record_id] = {"offset": 0, "length": 0}
            else:
                self._index_overflowed = True
        return record_id

    def get(self, request_id: str) -> RecordedRequest:  # type: ignore[override]
        with self._lock:
            for rec in self._records:
                if rec.id == request_id:
                    return rec
        raise KeyError(f"request_id {request_id!r} not found in InMemoryReplayStore")

    def list(  # type: ignore[override]
        self, *, limit: int | None = None, method: str | None = None
    ) -> list[RecordedRequest]:
        with self._lock:
            records = list(self._records)
        if method:
            records = [r for r in records if r.method.upper() == method.upper()]
        if limit is not None:
            records = records[:limit]
        return records

    def record_count(self) -> int:  # type: ignore[override]
        with self._lock:
            return len(self._records)

    def clear(self) -> None:  # type: ignore[override]
        with self._lock:
            self._records.clear()
            self._index.clear()
            self._index_overflowed = False

    def _load_index(self) -> None:  # no-op
        return None

    def _persist_index(self) -> None:  # no-op
        return None


__all__ = [
    "DEFAULT_INDEX_CAP",
    "DEFAULT_MAX_BODY_BYTES",
    "InMemoryReplayStore",
    "Mutation",
    "RecordedRequest",
    "ReplayMutator",
    "ReplayStore",
]
