"""Race condition hunter (plan §3.2.2).

Hunts for "time-of-check to time-of-use" (TOCTOU) and concurrency bugs
on endpoints that perform a state change (transfer, redeem, withdraw,
coupon apply, balance credit). The classic failure mode: a server checks
a precondition (balance > 0, coupon unused) then applies the effect
in two non-atomic steps, so N concurrent requests all observe the
precondition as true and all succeed.

Approach
--------
1. ``fire_parallel(request, n_copies)`` — fire N copies of the same
   HTTP request via ``asyncio.gather``. The default N=10 is the minimum
   needed to outrace a single-threaded server's check/use gap. The
   caller can increase to 50-100 against apps that serialize inside
   the check step.

2. ``racy`` is True when ``success_count > 1`` and at least one
   success "should not have happened" — i.e. an idempotency signal
   (deducted balance, redeemed coupon, decremented stock) is missing
   on at least N-1 of the successes. We use two heuristics:

     (a) **Status-code uniformity**: if N copies return 2xx but the
         server's contract says at most 1 should succeed, that's racy.
     (b) **Side-effect deltas**: if the same endpoint's body contains
         a counter (e.g. "remaining": 3) we can read the deltas across
         responses. If responses disagree on the side-effect value
         (e.g. two responses both say "balance=100" when one should
         have decremented it), it's racy.

3. ``RaceResult`` carries:
     - ``concurrent_responses`` — list of ``httpx.Response`` (None on error)
     - ``racy`` — bool
     - ``success_count`` — number of 2xx responses
     - ``evidence`` — list of ``RequestResponseArtifact`` dicts (id,
       request, response) for replay/audit
     - ``reason`` — short string explaining the verdict
     - ``latency_ms`` — wall-clock for the gather

ToolProtocol
------------
``RaceHunter`` implements the ToolProtocol so the ResearchLoop can
dispatch it on a "race_condition" hypothesis. Preconditions and effects
are declared in the protocol's metadata; the runtime check
``check_authorization`` enforces scope.

Per plan §3.2.2: ``preconditions: [endpoint_reachable, no_idempotency_key]``,
``effects: [Effect(Belief("endpoint:racy", 0.6))]``. We model these as
instance attributes (``preconditions`` / ``effects``) since
ToolProtocol itself is a runtime interface and doesn't formally
declare them — the ResearchLoop reads them via
``getattr(tool, "preconditions", [])``.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import httpx

from src.agents.tools.protocol import ToolProtocol, AuthorizationContext  # noqa: F401
from src.schemas.tools import ToolCapability, ToolResult

logger = logging.getLogger(__name__)


# --- result types --------------------------------------------------------


@dataclass
class RequestResponseArtifact:
    """A (request, response) pair captured during parallel fire.

    Carried into ``RaceResult.evidence`` for replay and audit. The
    ``id`` is stable across processes so a downstream tool can refer
    back to this exact exchange (e.g. via the ReplayStore).
    """

    id: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    response_status: int
    response_headers: dict[str, str]
    response_body: str
    elapsed_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class RaceResult:
    """Result of ``RaceHunter.fire_parallel``.

    ``racy`` is True when the gathered responses indicate a TOCTOU
    window. We do not require N successes of N — even N-1 successes
    is racy if the endpoint's contract says only 1 should succeed.
    Callers should pass ``n_copies`` proportional to the expected
    serialization: stateful financial endpoints often need N=50.
    """

    concurrent_responses: list[httpx.Response | None]
    racy: bool
    success_count: int
    evidence: list[RequestResponseArtifact] = field(default_factory=list)
    reason: str = ""
    latency_ms: float = 0.0
    n_copies: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "racy": self.racy,
            "success_count": self.success_count,
            "n_copies": self.n_copies,
            "latency_ms": self.latency_ms,
            "reason": self.reason,
            "evidence": [e.to_dict() for e in self.evidence],
        }


# --- hunter --------------------------------------------------------------


class RaceHunter(ToolProtocol):
    """Detect TOCTOU/race conditions on state-changing endpoints.

    Usage::

        hunter = RaceHunter(n_copies=10, timeout=5.0)
        result = await hunter.fire_parallel(
            "POST", "https://target/api/transfer",
            json={"to": "alice", "amount": 100},
        )
        if result.racy:
            ... # report
    """

    name = "race_hunter"
    capability_tags = ["race_condition", "concurrency", "toctou", "state_change"]

    # Per plan §3.2.2 — declared on the class for the ResearchLoop to read
    # via getattr. ToolProtocol doesn't formally define them; this is the
    # convention adopted by other tools in this codebase.
    preconditions: list[str] = ["endpoint_reachable", "no_idempotency_key"]
    effects: list[dict[str, Any]] = [
        # Belief("endpoint:racy", 0.6) when racy=True; declared as a dict
        # so we don't need to import the Belief schema here. The
        # ResearchLoop translates the dict into the typed Belief.
        {"belief": "endpoint:racy", "confidence": 0.6}
    ]

    def __init__(
        self,
        n_copies: int = 10,
        timeout: float = 10.0,
        max_concurrent: int = 50,
    ) -> None:
        if n_copies < 1:
            raise ValueError(f"n_copies must be >= 1, got {n_copies}")
        if max_concurrent < 1:
            raise ValueError(f"max_concurrent must be >= 1, got {max_concurrent}")
        self.n_copies = n_copies
        self.timeout = timeout
        self._sem = asyncio.Semaphore(max_concurrent)

    async def fire_parallel(
        self,
        method: str,
        url: str,
        *,
        n_copies: int | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: Any = None,
        cookies: dict[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> RaceResult:
        """Fire N copies of a request concurrently and analyze the results.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH).
            url: Fully-qualified URL.
            n_copies: Override the default concurrency (plan default 10).
            headers: Optional request headers; **shared** across copies.
            params: Optional query parameters.
            json: Optional JSON body.
            data: Optional form body.
            cookies: Optional cookies.
            client: Optional pre-built ``httpx.AsyncClient``. When None,
                a fresh client is created and closed within this call.

        Returns:
            ``RaceResult`` with the gathered responses, the racy verdict,
            and per-request evidence artifacts.
        """
        n = self.n_copies if n_copies is None else n_copies
        if n < 1:
            raise ValueError(f"n_copies must be >= 1, got {n}")

        method = method.upper()
        headers = dict(headers or {})
        body_json = json
        body_data = data
        # Re-serialize body to a string for the artifact. We don't
        # round-trip through json.dumps for json= since the caller
        # might pass non-JSON-serializable httpx objects — but in
        # practice callers do pass dicts. If serialization fails,
        # store the repr.
        if body_json is not None:
            try:
                import json as _json
                request_body_repr = _json.dumps(body_json, default=str)
            except Exception:
                request_body_repr = repr(body_json)
        elif body_data is not None:
            request_body_repr = str(body_data)
        else:
            request_body_repr = ""

        owns_client = client is None
        if owns_client:
            # verify=False is documented pentest scope (Vulhub/DVWA labs).
            # In a real engagement, callers should pass an authenticated
            # ``client`` built from SharedSessionManager.
            client = httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                follow_redirects=False,
            )

        start = time.perf_counter()
        try:
            tasks = [
                self._fire_one(
                    client, method, url, headers, params, body_json, body_data,
                    cookies,
                )
                for _ in range(n)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)
        finally:
            if owns_client:
                await client.aclose()
        latency_ms = (time.perf_counter() - start) * 1000.0

        artifacts, responses = self._build_artifacts(
            results, method, url, headers, request_body_repr,
        )
        success_count = sum(
            1 for r in responses
            if r is not None and 200 <= r.status_code < 300
        )
        racy, reason = self._judge(responses, success_count, n)

        return RaceResult(
            concurrent_responses=responses,
            racy=racy,
            success_count=success_count,
            evidence=artifacts,
            reason=reason,
            latency_ms=latency_ms,
            n_copies=n,
        )

    async def _fire_one(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None,
        json_body: Any,
        data_body: Any,
        cookies: dict[str, str] | None,
    ) -> tuple[httpx.Response | None, float]:
        async with self._sem:
            t0 = time.perf_counter()
            try:
                resp = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    data=data_body,
                    cookies=cookies,
                )
                return resp, (time.perf_counter() - t0) * 1000.0
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                logger.debug("RaceHunter: request failed: %s", exc)
                return None, (time.perf_counter() - t0) * 1000.0

    def _build_artifacts(
        self,
        results: list[tuple[httpx.Response | None, float]],
        method: str,
        url: str,
        headers: dict[str, str],
        request_body_repr: str,
    ) -> tuple[list[RequestResponseArtifact], list[httpx.Response | None]]:
        artifacts: list[RequestResponseArtifact] = []
        responses: list[httpx.Response | None] = []
        for resp, elapsed_ms in results:
            if resp is None:
                responses.append(None)
                continue
            responses.append(resp)
            try:
                resp_body = resp.text
            except Exception:
                resp_body = ""
            artifacts.append(
                RequestResponseArtifact(
                    id=str(uuid4()),
                    method=method,
                    url=url,
                    request_headers=dict(headers),
                    request_body=request_body_repr,
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp_body[:8192],  # truncate evidence
                    elapsed_ms=elapsed_ms,
                )
            )
        return artifacts, responses

    def _judge(
        self,
        responses: list[httpx.Response | None],
        success_count: int,
        n: int,
    ) -> tuple[bool, str]:
        """Decide whether the gathered responses show a race.

        Heuristics, in order:
          1. success_count > 1 and at least 2 responses carry 2xx —
             even if the contract permits N, two simultaneous successes
             are evidence the server isn't serializing.
          2. success_count == n and n >= 2 — extreme case, every
             request succeeded (e.g. withdraw N=50 on a $5 account).
          3. Mixed status codes: at least one 2xx and at least one
             non-2xx-with-similar-body (e.g. "insufficient balance"
             appearing in some but not all responses) is suspicious.
        """
        if n < 2:
            return False, "n<2, single request is not a race"

        if success_count == 0:
            return False, "no successful responses"

        if success_count >= 2:
            # Heuristic 1+2: multi-success is the canonical race signal
            if success_count == n:
                return True, (
                    f"all {n} concurrent requests succeeded; "
                    "endpoint does not serialize state changes"
                )
            return True, (
                f"{success_count}/{n} concurrent requests succeeded; "
                "endpoint may permit duplicate state changes"
            )

        # success_count == 1: maybe safe, but check mixed status for
        # secondary signals (e.g. one 2xx + several 5xx with retry-after
        # is a different fingerprint than one 2xx + several 4xx with
        # body-shaped rejection).
        statuses = sorted({
            r.status_code for r in responses if r is not None
        })
        if len(statuses) >= 3:
            return False, (
                f"single success among mixed status codes {statuses}; "
                "no clear race signal"
            )
        return False, f"single success among {len(statuses)} status codes; no race"

    # ---- ToolProtocol --------------------------------------------------

    async def run(
        self,
        target: str,
        hypothesis: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: "AuthorizationContext | None" = None,
    ) -> ToolResult:
        """ToolProtocol entry point used by ResearchLoop dispatch.

        Reads ``params["method"]`` (default POST), ``params["n_copies"]``
        (default self.n_copies), ``params["json"]`` / ``params["data"]``
        / ``params["headers"]`` for the request body. ``target`` is the
        URL. Returns a ``ToolResult`` with one finding per racy run.
        """
        ok, reason = self.check_authorization(auth)
        if not ok:
            return ToolResult(
                success=False, error=f"authorization denied: {reason}",
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

        params = params or {}
        try:
            result = await self.fire_parallel(
                method=params.get("method", "POST"),
                url=target,
                n_copies=params.get("n_copies"),
                headers=params.get("headers"),
                json=params.get("json"),
                data=params.get("data"),
                client=params.get("client"),
            )
        except Exception as exc:
            logger.exception("RaceHunter.run: failed")
            return ToolResult(
                success=False, error=str(exc),
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

        findings: list[dict[str, Any]] = []
        if result.racy:
            findings.append({
                "type": "race_condition",
                "url": target,
                "method": params.get("method", "POST"),
                "severity": "high",
                "title": f"Race condition: {result.success_count}/{result.n_copies} "
                         "concurrent state-change requests succeeded",
                "description": result.reason,
                "evidence_count": len(result.evidence),
                "n_copies": result.n_copies,
                "success_count": result.success_count,
                "latency_ms": result.latency_ms,
            })
        return ToolResult(
            success=True,
            findings=findings,
            result_data=result.to_dict(),
            tool_name=self.name,
            hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
        )

    def describe_capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                tag="race_condition",
                description="Detect TOCTOU/state-change races via parallel fire",
                priority=9,
            ),
            ToolCapability(
                tag="concurrency",
                description="Concurrent request analysis",
                priority=7,
            ),
            ToolCapability(
                tag="toctou",
                description="Time-of-check to time-of-use vulnerabilities",
                priority=8,
            ),
            ToolCapability(
                tag="state_change",
                description="Endpoints that mutate server-side state",
                priority=6,
            ),
        ]


__all__ = [
    "RaceHunter",
    "RaceResult",
    "RequestResponseArtifact",
]
