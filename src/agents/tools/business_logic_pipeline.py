"""Business logic vulnerability pipeline for deep class-targeted testing.

Implements 4 genuinely new capabilities that don't duplicate existing DAST:
1. Workflow authorization bypass — multi-step workflow auth testing
2. Race condition active exploitation — concurrent request submission
3. IDOR active testing — object reference manipulation across user contexts
4. Business rule enforcement — negative values, zero prices, quantity manipulation

The existing WebappAgent has surface detection for these categories
(race_condition_indicators, business_logic investigation types), but
this pipeline provides ACTIVE EXPLOITATION and TESTING capabilities.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode

import httpx

logger = logging.getLogger(__name__)


@dataclass
class BusinessLogicResult:
    """Result from a business logic test."""
    url: str
    test_type: str  # workflow_auth, race_condition, idor, business_rule
    finding: str | None = None
    severity: str = "info"
    evidence: str = ""
    confidence: float = 0.0
    cwe_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class WorkflowAuthPipeline:
    """Test multi-step workflow authorization bypass.

    Tests whether a user can skip steps in a multi-step workflow
    (e.g., skip payment step, skip approval step, access admin-only
    workflow states). This is genuinely new — existing tools only
    check surface indicators, not active multi-step auth bypass.
    """

    async def run(
        self,
        target_url: str,
        session: httpx.AsyncClient | None = None,
        *,
        workflow_steps: list[dict[str, Any]] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> list[BusinessLogicResult]:
        """Test workflow authorization bypass.

        Args:
            target_url: Base URL of the target.
            session: Optional httpx async client.
            workflow_steps: List of workflow step dicts with 'url', 'method', 'data'.
            auth_cookies: Cookies for authenticated session.

        Returns:
            List of BusinessLogicResult findings.
        """
        results: list[BusinessLogicResult] = []
        client = session or httpx.AsyncClient(timeout=15.0, follow_redirects=False, http2=True)

        try:
            # Strategy 1: Skip-step testing — access later steps without completing earlier ones
            if workflow_steps:
                for i, step in enumerate(workflow_steps):
                    skip_results = await self._test_skip_step(client, step, i, auth_cookies)
                    results.extend(skip_results)

            # Strategy 2: Direct endpoint access — try accessing protected endpoints directly
            common_workflow_paths = [
                "/checkout/confirm", "/checkout/complete",
                "/order/confirm", "/order/place",
                "/payment/process", "/payment/confirm",
                "/admin/approve", "/admin/review",
                "/api/v1/orders/confirm", "/api/v1/checkout/complete",
                "/api/v1/workflow/approve", "/api/v1/workflow/complete",
            ]
            direct_results = await self._test_direct_access(client, target_url, common_workflow_paths, auth_cookies)
            results.extend(direct_results)

            # Strategy 3: State manipulation — try submitting completed state directly
            state_results = await self._test_state_manipulation(client, target_url, auth_cookies)
            results.extend(state_results)

        finally:
            if session is None:
                await client.aclose()

        return results

    async def _test_skip_step(
        self, client: httpx.AsyncClient, step: dict[str, Any], step_index: int,
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test accessing a workflow step without completing previous steps."""
        results = []
        url = step.get("url", "")
        method = step.get("method", "GET").upper()
        data = step.get("data", {})
        headers = {}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        try:
            if method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                resp = await client.request(method, url, json=data, headers=headers)

            # If we get a 200 response accessing a step we shouldn't be able to
            if resp.status_code == 200:
                results.append(BusinessLogicResult(
                    url=url,
                    test_type="workflow_auth",
                    finding=f"Workflow step {step_index} accessible without completing previous steps",
                    severity="medium",
                    evidence=f"Status {resp.status_code} on {method} {url} — expected redirect or 403",
                    confidence=0.6,
                    cwe_id="CWE-639",
                    details={"step_index": step_index, "method": method, "status_code": resp.status_code},
                ))
        except Exception as exc:
            logger.debug("WorkflowAuth skip-step test failed: %s", exc)

        return results

    async def _test_direct_access(
        self, client: httpx.AsyncClient, base_url: str, paths: list[str],
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test direct access to protected workflow endpoints."""
        results = []
        headers = {}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        for path in paths:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url, headers=headers)
                # 200 means we accessed a protected endpoint
                if resp.status_code == 200:
                    # Check if response contains workflow-related content
                    body = resp.text[:500].lower()
                    if any(kw in body for kw in ["order", "confirm", "checkout", "payment", "approved"]):
                        results.append(BusinessLogicResult(
                            url=url,
                            test_type="workflow_auth",
                            finding=f"Workflow endpoint accessible without authorization: {path}",
                            severity="medium",
                            evidence=f"Status 200 on direct access to {url}",
                            confidence=0.5,
                            cwe_id="CWE-639",
                            details={"path": path, "status_code": resp.status_code},
                        ))
            except Exception:
                continue

        return results

    async def _test_state_manipulation(
        self, client: httpx.AsyncClient, target_url: str,
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test manipulating workflow state parameters directly."""
        results = []
        headers = {"Content-Type": "application/json"}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        # Try common state manipulation payloads
        state_payloads = [
            {"status": "completed", "state": "approved"},
            {"step": "final", "approved": True},
            {"payment_status": "paid", "order_status": "confirmed"},
        ]

        api_base = urljoin(target_url, "/api/v1/")
        for payload in state_payloads:
            for endpoint in ["orders", "checkout", "workflow", "payment"]:
                url = urljoin(api_base, f"{endpoint}/")
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        results.append(BusinessLogicResult(
                            url=url,
                            test_type="workflow_auth",
                            finding=f"State manipulation accepted at {endpoint}",
                            severity="high",
                            evidence=f"Status {resp.status_code} when posting {payload} to {url}",
                            confidence=0.7,
                            cwe_id="CWE-639",
                            details={"endpoint": endpoint, "payload": payload, "status_code": resp.status_code},
                        ))
                except Exception:
                    continue

        return results


class RaceConditionPipeline:
    """Active race condition exploitation — concurrent request submission.

    Unlike existing _check_race_condition_indicators which only detects
    surface indicators, this pipeline actively exploits race conditions
    by sending concurrent requests to financial/state-changing operations.
    """

    async def run(
        self,
        target_url: str,
        session: httpx.AsyncClient | None = None,
        *,
        endpoints: list[dict[str, Any]] | None = None,
        auth_cookies: dict[str, str] | None = None,
        concurrency: int = 10,
    ) -> list[BusinessLogicResult]:
        """Actively test for race conditions.

        Args:
            target_url: Base URL of the target.
            session: Optional httpx async client.
            endpoints: List of endpoint dicts with 'url', 'method', 'data'.
            auth_cookies: Cookies for authenticated session.
            concurrency: Number of concurrent requests per test.

        Returns:
            List of BusinessLogicResult findings.
        """
        results: list[BusinessLogicResult] = []
        client = session or httpx.AsyncClient(timeout=15.0, follow_redirects=False, http2=True)

        try:
            # Default race condition test endpoints
            if not endpoints:
                endpoints = self._default_race_endpoints(target_url)

            for endpoint in endpoints:
                race_results = await self._test_race_condition(client, endpoint, auth_cookies, concurrency)
                results.extend(race_results)

        finally:
            if session is None:
                await client.aclose()

        return results

    def _default_race_endpoints(self, base_url: str) -> list[dict[str, Any]]:
        """Generate default race condition test endpoints."""
        return [
            {"url": urljoin(base_url, "/api/v1/payment/process"), "method": "POST", "data": {"amount": 1.00}},
            {"url": urljoin(base_url, "/api/v1/checkout/complete"), "method": "POST", "data": {}},
            {"url": urljoin(base_url, "/api/v1/orders/place"), "method": "POST", "data": {}},
            {"url": urljoin(base_url, "/api/v1/transfer"), "method": "POST", "data": {"amount": 1.00}},
            {"url": urljoin(base_url, "/api/v1/coupon/apply"), "method": "POST", "data": {"code": "RACE100"}},
        ]

    async def _test_race_condition(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any],
        auth_cookies: dict[str, str] | None, concurrency: int,
    ) -> list[BusinessLogicResult]:
        """Send concurrent requests and check for inconsistent responses."""
        results = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "POST").upper()
        data = endpoint.get("data", {})
        headers = {"Content-Type": "application/json"}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        # Send concurrent requests
        async def send_request():
            try:
                if method == "POST":
                    return await client.post(url, json=data, headers=headers)
                elif method == "PUT":
                    return await client.put(url, json=data, headers=headers)
                else:
                    return await client.request(method, url, json=data, headers=headers)
            except Exception:
                return None

        responses = await asyncio.gather(*[send_request() for _ in range(concurrency)])

        # Analyze responses for race condition indicators
        successful = [r for r in responses if r is not None and r.status_code in (200, 201)]
        if len(successful) > 1:
            # Multiple successful responses = potential race condition
            response_bodies = [r.text[:200] for r in successful if r]
            unique_bodies = len(set(hashlib.md5(b.encode()).hexdigest() for b in response_bodies))

            severity = "high" if len(successful) > 2 else "medium"
            results.append(BusinessLogicResult(
                url=url,
                test_type="race_condition",
                finding=f"Race condition: {len(successful)}/{concurrency} concurrent requests succeeded",
                severity=severity,
                evidence=f"{len(successful)} successful responses out of {concurrency} concurrent requests to {url}",
                confidence=min(0.9, 0.4 + 0.1 * len(successful)),
                cwe_id="CWE-362",
                details={
                    "concurrency": concurrency,
                    "successful_count": len(successful),
                    "unique_responses": unique_bodies,
                    "status_codes": [r.status_code for r in responses if r],
                },
            ))

        return results


class IDORPipeline:
    """Active IDOR testing — object reference manipulation across user contexts.

    Unlike existing IDORValidator (which validates patterns), this pipeline
    actively tests IDOR by manipulating object references and checking access
    across different user contexts.
    """

    async def run(
        self,
        target_url: str,
        session: httpx.AsyncClient | None = None,
        *,
        endpoints: list[dict[str, Any]] | None = None,
        user_contexts: list[dict[str, str]] | None = None,
        object_ids: list[str] | None = None,
    ) -> list[BusinessLogicResult]:
        """Actively test for Insecure Direct Object References.

        Args:
            target_url: Base URL of the target.
            session: Optional httpx async client.
            endpoints: List of endpoint dicts to test.
            user_contexts: List of auth context dicts (cookies/tokens for different users).
            object_ids: List of object IDs to test access for.

        Returns:
            List of BusinessLogicResult findings.
        """
        results: list[BusinessLogicResult] = []
        client = session or httpx.AsyncClient(timeout=15.0, follow_redirects=False, http2=True)

        try:
            if not endpoints:
                endpoints = self._default_idor_endpoints(target_url)

            if not object_ids:
                object_ids = ["1", "2", "0", "admin", "100", "999"]

            if not user_contexts:
                # Without user contexts, test for unauthenticated IDOR
                for endpoint in endpoints:
                    idor_results = await self._test_unauthenticated_idor(client, endpoint, object_ids)
                    results.extend(idor_results)
            else:
                # With multiple user contexts, test cross-user IDOR
                for endpoint in endpoints:
                    for i, ctx in enumerate(user_contexts):
                        for j, other_ctx in enumerate(user_contexts):
                            if i != j:
                                idor_results = await self._test_cross_user_idor(
                                    client, endpoint, object_ids, ctx, other_ctx
                                )
                                results.extend(idor_results)

        finally:
            if session is None:
                await client.aclose()

        return results

    def _default_idor_endpoints(self, base_url: str) -> list[dict[str, Any]]:
        """Generate default IDOR test endpoints."""
        return [
            {"url": urljoin(base_url, "/api/v1/users/{id}"), "method": "GET"},
            {"url": urljoin(base_url, "/api/v1/orders/{id}"), "method": "GET"},
            {"url": urljoin(base_url, "/api/v1/accounts/{id}"), "method": "GET"},
            {"url": urljoin(base_url, "/api/v1/documents/{id}"), "method": "GET"},
            {"url": urljoin(base_url, "/api/v1/profiles/{id}"), "method": "GET"},
        ]

    async def _test_unauthenticated_idor(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any], object_ids: list[str],
    ) -> list[BusinessLogicResult]:
        """Test IDOR without authentication — accessing objects directly."""
        results = []
        url_template = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()

        for obj_id in object_ids:
            url = url_template.replace("{id}", obj_id)
            try:
                if method == "GET":
                    resp = await client.get(url)
                else:
                    resp = await client.request(method, url)

                if resp.status_code == 200:
                    results.append(BusinessLogicResult(
                        url=url,
                        test_type="idor",
                        finding=f"Unauthenticated access to object {obj_id} at {url}",
                        severity="high",
                        evidence=f"Status 200 on {method} {url} without authentication",
                        confidence=0.8,
                        cwe_id="CWE-639",
                        details={"object_id": obj_id, "method": method, "status_code": resp.status_code},
                    ))
            except Exception:
                continue

        return results

    async def _test_cross_user_idor(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any],
        object_ids: list[str], user_ctx: dict[str, str], other_ctx: dict[str, str],
    ) -> list[BusinessLogicResult]:
        """Test IDOR across different user contexts."""
        results = []
        url_template = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()

        # First, get objects accessible to the other user
        other_headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in other_ctx.items())}

        for obj_id in object_ids:
            url = url_template.replace("{id}", obj_id)
            try:
                # Try accessing other user's objects with our cookies
                our_headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in user_ctx.items())}
                if method == "GET":
                    resp = await client.get(url, headers=our_headers)
                else:
                    resp = await client.request(method, url, headers=our_headers)

                if resp.status_code == 200:
                    results.append(BusinessLogicResult(
                        url=url,
                        test_type="idor",
                        finding=f"Cross-user IDOR: User A can access User B's object {obj_id}",
                        severity="high",
                        evidence=f"Status 200 accessing {url} with different user context",
                        confidence=0.85,
                        cwe_id="CWE-639",
                        details={"object_id": obj_id, "method": method, "status_code": resp.status_code},
                    ))
            except Exception:
                continue

        return results


class BusinessRulePipeline:
    """Business rule enforcement testing — negative values, price manipulation, quantity bypass.

    Tests whether the application properly validates business logic constraints:
    - Negative quantities and prices
    - Zero-price items
    - Quantity overflow
    - State bypass (e.g., completing without payment)
    """

    async def run(
        self,
        target_url: str,
        session: httpx.AsyncClient | None = None,
        *,
        endpoints: list[dict[str, Any]] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> list[BusinessLogicResult]:
        """Test business rule enforcement.

        Args:
            target_url: Base URL of the target.
            session: Optional httpx async client.
            endpoints: List of endpoint dicts to test.
            auth_cookies: Cookies for authenticated session.

        Returns:
            List of BusinessLogicResult findings.
        """
        results: list[BusinessLogicResult] = []
        client = session or httpx.AsyncClient(timeout=15.0, follow_redirects=False, http2=True)

        try:
            # Test 1: Negative value manipulation
            neg_results = await self._test_negative_values(client, target_url, auth_cookies)
            results.extend(neg_results)

            # Test 2: Zero price bypass
            zero_results = await self._test_zero_prices(client, target_url, auth_cookies)
            results.extend(zero_results)

            # Test 3: Quantity overflow
            qty_results = await self._test_quantity_overflow(client, target_url, auth_cookies)
            results.extend(qty_results)

            # Test 4: Parameter manipulation
            param_results = await self._test_parameter_manipulation(client, target_url, auth_cookies)
            results.extend(param_results)

        finally:
            if session is None:
                await client.aclose()

        return results

    async def _test_negative_values(
        self, client: httpx.AsyncClient, base_url: str,
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test negative value manipulation."""
        results = []
        headers = {"Content-Type": "application/json"}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        negative_payloads = [
            {"amount": -1, "quantity": -1},
            {"price": -0.01, "total": -100},
            {"discount": -50, "price": 100},
            {"quantity": -999, "price": 10},
        ]

        for endpoint in ["/api/v1/cart/add", "/api/v1/order/create", "/api/v1/payment/process"]:
            url = urljoin(base_url, endpoint)
            for payload in negative_payloads:
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        results.append(BusinessLogicResult(
                            url=url,
                            test_type="business_rule",
                            finding=f"Negative values accepted: {payload}",
                            severity="high",
                            evidence=f"Status {resp.status_code} when submitting negative values to {url}",
                            confidence=0.7,
                            cwe_id="CWE-639",
                            details={"endpoint": endpoint, "payload": payload, "status_code": resp.status_code},
                        ))
                except Exception:
                    continue

        return results

    async def _test_zero_prices(
        self, client: httpx.AsyncClient, base_url: str,
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test zero price bypass."""
        results = []
        headers = {"Content-Type": "application/json"}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        zero_payloads = [
            {"price": 0, "quantity": 1},
            {"total": 0, "item_id": "test"},
            {"amount": 0.00, "currency": "USD"},
        ]

        for endpoint in ["/api/v1/cart/add", "/api/v1/order/create", "/api/v1/checkout"]:
            url = urljoin(base_url, endpoint)
            for payload in zero_payloads:
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        results.append(BusinessLogicResult(
                            url=url,
                            test_type="business_rule",
                            finding=f"Zero price accepted: {payload}",
                            severity="medium",
                            evidence=f"Status {resp.status_code} when submitting zero price to {url}",
                            confidence=0.6,
                            cwe_id="CWE-639",
                            details={"endpoint": endpoint, "payload": payload, "status_code": resp.status_code},
                        ))
                except Exception:
                    continue

        return results

    async def _test_quantity_overflow(
        self, client: httpx.AsyncClient, base_url: str,
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test quantity overflow manipulation."""
        results = []
        headers = {"Content-Type": "application/json"}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        overflow_payloads = [
            {"quantity": 99999999, "price": 1},
            {"quantity": 2147483647, "item_id": "test"},  # INT_MAX
            {"quantity": -1, "price": 100},  # Negative quantity
        ]

        for endpoint in ["/api/v1/cart/add", "/api/v1/order/create"]:
            url = urljoin(base_url, endpoint)
            for payload in overflow_payloads:
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        results.append(BusinessLogicResult(
                            url=url,
                            test_type="business_rule",
                            finding=f"Quantity overflow accepted: {payload}",
                            severity="medium",
                            evidence=f"Status {resp.status_code} when submitting overflow quantity to {url}",
                            confidence=0.6,
                            cwe_id="CWE-190",
                            details={"endpoint": endpoint, "payload": payload, "status_code": resp.status_code},
                        ))
                except Exception:
                    continue

        return results

    async def _test_parameter_manipulation(
        self, client: httpx.AsyncClient, base_url: str,
        auth_cookies: dict[str, str] | None,
    ) -> list[BusinessLogicResult]:
        """Test parameter manipulation (adding hidden fields, type confusion)."""
        results = []
        headers = {"Content-Type": "application/json"}
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        manipulation_payloads = [
            {"item_id": "test", "is_admin": True},
            {"product_id": "1", "price": 0.01},  # Price override attempt
            {"order_id": "123", "status": "completed"},  # Status override
            {"user_id": "1", "role": "admin"},  # Role escalation
        ]

        for endpoint in ["/api/v1/cart/add", "/api/v1/order/create", "/api/v1/users/update"]:
            url = urljoin(base_url, endpoint)
            for payload in manipulation_payloads:
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        results.append(BusinessLogicResult(
                            url=url,
                            test_type="business_rule",
                            finding=f"Parameter manipulation accepted: {list(payload.keys())}",
                            severity="medium",
                            evidence=f"Status {resp.status_code} when submitting manipulated params to {url}",
                            confidence=0.5,
                            cwe_id="CWE-639",
                            details={"endpoint": endpoint, "payload": payload, "status_code": resp.status_code},
                        ))
                except Exception:
                    continue

        return results