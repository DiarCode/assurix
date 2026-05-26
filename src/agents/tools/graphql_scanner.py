"""GraphQL endpoint discovery, introspection, and security testing."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphiql", "/api/graphiql", "/gql", "/query",
    "/api/query", "/api/v1/graphql", "/playground",
]

INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name type { name } }
    }
  }
}"""

BATCH_QUERY = """[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]"""

ALIAS_OVERLOAD_QUERY = """{
  a0: __typename
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
  a11: __typename
  a12: __typename
  a13: __typename
  a14: __typename
  a15: __typename
  a16: __typename
  a17: __typename
  a18: __typename
  a19: __typename
}"""

DEPTH_NESTED_QUERY = """{
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}"""


@dataclass
class GraphQLResult:
    url: str
    test_type: str
    severity: str
    finding: str | None = None
    evidence: str = ""


class GraphQLScanner:
    """GraphQL endpoint discovery, introspection, and security testing."""

    def __init__(self, max_concurrent: int = 3, timeout: float = 15.0) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout

    async def _request(
        self, client: httpx.AsyncClient, method: str, url: str, **kwargs,
    ) -> httpx.Response | None:
        async with self.semaphore:
            try:
                return await client.request(method, url, timeout=self.timeout, follow_redirects=False, **kwargs)
            except (httpx.HTTPError, Exception):
                return None

    async def scan(self, base_url: str) -> list[GraphQLResult]:
        """Run full GraphQL security scan against a target."""
        results: list[GraphQLResult] = []

        async with httpx.AsyncClient(verify=False) as client:
            endpoint = await self._discover_endpoints(client, base_url, results)
            if not endpoint:
                return results

            await self._test_introspection(client, endpoint, results)
            await self._test_batch_queries(client, endpoint, results)
            await self._test_alias_overload(client, endpoint, results)
            await self._test_depth_attack(client, endpoint, results)
            await self._test_csrf_get(client, endpoint, results)

        return results

    async def _discover_endpoints(
        self, client: httpx.AsyncClient, base_url: str, results: list[GraphQLResult],
    ) -> str | None:
        """Probe common GraphQL endpoints."""
        for path in GRAPHQL_ENDPOINTS:
            url = urljoin(base_url, path.lstrip("/"))
            resp = await self._request(client, "GET", url)
            if resp and resp.status_code in (200, 400, 405):
                test_resp = await self._request(
                    client, "POST", url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                )
                if test_resp and test_resp.status_code == 200:
                    try:
                        data = json.loads(test_resp.text)
                        if "data" in data or "errors" in data:
                            results.append(GraphQLResult(
                                url=url, test_type="graphql_discovery",
                                severity="medium",
                                finding=f"GraphQL endpoint discovered: {path}",
                                evidence=f"Status: {test_resp.status_code}, Response keys: {list(data.keys())}",
                            ))
                            return url
                    except json.JSONDecodeError:
                        pass
        return None

    async def _test_introspection(
        self, client: httpx.AsyncClient, endpoint: str, results: list[GraphQLResult],
    ) -> None:
        """Test for GraphQL introspection disclosure."""
        resp = await self._request(
            client, "POST", endpoint,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if "data" in data and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    type_count = len(schema.get("types", []))
                    has_mutations = schema.get("mutationType") is not None
                    results.append(GraphQLResult(
                        url=endpoint, test_type="graphql_introspection",
                        severity="high",
                        finding="GraphQL introspection enabled — full schema disclosure",
                        evidence=f"Schema has {type_count} types, mutations: {has_mutations}",
                    ))
            except json.JSONDecodeError:
                pass

        # Test bypass techniques
        bypass_headers = [
            {"Accept": "application/json"},
            {"X-APOLLO-OPERATION-NAME": "IntrospectionQuery"},
        ]
        for headers in bypass_headers:
            resp = await self._request(
                client, "POST", endpoint,
                json={"query": INTROSPECTION_QUERY},
                headers={**headers, "Content-Type": "application/json"},
            )
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    if "data" in data and "__schema" in data.get("data", {}):
                        results.append(GraphQLResult(
                            url=endpoint, test_type="graphql_introspection_bypass",
                            severity="high",
                            finding=f"GraphQL introspection bypass via headers: {headers}",
                            evidence=f"Schema accessible with {headers}",
                        ))
                except json.JSONDecodeError:
                    pass

    async def _test_batch_queries(
        self, client: httpx.AsyncClient, endpoint: str, results: list[GraphQLResult],
    ) -> None:
        """Test for batch query abuse (DoS vector)."""
        resp = await self._request(
            client, "POST", endpoint,
            content=BATCH_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if isinstance(data, list) and len(data) >= 5:
                    results.append(GraphQLResult(
                        url=endpoint, test_type="graphql_batch",
                        severity="medium",
                        finding=f"GraphQL batch queries accepted ({len(data)} responses)",
                        evidence=f"Server processed {len(data)} queries in single request",
                    ))
            except json.JSONDecodeError:
                pass

    async def _test_alias_overload(
        self, client: httpx.AsyncClient, endpoint: str, results: list[GraphQLResult],
    ) -> None:
        """Test for alias overloading (DoS vector)."""
        resp = await self._request(
            client, "POST", endpoint,
            json={"query": ALIAS_OVERLOAD_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if "data" in data:
                    alias_count = len(data["data"])
                    if alias_count >= 10:
                        results.append(GraphQLResult(
                            url=endpoint, test_type="graphql_alias_overload",
                            severity="low",
                            finding=f"GraphQL alias overloading: {alias_count} aliases processed",
                            evidence=f"Server processed {alias_count} field aliases",
                        ))
            except json.JSONDecodeError:
                pass

    async def _test_depth_attack(
        self, client: httpx.AsyncClient, endpoint: str, results: list[GraphQLResult],
    ) -> None:
        """Test for query depth attacks."""
        import time
        start = time.monotonic()
        resp = await self._request(
            client, "POST", endpoint,
            json={"query": DEPTH_NESTED_QUERY},
            headers={"Content-Type": "application/json"},
        )
        elapsed = time.monotonic() - start

        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if "data" in data and data["data"] is not None:
                    results.append(GraphQLResult(
                        url=endpoint, test_type="graphql_depth",
                        severity="medium",
                        finding="GraphQL depth limiting not enforced — deep nested query succeeded",
                        evidence=f"7-level nested query processed in {elapsed:.1f}s",
                    ))
            except json.JSONDecodeError:
                pass

    async def _test_csrf_get(
        self, client: httpx.AsyncClient, endpoint: str, results: list[GraphQLResult],
    ) -> None:
        """Test for CSRF via GET method."""
        resp = await self._request(client, "GET", f"{endpoint}?query={{__typename}}")
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if "data" in data:
                    results.append(GraphQLResult(
                        url=endpoint, test_type="graphql_csrf",
                        severity="medium",
                        finding="GraphQL endpoint accepts GET requests (CSRF risk)",
                        evidence="Introspection query succeeded via GET method",
                    ))
            except json.JSONDecodeError:
                pass