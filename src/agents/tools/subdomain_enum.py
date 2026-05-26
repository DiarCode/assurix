"""Subdomain enumeration via DNS resolution and Certificate Transparency logs."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "app", "blog", "shop", "portal", "cdn", "static", "media",
    "docs", "vpn", "remote", "intranet", "internal", "beta", "demo",
    "git", "gitlab", "jenkins", "ci", "build", "monitor",
    "grafana", "kibana", "db", "database", "backup", "old", "new",
    "m", "mobile", "mx", "ns1", "smtp", "relay",
]


@dataclass
class SubdomainResult:
    subdomain: str
    ip: str
    status_code: int | None
    title: str
    severity: str
    finding: str | None = None
    evidence: str = ""


class SubdomainEnumerator:
    """Async subdomain enumeration via DNS and CT logs."""

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 20):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def enumerate(self, domain: str, extra_subdomains: list[str] | None = None) -> list[SubdomainResult]:
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        ct_results = await self._check_ct_logs(domain)
        dns_results = await self._check_dns(domain, extra_subdomains or COMMON_SUBDOMAINS)
        all_results: dict[str, SubdomainResult] = {}
        for r in ct_results + dns_results:
            key = r.subdomain
            if key not in all_results:
                all_results[key] = r
            elif r.status_code and not all_results[key].status_code:
                all_results[key] = r
        return sorted(all_results.values(), key=lambda r: r.subdomain)

    async def _check_dns(self, domain: str, subdomains: list[str]) -> list[SubdomainResult]:
        results: list[SubdomainResult] = []

        async def resolve(sub: str) -> SubdomainResult | None:
            fqdn = f"{sub}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, fqdn),
                    timeout=self.timeout,
                )
                severity = "high" if sub in ("admin", "staging", "dev", "test", "internal", "vpn", "backup", "db") else "info"
                finding = f"Sensitive subdomain found: {fqdn}" if severity == "high" else None
                return SubdomainResult(
                    subdomain=fqdn, ip=ip, status_code=None, title="",
                    severity=severity, finding=finding, evidence=f"Resolves to {ip}",
                )
            except Exception:
                return None

        tasks = [resolve(sub) for sub in subdomains]
        resolved = await asyncio.gather(*tasks)
        for r in resolved:
            if r:
                results.append(r)
        return results

    async def _check_ct_logs(self, domain: str) -> list[SubdomainResult]:
        results: list[SubdomainResult] = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if resp.status_code == 200:
                    entries = json.loads(resp.text)
                    seen: set[str] = set()
                    for entry in entries[:100]:
                        name = entry.get("name_value", "").split("\n")[0].strip()
                        if name and name not in seen and name.endswith(f".{domain}"):
                            seen.add(name)
                            results.append(SubdomainResult(
                                subdomain=name, ip="", status_code=None, title="",
                                severity="info", finding=None, evidence="Found in CT logs",
                            ))
        except Exception:
            pass
        return results