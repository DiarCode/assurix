"""Async TCP port scanner with service detection."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2222, 3000, 3306, 3389, 4443, 5000, 5432, 5672, 5900,
    6379, 6443, 8080, 8443, 8888, 9000, 9090, 9200, 9443, 27017,
]

SERVICE_MAP = {
    21: ("ftp", "FTP"), 22: ("ssh", "SSH"), 23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"), 53: ("dns", "DNS"), 80: ("http", "HTTP"),
    110: ("pop3", "POP3"), 111: ("rpcbind", "RPC"), 135: ("msrpc", "MS RPC"),
    139: ("netbios", "NetBIOS"), 143: ("imap", "IMAP"), 443: ("https", "HTTPS"),
    445: ("smb", "SMB"), 993: ("imaps", "IMAPS"), 995: ("pop3s", "POP3S"),
    1433: ("mssql", "MSSQL"), 1521: ("oracle", "Oracle DB"),
    2222: ("ssh-alt", "SSH alt"), 3000: ("node", "Node.js"),
    3306: ("mysql", "MySQL"), 3389: ("rdp", "RDP"),
    5000: ("python", "Python/Flask"), 5432: ("postgresql", "PostgreSQL"),
    5672: ("amqp", "RabbitMQ"), 5900: ("vnc", "VNC"),
    6379: ("redis", "Redis"), 6443: ("k8s-api", "K8s API"),
    8080: ("http-proxy", "HTTP Proxy"), 8443: ("https-alt", "HTTPS alt"),
    9000: ("php-fpm", "PHP-FPM"), 9090: ("prometheus", "Prometheus"),
    9200: ("elasticsearch", "Elasticsearch"), 27017: ("mongodb", "MongoDB"),
}

VULN_PORTS = {
    21: "FTP - check for anonymous login",
    23: "Telnet - cleartext protocol, should not be exposed",
    445: "SMB - EternalBlue and other SMB vulnerabilities possible",
    3306: "MySQL - check for default/weak credentials",
    5432: "PostgreSQL - check for default/weak credentials",
    6379: "Redis - check for unauthenticated access (default allows)",
    9200: "Elasticsearch - check for unauthenticated API access",
    27017: "MongoDB - check for unauthenticated access",
    3389: "RDP - check for brute-force and BlueKeep",
    5900: "VNC - check for unauthenticated access",
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str
    severity: str
    finding: str | None = None
    evidence: str = ""


class PortScanner:
    """Async TCP connect port scanner with service detection."""

    def __init__(self, timeout: float = 3.0, max_concurrent: int = 50):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_host(self, host: str, ports: list[int] | None = None) -> list[PortResult]:
        host = re.sub(r'^https?://', '', host).split('/')[0].split(':')[0]
        ports = sorted(set(ports or TOP_PORTS))
        tasks = [self._scan_port(host, port) for port in ports]
        port_results = await asyncio.gather(*tasks)
        results = [r for r in port_results if r and r.state == "open"]
        results.sort(key=lambda r: r.port)
        return results

    async def _scan_port(self, host: str, port: int) -> PortResult | None:
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                banner = ""
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()
            except (ConnectionRefusedError, OSError):
                return PortResult(port=port, state="closed", service="", banner="", severity="info")
            except asyncio.TimeoutError:
                return PortResult(port=port, state="filtered", service="", banner="", severity="info")
            except Exception:
                return None

        service_info = SERVICE_MAP.get(port, ("unknown", f"Unknown service on port {port}"))
        service, description = service_info
        severity = "info"
        finding = None
        if port in VULN_PORTS:
            severity = "medium"
            finding = VULN_PORTS[port]
        return PortResult(
            port=port, state="open", service=service, banner=banner,
            severity=severity, finding=finding,
            evidence=f"Port {port}/{service} OPEN - {description}{(' - ' + banner[:60]) if banner else ''}",
        )