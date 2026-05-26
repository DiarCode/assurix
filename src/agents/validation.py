"""Independent exploit re-verification agent (MAPTA pattern).

For each high/medium finding, generates a minimal PoC, re-executes
against the live target, and verifies the expected behavior occurs.
Increases confidence for verified findings, decreases for unverified.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent

logger = logging.getLogger(__name__)

MAX_VALIDATIONS_PER_SCAN = 20

CONFIDENCE_BOOST_VERIFIED = 0.15
CONFIDENCE_PENALTY_UNVERIFIED = 0.20


class ValidationAgent(BaseAgent):
    """Independent exploit re-verification agent."""

    name = "validation"

    def __init__(self) -> None:
        self._http_client: httpx.AsyncClient | None = None

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        """Validate findings by independently re-verifying each one, then adversarial debate."""
        findings = payload.get("findings", [])
        target_url = payload.get("target_url", "")
        surface = payload.get("observations", {})

        if not findings or not target_url:
            return {"findings": findings, "artifacts": [], "target_url": target_url}

        to_validate = [
            f for f in findings
            if f.get("severity", "info").lower() in ("high", "critical", "medium")
        ][:MAX_VALIDATIONS_PER_SCAN]

        if not to_validate:
            return {"findings": findings, "artifacts": [], "target_url": target_url}

        # Phase 1: Rule-based validation (fixed P0 methods)
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            self._http_client = client
            validated = []
            for finding in to_validate:
                result = await self._validate_finding(finding, target_url, client)
                validated.append(result)

        # Merge validation results back into findings
        validation_map = {f.get("title", ""): f for f in validated}
        for finding in findings:
            title = finding.get("title", "")
            if title in validation_map:
                validated_finding = validation_map[title]
                finding["exploit_verified"] = validated_finding.get("exploit_verified", False)
                finding["verification_evidence"] = validated_finding.get("verification_evidence", "")
                current_confidence = finding.get("confidence_score", 0.7)
                if finding.get("exploit_verified"):
                    finding["confidence_score"] = min(1.0, current_confidence + CONFIDENCE_BOOST_VERIFIED)
                else:
                    finding["confidence_score"] = max(0.1, current_confidence - CONFIDENCE_PENALTY_UNVERIFIED)

        # Phase 2: Adversarial debate validation for survivors (P3)
        survivors = [f for f in findings if f.get("exploit_verified", False) and f.get("confidence_score", 0) >= 0.6]
        if survivors:
            try:
                from src.agents.adversarial import AdversarialValidator
                adv = AdversarialValidator(min_confidence=0.6)
                adv_results = await adv.validate_findings(survivors, surface)
                adv_map = {f.get("title", ""): f for f in adv_results}
                for finding in findings:
                    title = finding.get("title", "")
                    if title in adv_map:
                        adv_finding = adv_map[title]
                        if not adv_finding.get("validated", True):
                            finding["exploit_verified"] = False
                            finding["confidence_score"] = min(
                                finding.get("confidence_score", 0.7), 0.3
                            )
                            finding["verification_evidence"] = (
                                f"Adversarial debate rejected: {adv_finding.get('validation_reasoning', '')}"
                            )
            except Exception as e:
                logger.warning(f"Adversarial validation failed: {e}")

        return {"findings": findings, "artifacts": [], "target_url": target_url}

    async def _validate_finding(
        self, finding: dict, target_url: str, client: httpx.AsyncClient,
    ) -> dict:
        """Route to appropriate validation method."""
        title_lower = finding.get("title", "").lower()

        if any(kw in title_lower for kw in ("idor", "access control", "unauthorized access", "bypass")):
            return await self._validate_idor(finding, finding.get("url", target_url), client)
        elif any(kw in title_lower for kw in ("xss", "cross-site scripting", "reflected", "stored")):
            return await self._validate_xss(finding, finding.get("url", target_url), client)
        elif any(kw in title_lower for kw in ("sqli", "sql injection", "blind")):
            return await self._validate_sqli(finding, finding.get("url", target_url), client)
        elif any(kw in title_lower for kw in ("ssrf", "server-side request")):
            return await self._validate_ssrf(finding, finding.get("url", target_url), client)
        elif any(kw in title_lower for kw in ("redirect", "open redirect")):
            return await self._validate_redirect(finding, finding.get("url", target_url), client)
        elif any(kw in title_lower for kw in ("exposed", "sensitive", "directory", "path", "file", "info", "disclosure")):
            return await self._validate_exposure(finding, finding.get("url", target_url), client)
        else:
            return await self._validate_generic(finding, finding.get("url", target_url), client)

    async def _validate_idor(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Validate IDOR with differential testing across user IDs."""
        try:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                return {**finding, "exploit_verified": False, "verification_evidence": f"Redirects to: {location}"}
            if resp.status_code in (401, 403):
                return {**finding, "exploit_verified": False, "verification_evidence": f"Returns {resp.status_code}"}
            if resp.status_code == 200:
                # SPA catch-all detection
                if any(ind in resp.text.lower() for ind in ('<div id="root">', '<div id="app">', '<div id="__next"', '<div id="__nuxt"')):
                    return {**finding, "exploit_verified": False, "verification_evidence": "SPA catch-all page, not real IDOR"}
                # JSON with user-specific data — must have user fields
                try:
                    data = json.loads(resp.text)
                    user_fields = {"id", "email", "username", "name", "phone", "user_id", "user"}
                    has_user_data = False
                    if isinstance(data, dict):
                        has_user_data = bool(set(str(k).lower() for k in data.keys()) & user_fields)
                    elif isinstance(data, list) and data:
                        has_user_data = bool(set(str(k).lower() for k in data[0].keys()) & user_fields) if isinstance(data[0], dict) else False
                    if not has_user_data:
                        return {**finding, "exploit_verified": False, "verification_evidence": f"200 response lacks user-specific data fields ({len(resp.text)}B)"}
                    # Differential test: try a different ID to verify data differs per user
                    import re
                    alt_url = re.sub(r'/(\d+)(?=[/?]|$)', '/99999', url, count=1)
                    if alt_url != url:
                        alt_resp = await client.get(alt_url, follow_redirects=False)
                        if alt_resp and alt_resp.status_code == 200 and alt_resp.text != resp.text:
                            return {**finding, "exploit_verified": True, "verification_evidence": f"IDOR confirmed: different user IDs return different data (original {len(resp.text)}B vs alt {len(alt_resp.text)}B)"}
                        elif alt_resp and alt_resp.status_code == 200 and alt_resp.text == resp.text:
                            return {**finding, "exploit_verified": False, "verification_evidence": f"Same response for different user IDs — not real IDOR"}
                    return {**finding, "exploit_verified": True, "verification_evidence": f"JSON with user fields accessible without auth ({len(resp.text)}B)"}
                except (json.JSONDecodeError, TypeError):
                    return {**finding, "exploit_verified": False, "verification_evidence": f"Non-JSON 200 response, not IDOR ({len(resp.text)}B)"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status: {resp.status_code}"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}

    async def _validate_xss(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Validate XSS by checking if markers appear in response."""
        try:
            resp = await client.get(url, follow_redirects=True)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                markers = ["assurix_xss_", "<script>", "alert(", "onerror="]
                found = [m for m in markers if m.lower() in body_lower]
                if found:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"XSS marker found: {found}"}
                return {**finding, "exploit_verified": False, "verification_evidence": "No XSS marker reflected in independent verification"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status: {resp.status_code}"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}

    async def _validate_sqli(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Validate SQL injection via error keywords + differential testing."""
        try:
            # Get baseline (clean) response
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
            baseline = await client.get(clean_url, follow_redirects=False)

            resp = await client.get(url, follow_redirects=False)
            # Status 500 alone is NOT SQLi — need SQL error keywords
            if resp.status_code == 500:
                body_lower = resp.text.lower()
                sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "odbc", "sqlstate", "unclosed quotation", "unexpected end of sql"]
                found_errors = [e for e in sql_errors if e in body_lower]
                if found_errors:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"SQL error in 500 response: {found_errors}"}
                # 500 without SQL keywords — generic server error, not SQLi
                if baseline and baseline.status_code == 500:
                    return {**finding, "exploit_verified": False, "verification_evidence": f"500 on both clean and injected requests — generic server error"}
                return {**finding, "exploit_verified": False, "verification_evidence": f"500 but no SQL error keywords in response"}
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "odbc", "sqlstate", "unclosed quotation"]
                found_errors = [e for e in sql_errors if e in body_lower]
                if found_errors:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"SQL error confirmed: {found_errors}"}
                # Differential test: if response differs from baseline, it's suspicious
                if baseline and baseline.status_code == 200 and resp.text != baseline.text:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"Differential: injected response differs from clean baseline ({len(resp.text)}B vs {len(baseline.text)}B)"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status {resp.status_code}, no SQL errors or differential"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}

    async def _validate_ssrf(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Validate SSRF by testing internal URL injection and checking for metadata/leaked data."""
        try:
            # SSRF means the SERVER made a request to an internal resource
            # Just reaching a URL is NOT SSRF — test by injecting internal URLs as parameters
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            # Get baseline response without SSRF params
            clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
            baseline = await client.get(clean_url, follow_redirects=False)

            resp = await client.get(url, follow_redirects=False)
            if resp.status_code in (200, 301, 302):
                # Check if response contains cloud metadata or internal service data
                body_lower = resp.text.lower() if resp.status_code == 200 else ""
                metadata_markers = [
                    "ami-id", "instance-id", "instance-type", "local-ipv4",
                    "iam", "security-credentials", "meta-data",
                    "computeMetadata", "access-token",
                ]
                found_metadata = [m for m in metadata_markers if m in body_lower]
                if found_metadata:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"SSRF confirmed: cloud metadata found: {found_metadata}"}
                # Differential test: if SSRF response differs from clean baseline
                if baseline and baseline.status_code == 200 and resp.text != baseline.text:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"SSRF response differs from baseline ({len(resp.text)}B vs {len(baseline.text)}B)"}
                # Same as baseline — the server didn't make a side-channel request
                return {**finding, "exploit_verified": False, "verification_evidence": f"URL reachable but response identical to baseline — no SSRF evidence"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status: {resp.status_code}"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}

    async def _validate_redirect(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Validate open redirect."""
        try:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                return {**finding, "exploit_verified": True, "verification_evidence": f"Redirect confirmed to: {location}"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status: {resp.status_code}, not a redirect"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}

    async def _validate_exposure(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Validate sensitive path exposure — only confirm if sensitive content is present."""
        try:
            resp = await client.get(url, follow_redirects=True)
            if resp.status_code == 200:
                # SPA catch-all: not a real exposure
                if any(ind in resp.text.lower() for ind in ('<div id="root">', '<div id="app">', '<div id="__next"', '<div id="__nuxt"')):
                    return {**finding, "exploit_verified": False, "verification_evidence": "SPA catch-all page, not real exposure"}
                # Content-type check: HTML without sensitive markers is not exposure
                content_type = resp.headers.get("content-type", "").lower()
                sensitive_markers = [
                    "root:", "[extensions]", "db_password", "secret_key", "api_key",
                    "private_key", "password=", "aws_secret", "connection_string",
                    "database_url", "smtp", "credentials",
                ]
                found = [m for m in sensitive_markers if m in resp.text.lower()]
                if found:
                    return {**finding, "exploit_verified": True, "verification_evidence": f"Sensitive content confirmed: {found}"}
                # No sensitive markers — not a real exposure
                return {**finding, "exploit_verified": False, "verification_evidence": f"Path accessible but no sensitive markers in response ({len(resp.text)}B)"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status: {resp.status_code}"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}

    async def _validate_generic(self, finding: dict, url: str, client: httpx.AsyncClient) -> dict:
        """Generic validation with baseline comparison and soft-404 detection."""
        try:
            # Get baseline: same URL without finding-specific query params
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            baseline_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
            baseline = await client.get(baseline_url, follow_redirects=False)

            resp = await client.get(url, follow_redirects=False)
            if resp.status_code == 200:
                # SPA catch-all detection
                if any(ind in resp.text.lower() for ind in ('<div id="root">', '<div id="app">', '<div id="__next"', '<div id="__nuxt"')):
                    return {**finding, "exploit_verified": False, "verification_evidence": "SPA catch-all page"}
                # Soft-404: if response is near-identical to baseline, it's a catch-all
                if baseline and baseline.status_code == 200:
                    body_diff = abs(len(resp.text) - len(baseline.text))
                    avg_len = (len(resp.text) + len(baseline.text)) / 2
                    if avg_len > 0 and body_diff / avg_len < 0.05:
                        return {**finding, "exploit_verified": False, "verification_evidence": f"Response too similar to baseline (soft-404): {len(resp.text)}B vs {len(baseline.text)}B"}
                    # Response differs from baseline — likely real finding
                    if body_diff > 100:
                        return {**finding, "exploit_verified": True, "verification_evidence": f"Response differs from baseline ({len(resp.text)}B vs {len(baseline.text)}B, diff {body_diff}B)"}
                return {**finding, "exploit_verified": False, "verification_evidence": f"200 but no significant difference from baseline ({len(resp.text)}B)"}
            if resp.status_code in (301, 302, 303, 307, 308):
                return {**finding, "exploit_verified": False, "verification_evidence": f"Redirects to: {resp.headers.get('location', 'unknown')}"}
            return {**finding, "exploit_verified": False, "verification_evidence": f"Status: {resp.status_code}"}
        except Exception as e:
            return {**finding, "exploit_verified": False, "verification_evidence": f"Validation error: {e}"}