"""Content-aware severity downgrade pipeline.

Applies rule-based severity adjustments to findings based on response
characteristics — login redirects, soft-404 pages, expected errors, timing
noise, and missing evidence.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

LEVEL_NAMES = ["info", "low", "medium", "high", "critical"]


class SeverityAdjuster:
    """Rule-based severity downgrade pipeline."""

    def adjust(self, finding: dict) -> dict:
        """Apply all downgrade rules to a finding. Returns modified finding."""
        severity = finding.get("severity", "info").lower()
        if severity not in LEVEL_NAMES:
            return finding

        level = LEVEL_NAMES.index(severity)

        # Rule 1: Login redirect — downgrade by 2
        if self._is_login_redirect(finding):
            level = max(0, level - 2)
            finding["_adjustment"] = finding.get("_adjustment", "")
            finding["_adjustment"] += "login_redirect(-2) "

        # Rule 2: Soft-404 — downgrade to info
        if self._is_soft_404(finding):
            level = 0
            finding["_adjustment"] = finding.get("_adjustment", "")
            finding["_adjustment"] += "soft_404(->info) "

        # Rule 3: Expected error — downgrade to info
        if self._is_expected_error(finding):
            level = 0
            finding["_adjustment"] = finding.get("_adjustment", "")
            finding["_adjustment"] += "expected_error(->info) "

        # Rule 4: Timing noise — downgrade by 1
        if self._is_timing_noise(finding):
            level = max(0, level - 1)
            finding["_adjustment"] = finding.get("_adjustment", "")
            finding["_adjustment"] += "timing_noise(-1) "

        # Rule 5: No concrete evidence — downgrade by 1
        if not self._has_concrete_evidence(finding):
            level = max(0, level - 1)
            finding["_adjustment"] = finding.get("_adjustment", "")
            finding["_adjustment"] += "no_evidence(-1) "

        finding["severity"] = LEVEL_NAMES[level]
        return finding

    def adjust_batch(self, findings: list[dict]) -> list[dict]:
        """Apply severity adjustment to a batch of findings."""
        return [self.adjust(f) for f in findings]

    def _is_login_redirect(self, finding: dict) -> bool:
        """Check if finding is a login page or auth redirect scored as higher severity."""
        evidence = finding.get("evidence", "").lower()
        description = finding.get("description", "").lower()
        url = finding.get("url", "").lower()

        login_keywords = ["login", "signin", "sign-in", "log in", "authenticate"]
        redirect_keywords = ["302", "301", "redirect", "location:"]
        auth_keywords = ["401 unauthorized", "403 forbidden", "auth required"]

        is_login = any(k in evidence for k in login_keywords) or any(k in description for k in login_keywords)
        is_redirect = any(k in evidence for k in redirect_keywords) or any(k in description for k in redirect_keywords)
        is_auth_gate = any(k in evidence for k in auth_keywords) or any(k in description for k in auth_keywords)

        # If the finding is about accessing a page that just redirects to login,
        # it's not a real vulnerability — just an auth gate
        title = finding.get("title", "").lower()
        is_auth_bypass_finding = "auth" in title and ("bypass" in title or "access" in title)

        return (is_login or is_redirect or is_auth_gate) and not is_auth_bypass_finding

    def _is_soft_404(self, finding: dict) -> bool:
        """Check if finding is likely a soft-404 (SPA catch-all)."""
        evidence = finding.get("evidence", "").lower()
        description = finding.get("description", "").lower()
        body = evidence + description

        spa_indicators = [
            "spa", "single page", "catch-all", "angular", "react", "vue",
            "next.js", "nuxt", "svelte",
        ]
        # If the finding explicitly mentions it's a soft-404 or SPA catch-all
        if "soft-404" in body or "soft 404" in body:
            return True
        if "catch-all" in body or "catch all" in body:
            return True
        # If status is 200 but body is very short (likely SPA shell)
        if "status: 200" in body and ("length: 0" in body or "length: <100" in body):
            return True

        return False

    def _is_expected_error(self, finding: dict) -> bool:
        """Check if finding is a JSON 4xx error response (expected behavior)."""
        evidence = finding.get("evidence", "").lower()
        title = finding.get("title", "").lower()

        # JSON 4xx responses are expected API behavior
        if any(k in evidence for k in ['"error"', '"message"', '"status": 4', '"code": 4']):
            if any(k in evidence for k in ['"not found"', '"forbidden"', '"unauthorized"', '"bad request"']):
                return True

        # "Possible IDOR" findings that return 403/401 are expected
        if "idor" in title and ("403" in evidence or "401" in evidence):
            return True

        return False

    def _is_timing_noise(self, finding: dict) -> bool:
        """Check if timing-based finding has insufficient timing differential."""
        evidence = finding.get("evidence", "")
        # Check for timing differential less than 50ms
        import re
        timing_matches = re.findall(r'(\d+)\s*ms', evidence)
        if timing_matches:
            max_timing = max(int(t) for t in timing_matches)
            if max_timing < 50:
                return True
        return False

    def _has_concrete_evidence(self, finding: dict) -> bool:
        """Check if finding has concrete evidence (not just speculation)."""
        evidence = finding.get("evidence", "")
        # Findings without concrete evidence references
        concrete_indicators = [
            "status:", "length:", "payload:", "response:",
            "header:", "cookie:", "redirect:", "200", "403", "500",
        ]
        return any(ind in evidence.lower() for ind in concrete_indicators)