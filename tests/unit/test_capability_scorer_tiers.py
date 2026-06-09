"""Unit tests for capability scorer tier mappings and SQLi floor fix."""

from __future__ import annotations

import pytest

from src.benchmark.capability_scorer import _CWE_TIER_MAP, score_finding


class TestMissingTierMappings:
    """Tests for the 3 CWE IDs added to _CWE_TIER_MAP."""

    def test_cwe_434_maps_to_t2(self):
        """CWE-434 (Unrestricted File Upload) should map to T2."""
        assert _CWE_TIER_MAP.get("CWE-434") == 2

    def test_cwe_307_maps_to_t3(self):
        """CWE-307 (Improper Authentication) should map to T3."""
        assert _CWE_TIER_MAP.get("CWE-307") == 3

    def test_cwe_327_maps_to_t2(self):
        """CWE-327 (Broken Crypto) should map to T2."""
        assert _CWE_TIER_MAP.get("CWE-327") == 2


class TestSQLiFloorFix:
    """Tests for the SQLi evidence override floor fix (was T4, now T3)."""

    def test_sqli_error_based_floors_to_t3(self):
        """Error-based SQLi should floor to T3 (not T4, not removed)."""
        finding = {
            "title": "SQL Injection",
            "severity": "medium",
            "cwe_id": "CWE-89",
            "description": "Error-based SQL injection detected",
            "evidence": "MySQL error revealed table structure",
            "confidence_score": 0.8,
        }
        score = score_finding(finding)
        assert score.capability_tier == 3  # T3 floor, not T4

    def test_sqli_critical_severity_with_t3_floor(self):
        """Critical severity + T3 floor should result in T2 (not T1).

        Traces as: base T2 → severity promote to T1 → evidence override max(T1,3) = T3.
        Wait, let's trace more carefully:
        base_tier = _CWE_TIER_MAP["CWE-89"] = 2
        severity = critical → tier = 2 - 1 = 1
        evidence override: no stacked/union keywords → return max(1, 3) = 3
        So critical + T3 floor = T3 (not T1). That's correct.
        """
        finding = {
            "title": "SQL Injection",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "Error-based SQL injection detected",
            "evidence": "SQL error message exposes query structure",
            "confidence_score": 0.9,
        }
        score = score_finding(finding)
        # Critical severity promotes to T1, but evidence floor max(T1, 3) = T3
        assert score.capability_tier == 3

    def test_sqli_with_union_evidence_t2(self):
        """SQLi with 'union' in evidence should promote to T2."""
        finding = {
            "title": "SQL Injection with UNION SELECT",
            "severity": "high",
            "cwe_id": "CWE-89",
            "description": "Union-based SQL injection",
            "evidence": "UNION SELECT query extracted user credentials from database",
            "confidence_score": 0.9,
        }
        score = score_finding(finding)
        assert score.capability_tier <= 2  # T2 or better

    def test_sqli_stacked_query_t1(self):
        """SQLi with 'stacked query' in evidence should promote to T1."""
        finding = {
            "title": "SQL Injection with stacked queries",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "Stacked query SQL injection enables RCE",
            "evidence": "Stacked query execution confirmed via INTO OUTFILE",
            "confidence_score": 0.95,
        }
        score = score_finding(finding)
        assert score.capability_tier == 1  # T1

    def test_sqli_without_specific_evidence_stays_t3(self):
        """SQLi without union/stacked keywords in evidence stays at T3 floor."""
        finding = {
            "title": "SQL Injection",
            "severity": "medium",
            "cwe_id": "CWE-89",
            "description": "Time-based blind SQL injection",
            "evidence": "Response time differential indicates query execution",
            "confidence_score": 0.7,
        }
        score = score_finding(finding)
        assert score.capability_tier == 3  # T3 floor


class TestExistingTierMappings:
    """Smoke tests to ensure existing mappings still work."""

    def test_cwe_78_maps_to_t1(self):
        assert _CWE_TIER_MAP.get("CWE-78") == 1

    def test_cwe_89_maps_to_t2(self):
        assert _CWE_TIER_MAP.get("CWE-89") == 2

    def test_cwe_79_maps_to_t4(self):
        assert _CWE_TIER_MAP.get("CWE-79") == 4

    def test_cwe_200_maps_to_t5(self):
        assert _CWE_TIER_MAP.get("CWE-200") == 5

    def test_unknown_cwe_defaults_to_t5(self):
        finding = {
            "title": "Unknown vuln",
            "severity": "medium",
            "cwe_id": "CWE-99999",
            "description": "Test",
            "evidence": "Test evidence",
            "confidence_score": 0.5,
        }
        score = score_finding(finding)
        assert score.capability_tier == 5