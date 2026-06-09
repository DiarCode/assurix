"""Unit tests for CyberArena ground truth loading and structure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.benchmark.registry import get_suite, load_ground_truth

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "benchmarks"


class TestCyberArenaSuite:
    """Tests for the cyberarena benchmark suite registration."""

    def test_cyberarena_suite_exists(self):
        suite = get_suite("cyberarena")
        assert suite is not None
        assert suite.name == "cyberarena"

    def test_ground_truth_file_loads(self):
        test_cases = load_ground_truth("cyberarena")
        assert isinstance(test_cases, list)
        assert len(test_cases) >= 25

    def test_ground_truth_has_all_three_targets(self):
        test_cases = load_ground_truth("cyberarena")
        target_names = {tc.get("target_name") for tc in test_cases}
        assert "dvwa" in target_names
        assert "juice-shop" in target_names
        assert "webgoat" in target_names

    def test_ground_truth_endpoint_format(self):
        test_cases = load_ground_truth("cyberarena")
        for tc in test_cases:
            assert "endpoint" in tc, f"Missing 'endpoint' in {tc.get('id')}"
            assert "parameter" in tc, f"Missing 'parameter' in {tc.get('id')}"
            assert "target_name" in tc, f"Missing 'target_name' in {tc.get('id')}"

    def test_ground_truth_cwe_ids_valid(self):
        import re
        test_cases = load_ground_truth("cyberarena")
        cwe_pattern = re.compile(r"^CWE-\d+$")
        for tc in test_cases:
            for ef in tc.get("expected_findings", []):
                cwe = ef.get("cwe_id", "")
                assert cwe_pattern.match(cwe), f"Invalid CWE ID '{cwe}' in {tc.get('id')}"

    def test_ground_truth_setup_required_dvwa(self):
        test_cases = load_ground_truth("cyberarena")
        dvwa_cases = [tc for tc in test_cases if tc.get("target_name") == "dvwa"]
        for tc in dvwa_cases:
            setup = tc.get("setup_required", [])
            assert "dvwa_auth" in setup, f"DVWA entry {tc.get('id')} missing 'dvwa_auth' in setup_required"
            assert "dvwa_security_low" in setup, f"DVWA entry {tc.get('id')} missing 'dvwa_security_low' in setup_required"


class TestCyberArenaSpecificEntries:
    """Tests for specific ground truth entries mentioned in acceptance criteria."""

    def test_dvwa_xss_r_endpoint_verified(self):
        test_cases = load_ground_truth("cyberarena")
        xss_r = [tc for tc in test_cases if tc.get("id") == "dvwa-xss-r-001"]
        assert len(xss_r) == 1
        tc = xss_r[0]
        assert tc["endpoint"] == "/vulnerabilities/xss_r/"
        assert any(ef.get("cwe_id") == "CWE-79" for ef in tc.get("expected_findings", []))

    def test_js_2fa_bypass_id_matches_cwe(self):
        test_cases = load_ground_truth("cyberarena")
        twofa = [tc for tc in test_cases if tc.get("id") == "js-2fa-bypass-001"]
        assert len(twofa) == 1
        tc = twofa[0]
        assert any(ef.get("cwe_id") == "CWE-287" for ef in tc.get("expected_findings", []))
        # Should NOT be CWE-918 (SSRF)
        assert not any(ef.get("cwe_id") == "CWE-918" for ef in tc.get("expected_findings", []))

    def test_js_jwt_forge_endpoint_correct(self):
        test_cases = load_ground_truth("cyberarena")
        jwt = [tc for tc in test_cases if tc.get("id") == "js-jwt-forge-001"]
        assert len(jwt) == 1
        tc = jwt[0]
        assert "/api/User/" in tc["endpoint"]