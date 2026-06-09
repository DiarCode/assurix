"""Unit tests for scripts/baseline_gate.py.

Per plan §6.4: the gate enforces zero new failures and no test-count regression.
These tests exercise the gate's compare() logic with mock JUnit XMLs that
cover the 5 named scenarios:
  1. Same-failures  → PASS (no new failures introduced)
  2. New-failure    → FAIL (a previously-passing test now fails)
  3. Flake-passes   → PASS with WARN (known flake now passes — not a regression)
  4. Flake-drift    → PASS with WARN (flake set shrinks)
  5. Empty-results  → FAIL (test count regression)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure scripts/ is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import baseline_gate  # noqa: E402  (import after sys.path mutation)


def _make_nodeid(i: int, status: str = "passed") -> dict[str, dict[str, str]]:
    return {f"tests/test_x.py::test_{i}": {"status": status, "message": ""}}


def _make_baseline_xml(tmp_path: Path, failures: list[str] | None = None,
                        filename: str = "junit.xml") -> Path:
    """Write a minimal JUnit XML to a temp file.

    `failures` is a list of test names (e.g. "test_3") that should be marked
    as failing. Each name in `failures` REPLACES the matching passing
    testcase rather than adding a duplicate.
    `filename` allows two JUnit files to coexist in the same tmp_path.
    """
    failures = failures or []
    failing_names = set(failures)
    body = '<?xml version="1.0"?>\n<testsuite>\n'
    for i in range(10):
        name = f"test_{i}"
        if name in failing_names:
            body += f'  <testcase classname="tests.test_x" name="{name}"><failure>{name} failed</failure></testcase>\n'
        else:
            body += f'  <testcase classname="tests.test_x" name="{name}"/>\n'
    body += "</testsuite>\n"
    p = tmp_path / filename
    p.write_text(body)
    return p


def test_same_failures_passes(tmp_path: Path) -> None:
    """Identical baseline = current → PASS."""
    baseline_path = _make_baseline_xml(tmp_path)
    passes, violations = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(baseline_path),
        known_flakes=set(),
        known_failures=set(),
    )
    assert passes is True
    assert violations == []


def test_new_failure_detected(tmp_path: Path) -> None:
    """A test that passed in baseline now fails in current → gate FAILS."""
    baseline_path = _make_baseline_xml(tmp_path, filename="baseline.xml")
    current_path = _make_baseline_xml(tmp_path, filename="current.xml", failures=["test_3"])
    passes, violations = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(current_path),
        known_flakes=set(),
        known_failures=set(),
    )
    assert passes is False
    assert any("test_3" in v and "NEW_FAILURE" in v for v in violations)
    # The failing test's nodeid uses dot-classname::name per JUnit XML format
    assert any("tests.test_x::test_3" in v for v in violations)


def test_flake_passes_is_warning_not_violation(tmp_path: Path) -> None:
    """A test listed as a known flake now PASSES → not a violation."""
    baseline_path = _make_baseline_xml(tmp_path, filename="baseline.xml", failures=["test_5"])
    current_path = _make_baseline_xml(tmp_path, filename="current.xml")  # test_5 now passes
    passes, violations = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(current_path),
        known_flakes={"tests/test_x.py::test_5"},
        known_failures=set(),
    )
    # baseline had test_5 as a failure; the gate ignores it (not a NEW failure)
    assert passes is True
    assert violations == []


def test_flake_drift_passes(tmp_path: Path) -> None:
    """The known_flake set shrinks → not a regression (flake was fixed)."""
    baseline_path = _make_baseline_xml(tmp_path, filename="baseline.xml")
    current_path = _make_baseline_xml(tmp_path, filename="current.xml")
    passes, violations = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(current_path),
        known_flakes={"tests/test_x.py::test_already_gone"},  # not in current
        known_failures=set(),
    )
    assert passes is True
    assert violations == []


def test_test_count_regression_detected(tmp_path: Path) -> None:
    """Current has fewer tests than baseline → FAIL with TEST_COUNT_REGRESSION."""
    baseline_path = _make_baseline_xml(tmp_path, filename="baseline.xml")
    # Current has only 5 tests
    body = '<?xml version="1.0"?>\n<testsuite>\n'
    for i in range(5):
        body += f'  <testcase classname="tests.test_x" name="test_{i}"/>\n'
    body += "</testsuite>\n"
    current_path = tmp_path / "junit-smaller.xml"
    current_path.write_text(body)

    passes, violations = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(current_path),
        known_flakes=set(),
        known_failures=set(),
    )
    assert passes is False
    assert any("TEST_COUNT_REGRESSION" in v for v in violations)


def test_missing_junit_exits_with_2(tmp_path: Path) -> None:
    """A non-existent baseline path → exit code 2 (invocation error)."""
    import subprocess
    result = subprocess.run(
        [
            sys.executable, str(SCRIPTS_DIR / "baseline_gate.py"),
            "--baseline", str(tmp_path / "does-not-exist.xml"),
            "--current", str(tmp_path / "also-missing.xml"),
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 2


def test_malformed_xml_exits_with_2(tmp_path: Path) -> None:
    """A malformed JUnit XML → exit code 2 (invocation error)."""
    bad = tmp_path / "bad.xml"
    bad.write_text("<?xml version='1.0'?><not closed")
    import subprocess
    result = subprocess.run(
        [
            sys.executable, str(SCRIPTS_DIR / "baseline_gate.py"),
            "--baseline", str(bad),
            "--current", str(bad),
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 2


def test_known_failure_exemption(tmp_path: Path) -> None:
    """A test in known_failures is exempt from the new-failure check.

    The classic case: the captured baseline XML happens to show the
    test passing (flake), but the team has documented it as a known
    failure. The gate must not flag it as a new regression.
    """
    baseline_path = _make_baseline_xml(tmp_path, filename="baseline.xml")
    # test_3 was passing in baseline, now failing in current
    current_path = _make_baseline_xml(tmp_path, filename="current.xml", failures=["test_3"])

    # Without the exemption: this is a NEW_FAILURE.
    passes, violations = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(current_path),
        known_flakes=set(),
        known_failures=set(),
    )
    assert passes is False
    assert any("test_3" in v for v in violations)

    # With the exemption (in JUnit dotted form): the violation is suppressed.
    passes2, violations2 = baseline_gate.compare(
        baseline=baseline_gate.parse_junit(baseline_path),
        current=baseline_gate.parse_junit(current_path),
        known_flakes=set(),
        known_failures={"tests.test_x::test_3"},
    )
    assert passes2 is True
    assert violations2 == []


def test_load_known_failures_normalizes_nodeid_forms(tmp_path: Path) -> None:
    """load_known_failures should accept both slash and dotted nodeid forms."""
    import json
    bj = tmp_path / "baseline.json"
    bj.write_text(json.dumps({
        "known_failures": [
            {"nodeid": "tests/unit/test_x.py::test_y"},
            {"nodeid": "tests.unit.test_z::test_w"},  # already dotted
        ],
    }))

    result = baseline_gate.load_known_failures(bj)
    # Both forms are in the set; the slash form gets normalised to dotted.
    assert "tests/unit/test_x.py::test_y" in result
    assert "tests.unit.test_x::test_y" in result
    assert "tests.unit.test_z::test_w" in result
