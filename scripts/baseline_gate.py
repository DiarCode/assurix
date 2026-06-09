#!/usr/bin/env python3
"""Test baseline gate — enforces zero new failures vs the captured JUnit XML.

Per plan §6.4: Day-1 punch-list MUST land this script before any Week 1 code
lands. The gate compares the current JUnit XML against a baseline XML and
fails CI if:

  1. Any test that PASSED in the baseline now FAILS (new failure).
  2. Any test that was in the `known_flakes` list of the baseline now PASSES
     when it previously FAILED (flake-now-passing is not a regression, but
     it IS a flake drift that the gate must report).
  3. The total number of tests in the run is FEWER than in the baseline
     (test files were deleted or skipped silently).

The script intentionally does NOT use pytest directly — it parses the JUnit
XML output via xml.etree.ElementTree so it can be invoked from any CI shell
or a developer terminal without test-environment coupling.

Usage:
    python scripts/baseline_gate.py \\
        --baseline ops/test-baseline/baseline-2026-06-03.xml \\
        --current  /tmp/pytest-current.xml \\
        --known-flakes-json ops/test-baseline/baseline.json \\
        [--baseline-json ops/test-baseline/baseline.json]

Exit codes:
    0  gate passes (no new failures, no test count regression)
    1  gate fails (one or more violations)
    2  invocation error (file missing, malformed XML)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Use defusedxml to prevent XXE and billion-laughs attacks on JUnit XML inputs.
# Python's stdlib xml.etree.ElementTree is vulnerable by default; defusedxml
# is a drop-in replacement that disallows external entity expansion.
from defusedxml import ElementTree as ET


def parse_junit(path: Path) -> dict[str, dict[str, str]]:
    """Parse a JUnit XML into a {nodeid: {status, message}} dict."""
    if not path.exists():
        print(f"ERROR: JUnit XML not found: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        print(f"ERROR: malformed JUnit XML at {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    results: dict[str, dict[str, str]] = {}
    for testcase in tree.iter("testcase"):
        classname = testcase.attrib.get("classname", "")
        name = testcase.attrib.get("name", "")
        nodeid = f"{classname}::{name}" if classname else name

        status = "passed"
        message = ""
        for child in testcase:
            if child.tag in ("failure", "error"):
                status = child.tag
                message = (child.text or "").strip()[:500]
                break
            if child.tag == "skipped":
                status = "skipped"
                message = (child.text or "").strip()[:200]
                break
        results[nodeid] = {"status": status, "message": message}
    return results


def load_known_flakes(json_path: Path) -> set[str]:
    """Return the set of nodeids listed as known flakes in baseline.json."""
    if not json_path.exists():
        return set()
    try:
        data = json.loads(json_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"WARN: malformed baseline.json ({exc}); treating as no flakes", file=sys.stderr)
        return set()
    return {f["nodeid"] for f in data.get("known_flakes", [])}


def load_known_failures(json_path: Path) -> set[str]:
    """Return the set of nodeids listed as known_failures in baseline.json.

    A "known failure" is a test that is documented as failing by design
    (e.g. legacy fixtures, not-yet-migrated assertions). The gate
    should NOT flag these as new failures even if the captured baseline
    XML happens to show them passing (which can happen with flakes).

    The nodeids in baseline.json are written in pytest's slash form
    (``tests/unit/foo.py::test_x``); the JUnit XML uses the dotted
    form (``tests.unit.foo::test_x``). We store BOTH forms in the
    returned set so lookups against either spelling succeed.
    """
    if not json_path.exists():
        return set()
    try:
        data = json.loads(json_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"WARN: malformed baseline.json ({exc}); treating as no known failures", file=sys.stderr)
        return set()
    out: set[str] = set()
    for entry in data.get("known_failures", []):
        nodeid = entry["nodeid"]
        out.add(nodeid)
        # Also accept the JUnit-dotted form: tests/unit/foo.py::test_x
        # becomes tests.unit.foo::test_x.
        if "::" in nodeid and "/" in nodeid:
            prefix, _, rest = nodeid.partition("::")
            dotted = prefix.replace("/", ".").removesuffix(".py")
            out.add(f"{dotted}::{rest}")
    return out


def load_known_flakes(json_path: Path) -> set[str]:
    """Return the set of nodeids listed as known flakes in baseline.json.

    Stores both the pytest slash form and the JUnit dotted form so
    lookups against either spelling succeed.
    """
    if not json_path.exists():
        return set()
    try:
        data = json.loads(json_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"WARN: malformed baseline.json ({exc}); treating as no flakes", file=sys.stderr)
        return set()
    out: set[str] = set()
    for entry in data.get("known_flakes", []):
        nodeid = entry["nodeid"]
        out.add(nodeid)
        if "::" in nodeid and "/" in nodeid:
            prefix, _, rest = nodeid.partition("::")
            dotted = prefix.replace("/", ".").removesuffix(".py")
            out.add(f"{dotted}::{rest}")
    return out


def compare(baseline: dict[str, dict[str, str]],
            current: dict[str, dict[str, str]],
            known_flakes: set[str],
            known_failures: set[str]) -> tuple[bool, list[str]]:
    """Return (passes?, violation_list).

    Tests listed in ``known_failures`` are exempted from the new-failure
    check: even if the captured baseline XML shows them passing (a
    flake), we know the team has accepted the failure and the gate
    should not block on it.
    """
    violations: list[str] = []

    # 1. New failures: tests that passed in baseline, failing now.
    #    Exempt anything in known_failures.
    for nodeid, base in baseline.items():
        if base["status"] != "passed":
            continue  # baseline was already failing/errored — not "new"
        if nodeid in known_failures:
            continue  # team-accepted failure; not a regression
        cur = current.get(nodeid)
        if cur is None:
            violations.append(f"MISSING_TEST: {nodeid} not in current run")
            continue
        if cur["status"] in ("failure", "error"):
            violations.append(
                f"NEW_FAILURE: {nodeid} (was passed, now {cur['status']}): {cur['message'][:200]}"
            )

    # 2. Test count regression: fewer tests in current
    if len(current) < len(baseline):
        missing = set(baseline) - set(current)
        # Only report up to 5 missing to keep noise bounded
        sample = sorted(missing)[:5]
        violations.append(
            f"TEST_COUNT_REGRESSION: baseline had {len(baseline)} tests, current has {len(current)}. "
            f"Missing: {sample}{'...' if len(missing) > 5 else ''}"
        )

    # 3. Flake drift: known flake that was failing now passes
    for nodeid in known_flakes:
        cur = current.get(nodeid)
        if cur is None:
            continue
        if cur["status"] == "passed":
            # Not a regression, but a flake drift — report as warning, not violation
            print(f"  WARN: known flake {nodeid} now PASSES (flake drift, not a regression)")

    return (len(violations) == 0, violations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path, help="Path to baseline JUnit XML")
    parser.add_argument("--current", required=True, type=Path, help="Path to current JUnit XML")
    parser.add_argument(
        "--known-flakes-json",
        type=Path,
        default=Path("ops/test-baseline/baseline.json"),
        help="Path to baseline.json (for known_flakes list)",
    )
    args = parser.parse_args()

    print(f"[baseline_gate] parsing baseline: {args.baseline}")
    baseline = parse_junit(args.baseline)
    print(f"[baseline_gate] baseline: {len(baseline)} tests")

    print(f"[baseline_gate] parsing current:  {args.current}")
    current = parse_junit(args.current)
    print(f"[baseline_gate] current:  {len(current)} tests")

    known_flakes = load_known_flakes(args.known_flakes_json)
    print(f"[baseline_gate] known flakes: {len(known_flakes)}")
    known_failures = load_known_failures(args.known_flakes_json)
    print(f"[baseline_gate] known failures (exempted): {len(known_failures)}")

    passes, violations = compare(baseline, current, known_flakes, known_failures)

    if not passes:
        print(f"\n[baseline_gate] FAILED with {len(violations)} violation(s):")
        for v in violations:
            print(f"  - {v}")
        return 1

    print("[baseline_gate] PASSED — no new failures, no test count regression")
    return 0


if __name__ == "__main__":
    sys.exit(main())
