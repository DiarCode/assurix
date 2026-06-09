#!/usr/bin/env bash
# Test baseline gate — CI shell wrapper.
# Per plan §6.4: this script MUST land before any Week 1 acceptance criteria
# are evaluated. It captures the current pytest JUnit XML and compares it
# against the captured baseline.
#
# Usage: scripts/test_baseline_gate.sh
# Exits non-zero on gate failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BASELINE_XML="ops/test-baseline/baseline-2026-06-03.xml"
BASELINE_JSON="ops/test-baseline/baseline.json"
CURRENT_XML="/tmp/pytest-current.xml"

if [[ ! -f "$BASELINE_XML" ]]; then
    echo "ERROR: baseline JUnit XML not found at $BASELINE_XML"
    echo "Day-1 punch-list step 1 must run: python -m pytest --junitxml=$BASELINE_XML tests/"
    exit 2
fi

if [[ ! -f "$BASELINE_JSON" ]]; then
    echo "ERROR: baseline.json not found at $BASELINE_JSON"
    exit 2
fi

echo "[test_baseline_gate] running pytest with JUnit XML capture..."
python -m pytest --junitxml="$CURRENT_XML" tests/ 2>&1 | tail -20

echo "[test_baseline_gate] invoking gate logic..."
python scripts/baseline_gate.py \
    --baseline "$BASELINE_XML" \
    --current "$CURRENT_XML" \
    --known-flakes-json "$BASELINE_JSON"
