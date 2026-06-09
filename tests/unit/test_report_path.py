"""Report path: every report lands in data/reports/ with the canonical
filename pattern ``<timestamp>_<target>_<eng8>.md``, and a ``LATEST.md``
symlink always points at the most recent report.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_cwd():
    """chdir to a temp dir for the test, then always restore cwd on teardown.

    The reporter writes to ``data/reports/`` relative to the cwd. We need a
    clean temp dir so each test gets a fresh ``data/reports/`` and we don't
    pollute the repo. Restoring cwd in teardown prevents the chdir from
    leaking to sibling tests that read relative paths.
    """
    original = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            try:
                os.chdir(original)
            except FileNotFoundError:
                # original cwd no longer exists; fall back to a safe dir
                os.chdir(str(Path.home()))


def _make_finding(title: str, severity: str = "high", conf: float = 0.8) -> dict:
    return {
        "title": title,
        "severity": severity,
        "confidence_score": conf,
        "description": "test",
        "source_agent": "test",
    }


def test_report_lands_in_data_reports(temp_cwd) -> None:
    """Generated reports go to data/reports/, not data/artifacts/."""
    from src.reporting.md_report import generate_report

    p = generate_report(
        engagement_id="00000000-aaaa-bbbb-cccc-000000000001",
        target_url="https://example.com",
        findings=[_make_finding("XSS")],
    )
    assert p.parent.name == "reports"
    assert "data/reports" in str(p)
    assert "data/artifacts" not in str(p)
    assert p.exists()


def test_filename_pattern() -> None:
    """Filename is ``<YYYYMMDD_HHMMSS>_<target>_<eng8>.md``."""
    from src.reporting.md_report import _report_filename, generate_report
    from datetime import UTC, datetime

    fixed = datetime(2026, 6, 4, 14, 30, 0, tzinfo=UTC)
    name = _report_filename(
        "abcdef01-2345-6789-0123-456789012345",
        "https://admin.example.com/path",
        fixed,
    )
    # 20260604_143000_admin.example.com_path_abcdef01.md
    assert re.match(r"\d{8}_\d{6}_.+_[0-9a-f]{8}\.md$", name), f"Bad pattern: {name}"
    assert name.startswith("20260604_143000_")
    assert name.endswith("_abcdef01.md")


def test_sanitize_target() -> None:
    """Target URLs are sanitized to safe filename characters."""
    from src.reporting.md_report import _sanitize_target_for_filename

    cases = [
        ("https://admin.example.com", "admin.example.com"),
        ("https://admin.example.com/path?q=1", "admin.example.com_path_q_1"),
        ("http://localhost:8080/api/v1/users", "localhost_8080_api_v1_users"),
        ("", "unknown"),
        ("   ", "unknown"),
    ]
    for raw, expected in cases:
        assert _sanitize_target_for_filename(raw) == expected, f"{raw!r} -> {expected}"


def test_latest_symlink_updates(temp_cwd) -> None:
    """Each report write refreshes data/reports/LATEST.md to the new file."""
    from src.reporting.md_report import generate_report

    p1 = generate_report(
        engagement_id="00000000-0000-0000-0000-000000000001",
        target_url="https://x",
        findings=[],
    )
    latest = p1.parent / "LATEST.md"
    assert latest.is_symlink() or latest.exists()
    # Generate a second report; the symlink should now point at the new one
    p2 = generate_report(
        engagement_id="00000000-0000-0000-0000-000000000002",
        target_url="https://y",
        findings=[],
    )
    # After the second call, LATEST.md points at p2
    if latest.is_symlink():
        assert os.readlink(str(latest)) == p2.name


def test_zero_findings_writes_recon_report(temp_cwd) -> None:
    """A zero-finding scan still writes a report with the methodology section."""
    from src.reporting.md_report import generate_report

    p = generate_report(
        engagement_id="00000000-0000-0000-0000-000000000003",
        target_url="https://x",
        findings=[],
        surface={"technologies": ["nginx"], "endpoints": ["/login", "/api"]},
        methodology={
            "steps": [
                {
                    "phase": "Recon",
                    "timestamp": "2026-06-04T10:00:00Z",
                    "action": "Crawled 50 pages, mapped 12 endpoints",
                    "outcome": "Surface captured",
                },
            ],
        },
    )
    body = p.read_text()
    assert "No exploitable vulnerabilities" in body
    assert "Recon" in body
    assert "Crawled 50 pages" in body
    assert "nginx" in body


def test_strict_gate_downgrades_low_confidence(temp_cwd) -> None:
    """Findings below the strict gate confidence floor must be downgraded to info."""
    from src.reporting.md_report import generate_report

    p = generate_report(
        engagement_id="00000000-0000-0000-0000-000000000004",
        target_url="https://x",
        findings=[
            _make_finding("Real high", conf=0.7),
            _make_finding("Unverified high", conf=0.1),
        ],
    )
    body = p.read_text()
    # The unverified finding (conf=0.1) is below the 0.30 floor and
    # must show the strict-gate downgrade marker in the rendered table.
    assert "Downgraded" in body, (
        f"Expected 'Downgraded' marker in body; got:\n{body}"
    )


def test_llm_narrative_renders_when_present(temp_cwd) -> None:
    """An LLM narrative dict is rendered into the executive summary."""
    from src.reporting.md_report import generate_report

    p = generate_report(
        engagement_id="00000000-0000-0000-0000-000000000005",
        target_url="https://x",
        findings=[],
        llm_narrative={
            "executive_summary": "LLM says: target is clean.",
            "risk_assessment": "LOW",
            "key_findings": ["Nothing"],
        },
    )
    body = p.read_text()
    assert "LLM says: target is clean." in body
