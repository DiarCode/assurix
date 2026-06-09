"""W1-C regression: the executive summary and the raw analyst notes
must render as two distinct sections in the MD report.

Defect 5 was that the reporter passed the LLM's
``executive_summary`` AS the ``analysis_notes`` argument to
``generate_report``, which made the LLM's narrative appear twice in
the rendered report (once at the top, once at the bottom in the
"Analyst notes" block). The fix:

- ``generate_report`` accepts a new keyword-only
  ``raw_analysis_notes`` parameter; the legacy ``analysis_notes``
  kwarg stays for API stability.
- The reporter passes the raw notes (from the previous agent's
  ``analysis_notes`` field) as ``raw_analysis_notes`` — NOT the LLM's
  ``executive_summary``.
- The MD template renders raw notes in a dedicated ``## Analyst
  Notes`` section after the methodology, with no overlap with the
  executive summary above.

These tests assert the two sections have distinct content and that
the executive summary is the LLM's narrative (when supplied), not
duplicated raw notes.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_cwd():
    """chdir to a temp dir so the report lands in a fresh data/reports/."""
    original = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            try:
                os.chdir(original)
            except FileNotFoundError:
                os.chdir(str(Path.home()))


def _make_finding(title: str, severity: str = "high", conf: float = 0.8) -> dict:
    return {
        "title": title,
        "severity": severity,
        "confidence_score": conf,
        "description": "test",
        "source_agent": "test",
    }


def test_executive_summary_and_analyst_notes_are_distinct(temp_cwd) -> None:
    """The LLM narrative goes into the executive summary; the raw
    notes go into their own section. They must not be the same
    string."""
    from src.reporting.md_report import generate_report

    llm_narrative = {
        "executive_summary": "LLM-GENERATED-NARRATIVE: this came from the LLM call.",
        "risk_assessment": "high",
        "key_findings": ["finding-1", "finding-2"],
    }
    raw_notes = "RAW-ANALYST-NOTES: this came from the prior agent's analysis_notes field."

    path = generate_report(
        engagement_id="11111111-1111-1111-1111-111111111111",
        target_url="https://example.com",
        findings=[_make_finding("XSS")],
        raw_analysis_notes=raw_notes,
        llm_narrative=llm_narrative,
    )
    md = path.read_text(encoding="utf-8")

    # The LLM narrative appears under the executive summary header.
    assert "## Executive Summary" in md
    assert "LLM-GENERATED-NARRATIVE" in md

    # The raw notes appear under the analyst notes header.
    assert "## Analyst Notes" in md
    assert "RAW-ANALYST-NOTES" in md

    # The two must not be conflated: the executive summary should not
    # contain the raw-notes marker, and the analyst notes section
    # should not contain the LLM marker.
    exec_section = md.split("## Analyst Notes")[0]
    analyst_section = md.split("## Analyst Notes", 1)[1]
    assert "RAW-ANALYST-NOTES" not in exec_section
    assert "LLM-GENERATED-NARRATIVE" not in analyst_section


def test_no_analyst_notes_section_when_raw_notes_empty(temp_cwd) -> None:
    """If the previous agent produced no analysis_notes, the dedicated
    section should be absent — not render an empty header."""
    from src.reporting.md_report import generate_report

    path = generate_report(
        engagement_id="22222222-2222-2222-2222-222222222222",
        target_url="https://example.com",
        findings=[_make_finding("XSS")],
        raw_analysis_notes="",
    )
    md = path.read_text(encoding="utf-8")
    assert "## Analyst Notes" not in md
    # The deterministic fallback executive summary should still render.
    assert "## Executive Summary" in md


def test_legacy_analysis_notes_kwarg_does_not_pollute_analyst_section(temp_cwd) -> None:
    """The legacy ``analysis_notes`` kwarg is kept for API stability
    but no longer drives the dedicated section — only
    ``raw_analysis_notes`` does. Passing the LLM summary via the
    legacy kwarg should NOT cause it to appear in the analyst
    section."""
    from src.reporting.md_report import generate_report

    path = generate_report(
        engagement_id="33333333-3333-3333-3333-333333333333",
        target_url="https://example.com",
        findings=[_make_finding("XSS")],
        analysis_notes="LEGACY-NOTES-VIA-OLD-KWARG",
        raw_analysis_notes="",
    )
    md = path.read_text(encoding="utf-8")
    # The legacy kwarg is accepted-and-ignored; the analyst section is
    # absent because raw_analysis_notes is empty.
    assert "## Analyst Notes" not in md


def test_zero_findings_still_renders_distinct_sections(temp_cwd) -> None:
    """The zero-findings deterministic fallback must coexist with the
    raw notes section when the LLM narrative is None."""
    from src.reporting.md_report import generate_report

    path = generate_report(
        engagement_id="44444444-4444-4444-4444-444444444444",
        target_url="https://example.com",
        findings=[],
        raw_analysis_notes="Methodology log: recon BFS visited 12 pages.",
        llm_narrative=None,
    )
    md = path.read_text(encoding="utf-8")
    assert "## Executive Summary" in md
    assert "No exploitable vulnerabilities were confirmed" in md
    assert "## Analyst Notes" in md
    assert "Methodology log: recon BFS visited 12 pages." in md
