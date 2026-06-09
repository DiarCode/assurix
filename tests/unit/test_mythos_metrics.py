"""Unit tests for MythosMetrics computation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.benchmark.capability_scorer import MythosMetrics, compute_mythos_metrics


def _make_hypothesis(status: str = "pending", cwe_id: str = "CWE-89"):
    """Create a mock Hypothesis ORM object."""
    h = MagicMock()
    h.status = status
    h.cwe_id = cwe_id
    return h


def _make_finding(
    finding_id: str = "f1",
    severity: str = "high",
    cwe_id: str = "CWE-89",
    source_agent: str = "pentester",
    description: str = "test finding",
):
    """Create a mock Finding ORM object."""
    f = MagicMock()
    f.id = finding_id
    f.severity = severity
    f.cwe_id = cwe_id
    f.source_agent = source_agent
    f.description = description
    f.finding_metadata = {}
    return f


def _make_provenance_link(finding_id: str = "f1", hypothesis_id: str = "h1"):
    """Create a mock ProvenanceLink ORM object."""
    pl = MagicMock()
    pl.finding_id = finding_id
    pl.hypothesis_id = hypothesis_id
    return pl


# --- Hypothesis hit rate ---


def test_hypothesis_hit_rate_zero_hypotheses():
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=[], provenance_links=[],
    )
    assert metrics.hypothesis_hit_rate == 0.0
    assert metrics.hit_rate_pass is False


def test_hypothesis_hit_rate_all_confirmed():
    hypotheses = [_make_hypothesis("confirmed"), _make_hypothesis("confirmed")]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=[], provenance_links=[],
    )
    assert metrics.hypothesis_hit_rate == 1.0
    assert metrics.hit_rate_pass is True


def test_hypothesis_hit_rate_half_confirmed():
    hypotheses = [_make_hypothesis("confirmed"), _make_hypothesis("falsified")]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=[], provenance_links=[],
    )
    assert metrics.hypothesis_hit_rate == 0.5
    assert metrics.hit_rate_pass is True  # >= 0.50


def test_hypothesis_hit_rate_below_threshold():
    hypotheses = [
        _make_hypothesis("confirmed"),
        _make_hypothesis("falsified"),
        _make_hypothesis("falsified"),
    ]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=[], provenance_links=[],
    )
    assert metrics.hypothesis_hit_rate < 0.50
    assert metrics.hit_rate_pass is False


# --- Provenance chain completeness ---


def test_provenance_chain_all_complete():
    findings = [_make_finding("f1"), _make_finding("f2")]
    links = [_make_provenance_link("f1"), _make_provenance_link("f2")]
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=findings, provenance_links=links,
    )
    assert metrics.provenance_chain_completeness == 1.0
    assert metrics.provenance_pass is True


def test_provenance_chain_missing_link():
    findings = [_make_finding("f1"), _make_finding("f2")]
    links = [_make_provenance_link("f1")]  # f2 has no link
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=findings, provenance_links=links,
    )
    assert metrics.provenance_chain_completeness < 1.0
    assert metrics.provenance_pass is False


def test_provenance_chain_zero_confirmed_findings():
    """Vacuously true when no confirmed findings exist."""
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=[], provenance_links=[],
    )
    assert metrics.provenance_chain_completeness == 1.0
    assert metrics.provenance_pass is True


# --- Novel findings vs linear ---


def test_novel_findings_vs_linear_count():
    linear_findings = [
        {"cwe_id": "CWE-89", "description": "/api/login", "source_agent": "pentester"},
        {"cwe_id": "CWE-79", "description": "/search", "source_agent": "pentester"},
    ]
    rl_findings = [
        _make_finding("f1", cwe_id="CWE-89", description="/api/login"),  # duplicate
        _make_finding("f2", cwe_id="CWE-22", description="/ftp/"),  # novel
        _make_finding("f3", cwe_id="CWE-327", description="/jwt"),  # novel
    ]
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=rl_findings, provenance_links=[],
        linear_findings=linear_findings,
    )
    assert metrics.novel_findings_vs_linear >= 2
    assert metrics.novel_pass is True


def test_novel_findings_vs_linear_none():
    linear_findings = [
        {"cwe_id": "CWE-89", "description": "/api/login", "source_agent": "pentester"},
    ]
    rl_findings = [
        _make_finding("f1", cwe_id="CWE-89", description="/api/login"),  # same
    ]
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=rl_findings, provenance_links=[],
        linear_findings=linear_findings,
    )
    assert metrics.novel_findings_vs_linear == 0
    assert metrics.novel_pass is False


def test_novel_findings_vs_linear_no_linear_baseline():
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=[], provenance_links=[],
        linear_findings=None,
    )
    assert metrics.novel_findings_vs_linear == 0
    assert metrics.novel_pass is False


# --- Reflection quality ---


def test_reflection_quality_pass():
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=[], provenance_links=[],
        research_iterations=3,  # < 5
    )
    # confirmed_count is 0, so reflection_pass should be False
    # Let's test with confirmed hypotheses
    hypotheses = [_make_hypothesis("confirmed"), _make_hypothesis("confirmed")]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=[], provenance_links=[],
        research_iterations=3,
    )
    assert metrics.confirmed_hypotheses == 2
    assert metrics.reflection_pass is True


def test_reflection_quality_too_many_iterations():
    hypotheses = [_make_hypothesis("confirmed"), _make_hypothesis("confirmed")]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=[], provenance_links=[],
        research_iterations=6,
    )
    assert metrics.reflection_pass is False


def test_reflection_quality_too_few_confirmed():
    hypotheses = [_make_hypothesis("confirmed")]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=[], provenance_links=[],
        research_iterations=3,
    )
    assert metrics.confirmed_hypotheses == 1
    assert metrics.reflection_pass is False


# --- Overall pass ---


def test_overall_pass_all_pass():
    # Set up conditions where all pass
    hypotheses = [_make_hypothesis("confirmed"), _make_hypothesis("confirmed")]
    findings = [_make_finding("f1", severity="high")]
    links = [_make_provenance_link("f1")]
    linear_findings = [{"cwe_id": "CWE-200", "description": "different", "source_agent": "pentester"}]
    metrics = compute_mythos_metrics(
        hypotheses=hypotheses, findings=findings, provenance_links=links,
        linear_findings=linear_findings, research_iterations=3,
    )
    # Check individual passes
    assert metrics.hit_rate_pass is True  # 2/2 = 1.0
    assert metrics.provenance_pass is True
    assert metrics.novel_pass is True  # finding not in linear
    assert metrics.reflection_pass is True  # 3 iter, 2 confirmed
    assert metrics.overall_pass is True


def test_overall_pass_one_fail():
    # 0 hypotheses -> hit_rate_pass = False
    metrics = compute_mythos_metrics(
        hypotheses=[], findings=[], provenance_links=[],
        research_iterations=0,
    )
    assert metrics.hit_rate_pass is False
    assert metrics.overall_pass is False