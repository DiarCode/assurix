"""Unit tests for the strict finding gate and dedup logic.

Verifies plan §Step 4 + §Acceptance Criteria:

* ``strict_finding_gate=True`` (default) downgrades findings missing
  (PoC, request/response, confidence >= 0.30) to ``info``.
* Zero-confidence findings get dropped/downgraded.
* ``strict_finding_gate=False`` preserves the legacy "DO NOT downgrade"
  behavior the existing test suite depends on — REGRESSION GUARD.
* Dedup collapses duplicates by ``dedup_key`` to a single entry, keeping
  the highest-confidence match.
* Dedup key generation handles missing URL gracefully (still produces a
  stable key, still groups correctly).

The tests construct a small ``Finding`` ORM object inline (no DB
needed) using the same approach as ``test_phase2_validation_provenance``.
"""

from __future__ import annotations

import hashlib
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from src.reporting.json_report import (
    JSONReportGenerator,
    STRICT_GATE_MIN_CONFIDENCE,
    STRICT_GATE_REQUIRED_FIELDS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    title: str = "Reflected XSS in /search",
    severity: str = "high",
    confidence: float = 0.6,
    poc: str | None = "GET /search?q=<script>alert(1)</script>",
    request_response: str | None = "HTTP/1.1 200 OK\nbody: <script>alert(1)</script>",
    dedup_key: str | None = None,
    source_url: str | None = None,
    finding_metadata: dict[str, Any] | None = None,
) -> Any:
    """Build a Finding-shaped object that the generator can serialize.

    Avoids touching the DB — uses ``SimpleNamespace`` for the columns
    ``_finding_to_dict`` reads. If a real Finding ORM is needed, swap in
    the SQLAlchemy model.
    """
    metadata: dict[str, Any] = dict(finding_metadata or {})
    if poc is not None:
        metadata.setdefault("poc", poc)
    if request_response is not None:
        metadata.setdefault("request_response", request_response)
    if source_url is not None:
        metadata.setdefault("source_url", source_url)

    return SimpleNamespace(
        id=str(uuid.uuid4()),
        title=title,
        description="XSS via the q parameter of /search.",
        severity=severity,
        confidence_score=confidence,
        validated=True,
        cwe_id="CWE-79",
        owasp_category="A03:2021",
        remediation="Sanitize user input.",
        source_agent="pentester",
        finding_metadata=metadata,
        dedup_key=dedup_key,
        created_at=None,
    )


# ---------------------------------------------------------------------------
# Downgrade rules
# ---------------------------------------------------------------------------


class TestStrictGateDowngrades:
    def test_strict_gate_downgrades_missing_poc(self) -> None:
        """No PoC + conf 0.20 -> downgraded to info under strict gate."""
        gen = JSONReportGenerator()
        finding = _make_finding(
            severity="high",
            confidence=0.20,
            poc=None,
            request_response="HTTP/1.1 200 OK",
            finding_metadata={"request_response": "HTTP/1.1 200 OK"},
        )
        # Force the strict gate on via the config dict.
        out = gen._apply_strict_gate(
            gen._validate_findings([finding], strict_finding_gate=True)
        )
        assert len(out) == 1
        assert out[0]["severity"] == "info", (
            f"expected downgrade to info, got {out[0]['severity']!r}"
        )
        # Downgrade marker lists what was missing.
        assert "strict_gate_downgraded" in out[0]
        assert "poc" in out[0]["strict_gate_downgraded"]

    def test_strict_gate_drops_zero_confidence(self) -> None:
        """Confidence below the 0.30 threshold must trigger downgrade."""
        gen = JSONReportGenerator()
        finding = _make_finding(severity="critical", confidence=0.0)
        out = gen._apply_strict_gate(
            gen._validate_findings([finding], strict_finding_gate=True)
        )
        assert out[0]["severity"] == "info"
        assert "confidence_score" in out[0]["strict_gate_downgraded"]
        # Sanity: the documented threshold hasn't drifted.
        assert STRICT_GATE_MIN_CONFIDENCE == 0.30

    def test_strict_gate_keeps_complete_finding(self) -> None:
        """A finding that meets all 3 requirements must keep its severity."""
        gen = JSONReportGenerator()
        finding = _make_finding(severity="high", confidence=0.95)
        out = gen._apply_strict_gate(
            gen._validate_findings([finding], strict_finding_gate=True)
        )
        assert out[0]["severity"] == "high"
        assert "strict_gate_downgraded" not in out[0]

    def test_strict_gate_ignores_low_severity(self) -> None:
        """The strict gate only acts on high/critical/medium. ``info``/``low`` pass through."""
        gen = JSONReportGenerator()
        finding = _make_finding(severity="low", confidence=0.0)
        out = gen._apply_strict_gate(
            gen._validate_findings([finding], strict_finding_gate=True)
        )
        assert out[0]["severity"] == "low"
        # The low-severity branch never sets the downgrade marker.
        assert "strict_gate_downgraded" not in out[0]


# ---------------------------------------------------------------------------
# Legacy behavior preservation (REGRESSION TEST)
# ---------------------------------------------------------------------------


class TestStrictGateRegression:
    def test_strict_gate_false_preserves_old_behavior(self) -> None:
        """``strict_finding_gate=False`` must NOT downgrade missing-PoC findings.

        This is the regression guard called out in plan §Acceptance
        Criteria: the existing test suite depends on the legacy
        "warn but DO NOT downgrade" path. If this test fails, somebody
        flipped the default and the existing suite will break.
        """
        gen = JSONReportGenerator()
        finding = _make_finding(
            severity="high",
            confidence=0.10,
            poc=None,
            request_response="HTTP/1.1 200 OK",
            finding_metadata={"request_response": "HTTP/1.1 200 OK"},
        )
        # _validate_findings with strict_finding_gate=False — the legacy
        # branch — must NOT mutate severity. It should attach a warning
        # marker instead.
        out = gen._validate_findings([finding], strict_finding_gate=False)
        assert out[0]["severity"] == "high", (
            f"legacy path downgraded severity: got {out[0]['severity']!r}"
        )
        assert "missing_fields_warning" in out[0]
        # And the strict gate itself must not have been invoked at all
        # (we never called it in this path). The full report flow with
        # ``config={'strict_finding_gate': False}`` also must not run
        # the strict gate.
        report = gen.generate_report(
            engagement=SimpleNamespace(
                id="e1", status="completed", started_at=None, completed_at=None,
                iteration_count=1, config={},
            ),
            findings=[finding],
            hypotheses=[],
            provenance_links=[],
            tool_invocations=[],
            include_metadata=False,
            config={"strict_finding_gate": False},
        )
        assert report["findings"][0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Dedup behavior
# ---------------------------------------------------------------------------


class TestDedup:
    def test_dedup_3_dup_to_1(self) -> None:
        """Three findings sharing a dedup_key collapse to one with the highest confidence."""
        gen = JSONReportGenerator()
        key = "abc123def4567890"
        f1 = _make_finding(title="A", confidence=0.4, dedup_key=key)
        f2 = _make_finding(title="B", confidence=0.9, dedup_key=key)
        f3 = _make_finding(title="C", confidence=0.6, dedup_key=key)

        out = gen._deduplicate_findings(
            [
                gen._finding_to_dict(f) for f in (f1, f2, f3)
            ]
        )
        assert len(out) == 1
        # The highest-confidence entry wins; the "B" finding has 0.9.
        assert out[0]["title"] == "B"
        assert out[0]["dedup_key"] == key
        assert float(out[0]["confidence_score"]) == 0.9

    def test_dedup_preserves_unique_keys(self) -> None:
        """Findings with distinct dedup_keys are all kept."""
        gen = JSONReportGenerator()
        f1 = _make_finding(dedup_key="k1")
        f2 = _make_finding(dedup_key="k2")
        f3 = _make_finding(dedup_key="k3")
        out = gen._deduplicate_findings(
            [gen._finding_to_dict(f) for f in (f1, f2, f3)]
        )
        assert len(out) == 3
        assert {f["dedup_key"] for f in out} == {"k1", "k2", "k3"}

    def test_dedup_keeps_no_key_findings(self) -> None:
        """Findings with no dedup_key are preserved (legacy rows)."""
        gen = JSONReportGenerator()
        f1 = _make_finding(dedup_key=None)
        f2 = _make_finding(dedup_key=None)
        out = gen._deduplicate_findings(
            [gen._finding_to_dict(f) for f in (f1, f2)]
        )
        # No dedup_key -> both pass through.
        assert len(out) == 2

    def test_dedup_mixed_keyed_and_unkeyed(self) -> None:
        gen = JSONReportGenerator()
        keyed_a = _make_finding(dedup_key="dup1")
        keyed_b = _make_finding(dedup_key="dup1", confidence=0.8)  # wins
        unkeyed = _make_finding(dedup_key=None)
        out = gen._deduplicate_findings(
            [gen._finding_to_dict(f) for f in (keyed_a, keyed_b, unkeyed)]
        )
        assert len(out) == 2
        # The keyed pair deduped to 1, the unkeyed was preserved.
        assert any(f["dedup_key"] == "dup1" for f in out)
        assert any(f["dedup_key"] is None for f in out)


# ---------------------------------------------------------------------------
# Dedup-key computation
# ---------------------------------------------------------------------------


class TestDedupKey:
    def test_dedup_key_handles_missing_url(self) -> None:
        """Missing URL/param must still produce a stable, deterministic key.

        Per plan §Step 4: "findings without URL/param get a UUID-based
        key". The actual UUID-based fallback lives in the agent layer;
        the JSON generator's own ``_compute_dedup_key`` always returns
        a 16-char hex digest (coercing ``None`` to ""), and the dedup
        pass preserves a ``None`` key as "no key" (no group). This test
        asserts the generator's key helper is total + stable.
        """
        gen = JSONReportGenerator()
        k1 = gen._compute_dedup_key(None, "xss", "<script>")
        k2 = gen._compute_dedup_key(None, "xss", "<script>")
        assert k1 == k2, "missing URL must produce stable key"
        assert len(k1) == 16
        # And a different param produces a different key.
        k3 = gen._compute_dedup_key(None, "xss", "<img>")
        assert k1 != k3

    def test_dedup_key_normalizes_inputs(self) -> None:
        """Whitespace + case differences must not change the key."""
        gen = JSONReportGenerator()
        k1 = gen._compute_dedup_key("  HTTPS://Example.com  ", "XSS", "Q")
        k2 = gen._compute_dedup_key("https://example.com", "xss", "q")
        assert k1 == k2

    def test_dedup_key_changes_with_category(self) -> None:
        gen = JSONReportGenerator()
        k1 = gen._compute_dedup_key("https://e.com", "xss", "q")
        k2 = gen._compute_dedup_key("https://e.com", "sqli", "q")
        assert k1 != k2

    def test_dedup_key_is_sha256_prefix(self) -> None:
        """Sanity check: the key matches sha256(...).hexdigest()[:16]."""
        gen = JSONReportGenerator()
        url, cat, param = "https://e.com", "xss", "q"
        expected = hashlib.sha256(
            f"{url.lower()}|{cat.lower()}|{param.lower()}".encode("utf-8")
        ).hexdigest()[:16]
        assert gen._compute_dedup_key(url, cat, param) == expected

    def test_required_fields_includes_poc_and_request_response(self) -> None:
        """The strict gate's required-field set must include both PoC and request/response."""
        assert "poc" in STRICT_GATE_REQUIRED_FIELDS
        assert "request_response" in STRICT_GATE_REQUIRED_FIELDS
