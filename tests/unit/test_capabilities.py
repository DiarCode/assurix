"""Unit tests for src/graph/capabilities.py (per plan §5.4.bis, §3.3.1.bis)."""
from __future__ import annotations

import logging

import pytest

from src.graph.capabilities import (
    CAPABILITY_VOCABULARY,
    Capability,
    guard_capability,
)


def test_vocabulary_is_closed_set() -> None:
    """Plan §5.4.bis acceptance: 11 values, all StrEnum members."""
    assert len(CAPABILITY_VOCABULARY) == 11
    assert CAPABILITY_VOCABULARY == frozenset(c.value for c in Capability)
    for cap in Capability:
        assert cap.value in CAPABILITY_VOCABULARY


def test_vocabulary_includes_named_patterns() -> None:
    """All 7 chain patterns from plan §3.3.1 are grounded in the vocabulary."""
    expected = {
        "session_hijack",     # XSS+CSP
        "cloud_meta_access",  # SSRF+CloudMeta
        "auth_bypass",        # IDOR+Admin
        "lfi_primitive",      # SSTI+LFI
        "ssrf_primitive",     # SSRF base
        "open_redirect",      # OpenRedirect+OAuth
        "graphql_introspection",  # GraphQLIntrospection
    }
    assert expected.issubset(CAPABILITY_VOCABULARY)


def test_guard_passes_valid_capability() -> None:
    assert guard_capability("session_hijack") == "session_hijack"
    assert guard_capability("auth_bypass") == "auth_bypass"


def test_guard_returns_none_for_unknown(caplog: pytest.LogCaptureFixture) -> None:
    """Plan §3.3.1.bis: unknown capability is rejected with WARNING."""
    with caplog.at_level(logging.WARNING, logger="src.graph.capabilities"):
        result = guard_capability("bogus_capability")
    assert result is None
    assert any("bogus_capability" in rec.message and "rejected" in rec.message for rec in caplog.records)


def test_guard_returns_none_for_none() -> None:
    """Explicit None in (e.g.) LLM response is preserved as None."""
    assert guard_capability(None) is None


def test_guard_rejects_ad_hoc_strings() -> None:
    """Real-world LLM drift: 'admin', 'rce', 'xss' should all be rejected."""
    assert guard_capability("admin") is None
    assert guard_capability("rce") is None
    assert guard_capability("xss") is None
    assert guard_capability("") is None
