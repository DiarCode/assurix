"""Phase 5 — API auth boundary: POST /scans must not accept operator-only
config overrides from an unauthenticated caller.

FIX 5 (HIGH): POST /scans is unauthenticated. Without filtering, a caller
could pass ``strict_finding_gate=False`` to bypass the strict finding gate.

FIX 6 (HIGH): Same merge — caller could pass ``use_depth_pass=False`` to
disable the post-reporter depth pass.

These tests assert that ``_merge_default_config`` (the single funnel for
caller-supplied config) silently drops operator-only keys and only honors
keys in the documented allowlist. We test the function directly rather
than spinning up the FastAPI app, because the trust boundary lives in
the merge, not the HTTP layer.
"""

from __future__ import annotations

import inspect

import pytest

from src.api.routers.scans import (
    DEFAULT_ENGAGEMENT_CONFIG,
    _CALLER_OVERRIDABLE_CONFIG_KEYS,
    _OPERATOR_ONLY_CONFIG_KEYS,
    _merge_default_config,
)


# ---------------------------------------------------------------------------
# FIX 5 — caller cannot disable strict_finding_gate
# ---------------------------------------------------------------------------


class TestStrictFindingGateBoundary:
    def test_caller_cannot_disable_strict_finding_gate(self) -> None:
        """POST /scans with strict_finding_gate=False must keep the default True."""
        merged = _merge_default_config({"strict_finding_gate": False})
        assert merged["strict_finding_gate"] is True, (
            "Caller-supplied strict_finding_gate=False leaked through the "
            "merge — this is the exact unauthenticated-bypass vulnerability "
            "FIX 5 is meant to prevent."
        )

    def test_caller_cannot_enable_strict_finding_gate_when_default_false(self) -> None:
        """If a future operator flips the default to False, a caller-supplied
        True must still be ignored. This is a symmetry test — the boundary is
        enforced in both directions."""
        # Simulate the operator-defaults case by patching the default briefly.
        from src.api.routers import scans as scans_mod

        original = scans_mod.DEFAULT_ENGAGEMENT_CONFIG
        try:
            scans_mod.DEFAULT_ENGAGEMENT_CONFIG = {**original, "strict_finding_gate": False}
            merged = _merge_default_config({"strict_finding_gate": True})
            assert merged["strict_finding_gate"] is False, (
                "Caller-supplied strict_finding_gate=True leaked through — "
                "the boundary is supposed to be one-way: operator-only."
            )
        finally:
            scans_mod.DEFAULT_ENGAGEMENT_CONFIG = original


# ---------------------------------------------------------------------------
# FIX 6 — caller cannot flip use_depth_pass / use_research_loop /
# use_hypothesis_orchestrator
# ---------------------------------------------------------------------------


class TestUseFlagBoundary:
    def test_caller_cannot_disable_use_depth_pass(self) -> None:
        """POST /scans with use_depth_pass=False must keep the default True."""
        merged = _merge_default_config({"use_depth_pass": False})
        assert merged["use_depth_pass"] is True, (
            "Caller-supplied use_depth_pass=False leaked through the merge "
            "— FIX 6 boundary broken."
        )

    def test_caller_cannot_disable_use_research_loop(self) -> None:
        merged = _merge_default_config({"use_research_loop": False})
        assert merged["use_research_loop"] is True

    def test_caller_cannot_disable_use_hypothesis_orchestrator(self) -> None:
        merged = _merge_default_config({"use_hypothesis_orchestrator": False})
        assert merged["use_hypothesis_orchestrator"] is True

    def test_caller_cannot_override_mode(self) -> None:
        """Mode is operator-only (e.g. 'offensive' vs 'audit')."""
        merged = _merge_default_config({"mode": "audit"})
        assert merged["mode"] == DEFAULT_ENGAGEMENT_CONFIG["mode"]

    def test_caller_cannot_override_max_iterations(self) -> None:
        """max_iterations is operator-only to bound compute spend."""
        merged = _merge_default_config({"max_iterations": 999999})
        assert merged["max_iterations"] == DEFAULT_ENGAGEMENT_CONFIG["max_iterations"]


# ---------------------------------------------------------------------------
# Boundary invariants — the allowlist and operator-only sets must be
# disjoint, exhaustive of the dangerous keys, and locked down.
# ---------------------------------------------------------------------------


class TestBoundaryInvariants:
    def test_allowlist_and_operator_only_are_disjoint(self) -> None:
        """A key cannot be both caller-overridable AND operator-only."""
        overlap = _CALLER_OVERRIDABLE_CONFIG_KEYS & _OPERATOR_ONLY_CONFIG_KEYS
        assert overlap == set(), (
            f"Keys {overlap!r} are in BOTH the allowlist and operator-only "
            f"set — pick one. This is a configuration error that would "
            f"re-introduce the vulnerability."
        )

    def test_strict_finding_gate_is_operator_only(self) -> None:
        assert "strict_finding_gate" in _OPERATOR_ONLY_CONFIG_KEYS

    def test_all_use_flags_are_operator_only(self) -> None:
        for key in ("use_depth_pass", "use_research_loop", "use_hypothesis_orchestrator"):
            assert key in _OPERATOR_ONLY_CONFIG_KEYS, (
                f"{key!r} must be operator-only — leaving it caller-overridable "
                f"re-opens FIX 6."
            )

    def test_mode_and_max_iterations_are_operator_only(self) -> None:
        assert "mode" in _OPERATOR_ONLY_CONFIG_KEYS
        assert "max_iterations" in _OPERATOR_ONLY_CONFIG_KEYS

    def test_default_config_starts_with_safe_state(self) -> None:
        """The default config must be the safe (depth-oriented) state."""
        assert DEFAULT_ENGAGEMENT_CONFIG["strict_finding_gate"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["use_depth_pass"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["use_research_loop"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["use_hypothesis_orchestrator"] is True
        assert DEFAULT_ENGAGEMENT_CONFIG["mode"] == "offensive"


# ---------------------------------------------------------------------------
# Sanity: legitimate caller overrides still work — we did not over-filter.
# ---------------------------------------------------------------------------


class TestLegitimateOverridesStillWork:
    def test_caller_can_set_depth_pass_budget(self) -> None:
        merged = _merge_default_config({"depth_pass_budget_minutes": 60})
        assert merged["depth_pass_budget_minutes"] == 60

    def test_caller_can_set_signoff_timeout(self) -> None:
        merged = _merge_default_config({"signoff_timeout_hours": 48})
        assert merged["signoff_timeout_hours"] == 48

    def test_caller_can_set_extra_payload(self) -> None:
        merged = _merge_default_config({"extra_payload": {"benchmark": True}})
        assert merged["extra_payload"] == {"benchmark": True}

    def test_unknown_caller_keys_are_silently_dropped(self) -> None:
        """Unknown keys (typos, future fields) don't crash the request, they
        just don't take effect. This is a UX decision documented in
        ``_merge_default_config``."""
        merged = _merge_default_config({"this_key_does_not_exist": "x"})
        assert "this_key_does_not_exist" not in merged
        # And the defaults are still all there.
        assert merged["strict_finding_gate"] is True
        assert merged["use_depth_pass"] is True

    def test_empty_caller_config_returns_full_defaults(self) -> None:
        merged = _merge_default_config({})
        assert merged == DEFAULT_ENGAGEMENT_CONFIG

    def test_none_caller_config_returns_full_defaults(self) -> None:
        """The endpoint guard is ``payload.get('config', {}) or {}`` — so the
        function itself sees a dict. Test that path explicitly."""
        merged = _merge_default_config({})
        assert merged["use_depth_pass"] is True
        assert merged["strict_finding_gate"] is True


# ---------------------------------------------------------------------------
# Documentation / contract test — assert the module docstring names the
# trust boundary so future contributors don't quietly weaken it.
# ---------------------------------------------------------------------------


class TestTrustBoundaryIsDocumented:
    def test_scans_module_docstring_mentions_auth_boundary(self) -> None:
        src = inspect.getsource(__import__("src.api.routers.scans", fromlist=["*"]))
        assert "unauthenticated" in src, (
            "scans.py must call out the unauthenticated trust boundary in a "
            "comment so a future contributor doesn't silently weaken it."
        )
        assert "_CALLER_OVERRIDABLE_CONFIG_KEYS" in src
        assert "_OPERATOR_ONLY_CONFIG_KEYS" in src
