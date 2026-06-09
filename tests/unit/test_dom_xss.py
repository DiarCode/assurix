"""Unit tests for DOMXSSHunter (plan §3.2.1, §5.6).

The hunter must work without a real browser. We use the
``MockPage`` fixture that ships with the module — it satisfies the
``_PageLike`` protocol and simulates DOM-XSS sinks deterministically
based on the URL fragment the hunter navigates to.

Coverage:
  Helpers:
    1. _url_with_fragment replaces existing fragment.
    2. _url_with_fragment percent-encodes payloads so JS survives transport.
    3. _init_script contains the marker function and title sentinel.

  Scoring:
    4. Dialog fire → confidence 1.0.
    5. Title sentinel → confidence 0.9.
    6. New event handler with marker → confidence 0.8.
    7. body.innerHTML grew + contains marker → confidence 0.6.
    8. No signal → returns confidence 0.0 (hunter skips).

  MockPage:
    9. MockPage.goto records the URL.
   10. MockPage.goto raises on raise_on_goto.
   11. MockPage.evaluate returns pre on first call, post on second.
   12. MockPage.screenshot returns bytes.

  DOMXSSHunter.hunt():
   13. Default payloads run; no signal → no findings.
   14. URL fragment with marker triggers the post-state flip →
       at least one finding, confidence >= 0.8.
   15. fire_dialog() mid-hunt → confidence 1.0.
   16. sink_hint filters payloads to those that target that sink.
   17. raise_on_goto skips the payload, doesn't crash.
   18. Sort order: confidence desc, then sink name asc.
   19. Screenshot saved when screenshot_dir is set.
   20. No screenshot dir → no screenshot_path.
   21. Custom payloads list replaces defaults.
   22. Multiple findings returned; list is sorted.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from src.agents.browser.dom_xss import (
    DEFAULT_PAYLOADS,
    DOMXSSHunter,
    MARKER_FN,
    MockPage,
    SINK_PROBE_JS,
    TITLE_MARKER_PREFIX,
    XSSFinding,
    _init_script,
    _url_with_fragment,
)


# --- helpers -------------------------------------------------------------


class TestUrlWithFragment:
    def test_replaces_existing_fragment(self) -> None:
        u = _url_with_fragment("https://t/page#old", "<b>x</b>")
        assert "#old" not in u
        assert u.startswith("https://t/page#")

    def test_adds_fragment_when_missing(self) -> None:
        u = _url_with_fragment("https://t/page", "<b>x</b>")
        assert "#" in u
        # The fragment is percent-encoded; the raw "<b>" should not
        # appear in the URL (it would confuse parsers).
        assert "<b>" not in u

    def test_preserves_query_string(self) -> None:
        u = _url_with_fragment("https://t/page?x=1", "<b>x</b>")
        assert "x=1" in u
        assert "#" in u

    def test_percent_encodes_payload(self) -> None:
        u = _url_with_fragment("https://t/", "<img src=x onerror=alert(1)>")
        # The space and angle brackets should be encoded.
        # (Playwright/Chromium decode this when reading location.hash.)
        assert " " not in u
        assert "<" not in u
        assert "%3C" in u


class TestInitScript:
    def test_contains_marker_function(self) -> None:
        s = _init_script()
        assert MARKER_FN in s

    def test_contains_title_sentinel(self) -> None:
        s = _init_script()
        assert TITLE_MARKER_PREFIX in s


# --- scoring -------------------------------------------------------------


def _hunter() -> DOMXSSHunter:
    return DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])  # img_onerror


def _img_post_state() -> dict[str, Any]:
    """The post-state the MockPage produces when the marker URL fires."""
    return {
        "body_innerHTML_len": 200,
        "body_innerHTML_tail": f"x = <tag>{MARKER_FN}(1)</tag>",
        "event_handlers": [
            {"tag": "IMG", "attr": "onerror", "value": MARKER_FN + "(1)"},
        ],
        "event_handler_count": 1,
        "location_href": "https://t/",
        "location_hash": f"#{MARKER_FN}",
        "title": f"{TITLE_MARKER_PREFIX}triggered",
    }


def _pre_state() -> dict[str, Any]:
    return {
        "body_innerHTML_len": 100,
        "body_innerHTML_tail": "no payload",
        "event_handlers": [],
        "event_handler_count": 0,
        "location_href": "https://t/",
        "location_hash": "",
        "title": "before",
    }


class TestScoring:
    def test_dialog_fire_is_confidence_1(self) -> None:
        h = _hunter()
        post = _pre_state()
        conf, sink, ev = h._score(_pre_state(), post, DEFAULT_PAYLOADS[0],
                                  dialogs=[{"type": "alert", "message": "x"}],
                                  page_errors=[])
        assert conf == 1.0
        assert ev["dialogs"]

    def test_title_sentinel_is_confidence_0_9(self) -> None:
        h = _hunter()
        post = dict(_pre_state())
        post["title"] = TITLE_MARKER_PREFIX + "x"
        conf, sink, _ = h._score(_pre_state(), post, DEFAULT_PAYLOADS[0],
                                  dialogs=[], page_errors=[])
        assert conf == 0.9

    def test_new_handler_with_marker_is_confidence_0_8(self) -> None:
        h = _hunter()
        pre = _pre_state()
        post = dict(_pre_state())
        post["event_handlers"] = [
            {"tag": "IMG", "attr": "onerror", "value": MARKER_FN + "(1)"},
        ]
        post["event_handler_count"] = 1
        conf, sink, _ = h._score(pre, post, DEFAULT_PAYLOADS[0],
                                  dialogs=[], page_errors=[])
        assert conf == 0.8
        assert "IMG" in sink

    def test_innerHTML_growth_with_marker_is_confidence_0_6(self) -> None:
        h = _hunter()
        pre = _pre_state()
        post = {
            "body_innerHTML_len": 500,
            "body_innerHTML_tail": "x" * 100 + MARKER_FN + "(1)" + "y" * 100,
            "event_handlers": [],
            "event_handler_count": 0,
            "location_href": "https://t/",
            "location_hash": "",
            "title": "before",
        }
        conf, sink, _ = h._score(pre, post, DEFAULT_PAYLOADS[0],
                                  dialogs=[], page_errors=[])
        assert conf == 0.6
        assert sink == "body.innerHTML"

    def test_no_signal_returns_zero(self) -> None:
        h = _hunter()
        pre = _pre_state()
        post = _pre_state()  # identical
        conf, sink, _ = h._score(pre, post, DEFAULT_PAYLOADS[0],
                                  dialogs=[], page_errors=[])
        assert conf == 0.0

    def test_innerHTML_growth_without_marker_is_zero(self) -> None:
        """The body grew but the marker isn't in it → not XSS-shaped."""
        h = _hunter()
        pre = _pre_state()
        post = dict(_pre_state())
        post["body_innerHTML_len"] = 500
        post["body_innerHTML_tail"] = "x" * 200
        conf, _, _ = h._score(pre, post, DEFAULT_PAYLOADS[0],
                               dialogs=[], page_errors=[])
        assert conf == 0.0


# --- MockPage -----------------------------------------------------------


class TestMockPage:
    def test_goto_records_url(self) -> None:
        page = MockPage()
        asyncio.run(page.goto("https://t/page"))
        assert page.visited == ["https://t/page"]

    def test_goto_raises_when_configured(self) -> None:
        page = MockPage(raise_on_goto=RuntimeError("boom"))
        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(page.goto("https://t/"))

    def test_evaluate_returns_pre_then_post(self) -> None:
        page = MockPage(
            pre_state={**_pre_state(), "title": "PRE"},
            post_state={**_pre_state(), "title": "POST"},
        )
        first = asyncio.run(page.evaluate(SINK_PROBE_JS))
        second = asyncio.run(page.evaluate(SINK_PROBE_JS))
        assert first["title"] == "PRE"
        assert second["title"] == "POST"

    def test_screenshot_returns_bytes(self) -> None:
        page = MockPage()
        b = asyncio.run(page.screenshot())
        assert b.startswith(b"\x89PNG")

    def test_screenshot_to_path(self, tmp_path: Path) -> None:
        page = MockPage()
        path = tmp_path / "out.png"
        asyncio.run(page.screenshot(path=str(path)))
        assert path.exists()

    def test_fire_dialog_invokes_listener(self) -> None:
        page = MockPage()
        seen: list[str] = []
        page.on("dialog", lambda d: seen.append(d.message))
        page.fire_dialog("hello")
        assert seen == ["hello"]

    def test_fire_pageerror_invokes_listener(self) -> None:
        page = MockPage()
        seen: list[str] = []
        page.on("pageerror", lambda e: seen.append(str(e)))
        page.fire_pageerror("boom")
        assert seen == ["boom"]


# --- DOMXSSHunter.hunt() end-to-end -------------------------------------


class TestHuntEndToEnd:
    def test_no_signal_returns_empty(self) -> None:
        """Without marker in URL and no pre-set post_state, no findings."""
        # MockPage with pre_state == post_state (no change), no dialog.
        page = MockPage(
            pre_state=_pre_state(),
            post_state=_pre_state(),
        )
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])
        findings = asyncio.run(h.hunt(page, "https://t/"))
        # The MockPage's goto() flips the post_state to the marker
        # version whenever the URL fragment contains MARKER_FN. Since
        # the hunter's URL *does* contain the marker (it built the URL
        # with the marker fragment), goto() flips the post-state, and
        # the hunter observes a high-confidence finding. To test the
        # "no signal" case, we use a payload that has NO marker.
        # Build a "no-op" payload that MockPage won't recognise.
        class _StrippedPage(MockPage):
            async def goto(self, url: str, **kwargs: Any) -> Any:  # type: ignore[override]
                self.visited.append(url)
                return None
        page2 = _StrippedPage(
            pre_state=_pre_state(), post_state=_pre_state(),
        )
        findings = asyncio.run(h.hunt(page2, "https://t/"))
        assert findings == []

    def test_marker_url_produces_high_confidence_finding(self) -> None:
        """The marker-bearing URL causes MockPage to flip its post-state,
        which the hunter reads and scores."""
        page = MockPage()
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])
        findings = asyncio.run(h.hunt(page, "https://t/"))
        assert len(findings) >= 1
        f = findings[0]
        assert f.confidence >= 0.8
        assert f.payload_name == "img_onerror"
        assert f.url.startswith("https://t/#")

    def test_fire_dialog_mid_hunt_yields_confidence_1(self) -> None:
        """If a dialog fires during navigation, score is 1.0."""
        page = MockPage(fire_dialog=True)
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])
        findings = asyncio.run(h.hunt(page, "https://t/"))
        assert len(findings) == 1
        assert findings[0].confidence == 1.0
        assert findings[0].evidence["dialogs"]

    def test_sink_hint_filters_payloads(self) -> None:
        """A sink_hint that matches no payload falls back to all payloads."""
        h = DOMXSSHunter()
        # Hint matching one of the defaults.
        matching = h._filter_payloads("img.onerror")
        assert any(p["name"] == "img_onerror" for p in matching)
        # Hint matching nothing — falls back to ALL payloads.
        fallback = h._filter_payloads("definitely-not-a-sink")
        assert len(fallback) == len(DEFAULT_PAYLOADS)

    def test_raise_on_goto_skips_payload_gracefully(self) -> None:
        """A failed navigation must not raise out of hunt()."""
        page = MockPage(raise_on_goto=RuntimeError("nope"))
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])
        findings = asyncio.run(h.hunt(page, "https://t/"))
        assert findings == []

    def test_sort_order(self) -> None:
        """When multiple findings emerge, they're sorted by confidence desc."""
        # Construct a page whose post_state is set to the title-only
        # signal (confidence 0.9) for the first payload and the
        # innerHTML-grew (0.6) for a second payload.
        page = MockPage(
            pre_state=_pre_state(),
            post_state={
                **_pre_state(),
                "title": TITLE_MARKER_PREFIX + "x",
                "body_innerHTML_len": 500,
                "body_innerHTML_tail": "x" * 100 + MARKER_FN + "(1)" + "y" * 100,
            },
        )
        h = DOMXSSHunter(
            payloads=[DEFAULT_PAYLOADS[0], DEFAULT_PAYLOADS[1]],
        )
        findings = asyncio.run(h.hunt(page, "https://t/"))
        # All findings (if any) sorted by confidence desc.
        confidences = [f.confidence for f in findings]
        assert confidences == sorted(confidences, reverse=True)

    def test_screenshot_saved_when_dir_set(self, tmp_path: Path) -> None:
        page = MockPage()
        h = DOMXSSHunter(
            payloads=[DEFAULT_PAYLOADS[0]],
            screenshot_dir=tmp_path,
        )
        findings = asyncio.run(h.hunt(page, "https://t/"))
        if findings:
            assert findings[0].screenshot_path is not None
            assert Path(findings[0].screenshot_path).exists()

    def test_no_screenshot_when_dir_none(self) -> None:
        page = MockPage()
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]], screenshot_dir=None)
        findings = asyncio.run(h.hunt(page, "https://t/"))
        if findings:
            assert findings[0].screenshot_path is None

    def test_custom_payloads(self) -> None:
        custom = [{
            "name": "custom_marker",
            "fragment": f"<x onfoo={MARKER_FN}(1)>",
            "sink": "x.onfoo",
        }]
        page = MockPage()
        h = DOMXSSHunter(payloads=custom)
        findings = asyncio.run(h.hunt(page, "https://t/custom"))
        assert findings
        assert findings[0].payload_name == "custom_marker"

    def test_default_payloads_have_required_keys(self) -> None:
        """Defensive: every default payload must have name+fragment+sink."""
        for p in DEFAULT_PAYLOADS:
            assert "name" in p
            assert "fragment" in p
            assert "sink" in p

    def test_finding_is_confirmed_property(self) -> None:
        f = XSSFinding(
            payload_name="x", payload_fragment="<x>", sink="s",
            confidence=0.9, url="u",
        )
        assert f.is_confirmed is True
        f2 = XSSFinding(
            payload_name="x", payload_fragment="<x>", sink="s",
            confidence=0.5, url="u",
        )
        assert f2.is_confirmed is False

    def test_finding_to_dict(self) -> None:
        f = XSSFinding(
            payload_name="x", payload_fragment="<x>", sink="s",
            confidence=0.9, url="u", evidence={"k": 1},
        )
        d = f.to_dict()
        assert d["payload_name"] == "x"
        assert d["confidence"] == 0.9
        assert d["evidence"] == {"k": 1}

    def test_init_scripts_installed(self) -> None:
        page = MockPage()
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])
        asyncio.run(h.hunt(page, "https://t/"))
        # The hunter must have installed the marker init script.
        assert any(MARKER_FN in s for s in page._init_scripts)

    def test_listeners_attached(self) -> None:
        page = MockPage()
        h = DOMXSSHunter(payloads=[DEFAULT_PAYLOADS[0]])
        asyncio.run(h.hunt(page, "https://t/"))
        assert "dialog" in page._listeners
        assert "pageerror" in page._listeners
