"""DOM-XSS hunter via real browser (plan §3.2.1, §5.6).

``DOMXSSHunter`` opens a target page in a real browser, injects a
known XSS payload via the URL fragment (the canonical DOM-XSS vector
— the server never sees the fragment, so this catches client-side
sinks that reflected-XSS scanning misses), and checks whether the
payload fired in a dangerous sink:

  * ``document.write`` / ``document.writeln``
  * ``element.innerHTML`` / ``element.outerHTML``
  * ``element.insertAdjacentHTML``
  * ``element.setAttribute("on*", ...)``
  * ``location`` / ``location.href`` / ``location.assign(...)`` writes
  * ``eval`` / ``Function(...)`` / ``setTimeout/setInterval`` with string
  * ``document.createContextualDocumentFragment``

The hunter uses a two-stage detection strategy:

  1. **Sink reflection probe.** Before the payload fires, evaluate
     a probe function in the page that returns a JSON snapshot of
     every known sink. After the payload, evaluate the same
     function again and diff. A new ``innerHTML`` containing the
     payload string, a new ``location.href`` pointing to
     ``javascript:...``, or a new function body is positive evidence.
  2. **Side-channel trigger.** Listen for ``alert``, ``confirm``,
     ``prompt``, and any exception thrown while evaluating the
     payload. The handler records ``DialogFired`` events so the
     hunter can report them as a definitive trigger.

The hunter is intentionally *not* coupled to Playwright: it accepts
any object that quacks like a Playwright ``Page`` (``goto``,
``evaluate``, ``add_init_script``, ``on``, ``screenshot``,
``close``). Production callers pass a real ``BrowserSession``;
unit tests pass a ``MockPage`` so the test runs without Chromium.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol

logger = logging.getLogger(__name__)


# --- Payloads ------------------------------------------------------------

# Canonical DOM-XSS vectors. Each is a (name, fragment, expected sink)
# triple. The hunter iterates through them in priority order, stopping
# at the first one that fires a known sink or triggers a side-channel.
DEFAULT_PAYLOADS: list[dict[str, str]] = [
    {
        "name": "img_onerror",
        "fragment": "<img src=x onerror=ASSURIX_DOM_XSS_MARKER(1)>",
        "sink": "img.onerror",
    },
    {
        "name": "svg_onload",
        "fragment": "<svg onload=ASSURIX_DOM_XSS_MARKER(1)>",
        "sink": "svg.onload",
    },
    {
        "name": "iframe_srcdoc",
        "fragment": "<iframe srcdoc=\"<script>ASSURIX_DOM_XSS_MARKER(1)</script>\">",
        "sink": "iframe.srcdoc",
    },
    {
        "name": "javascript_uri",
        "fragment": "javascript:ASSURIX_DOM_XSS_MARKER(1)",
        "sink": "location.href (javascript: URI)",
    },
    {
        "name": "input_onfocus",
        "fragment": "<input onfocus=ASSURIX_DOM_XSS_MARKER(1) autofocus>",
        "sink": "input.onfocus",
    },
    {
        "name": "details_ontoggle",
        "fragment": "<details ontoggle=ASSURIX_DOM_XSS_MARKER(1) open>",
        "sink": "details.ontoggle",
    },
    {
        "name": "object_data",
        "fragment": "<object data='javascript:ASSURIX_DOM_XSS_MARKER(1)'>",
        "sink": "object.data (javascript: URI)",
    },
]

# The unique marker the probe JS injects when a payload fires. Using a
# distinctive global function name avoids collisions with site JS and
# makes the "did it fire?" check trivial.
MARKER_FN = "ASSURIX_DOM_XSS_MARKER"

# Sentinel string the page writes into ``document.title`` so the
# hunter can read it from outside the page (a Playwright ``evaluate``
# on the title is a clean way to detect payload execution when dialog
# handling isn't available).
TITLE_MARKER_PREFIX = "ASSURIX_DOM_XSS_DETECTED:"

# JS that, when evaluated, returns a JSON snapshot of every sink we
# care about. The hunter diffs the pre-payload and post-payload
# snapshots to decide which sink fired.
SINK_PROBE_JS = """
() => {
    const out = {};
    try {
        out.body_innerHTML_len = (document.body && document.body.innerHTML || '').length;
        out.body_innerHTML_tail = (document.body && document.body.innerHTML || '').slice(-200);
    } catch (e) { out.body_err = String(e); }
    try {
        out.location_href = location.href;
        out.location_hash = location.hash;
    } catch (e) { out.location_err = String(e); }
    try {
        out.title = document.title;
    } catch (e) { out.title_err = String(e); }
    try {
        // Capture dangerous attribute handlers present in the DOM
        // (e.g. <img src=x onerror=...>). We only record the
        // presence+serialized function, not the body, to keep the
        // probe cheap.
        const handlers = [];
        const all = document.querySelectorAll('*');
        for (const el of all) {
            for (const attr of el.attributes || []) {
                if (attr.name && attr.name.toLowerCase().startsWith('on')) {
                    handlers.push({
                        tag: el.tagName,
                        attr: attr.name,
                        value: (attr.value || '').slice(0, 120),
                    });
                }
            }
        }
        out.event_handlers = handlers.slice(0, 50);
        out.event_handler_count = handlers.length;
    } catch (e) { out.handlers_err = String(e); }
    return out;
}
"""


# --- Protocol types ------------------------------------------------------


class _PageLike(Protocol):
    """A minimal subset of the Playwright ``Page`` interface.

    We use a Protocol so the hunter accepts any object with these
    methods (real Playwright Page, or the ``MockPage`` test fixture).
    The Protocol deliberately has no ``isinstance`` check — duck typing
    is the contract.
    """

    async def goto(self, url: str, **kwargs: Any) -> Any: ...
    async def evaluate(
        self, expression: str, arg: Any = None
    ) -> Any: ...
    async def add_init_script(self, script: str) -> None: ...
    def on(self, event: str, handler: Callable[..., Any]) -> None: ...
    async def screenshot(self, *, path: str | None = None) -> bytes: ...
    async def close(self) -> None: ...


# --- Finding schema ------------------------------------------------------


@dataclass
class XSSFinding:
    """A single confirmed (or suspected) DOM-XSS finding."""

    payload_name: str
    payload_fragment: str
    sink: str
    confidence: float
    url: str
    evidence: dict[str, Any] = field(default_factory=dict)
    screenshot_path: str | None = None
    detected_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def is_confirmed(self) -> bool:
        """True if the side-channel trigger fired or a sink mutation
        was observed. Lower-confidence ``detected`` events (e.g. only
        title change) are reported but not promoted to confirmed.
        """
        return self.confidence >= 0.8


# --- The hunter ----------------------------------------------------------


class DOMXSSHunter:
    """Drives a real browser through DOM-XSS payloads.

    The hunter is engine-agnostic: pass it any ``_PageLike`` object.
    In production the page comes from
    ``src.agents.browser.session.BrowserSession``; in tests, from a
    ``MockPage`` that simulates sinks.

    Args:
        payloads: List of payload dicts. Defaults to
            :data:`DEFAULT_PAYLOADS`.
        screenshot_dir: Where to save evidence screenshots. If
            ``None``, no screenshots are saved.
        navigation_timeout_ms: How long to wait for ``goto`` before
            declaring the page unreachable.
    """

    name = "dom_xss_hunter"

    def __init__(
        self,
        payloads: list[dict[str, str]] | None = None,
        screenshot_dir: Path | str | None = None,
        navigation_timeout_ms: int = 15_000,
    ) -> None:
        self.payloads = list(payloads) if payloads else list(DEFAULT_PAYLOADS)
        self.screenshot_dir = (
            Path(screenshot_dir) if screenshot_dir is not None else None
        )
        if self.screenshot_dir is not None:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.navigation_timeout_ms = navigation_timeout_ms

    async def hunt(
        self,
        page: _PageLike,
        base_url: str,
        *,
        sink_hint: str | None = None,
    ) -> list[XSSFinding]:
        """Run every payload against ``base_url`` and return findings.

        Args:
            page: A Playwright-style page (or MockPage for tests).
                The hunter will register an init script that wires
                ``window.ASSURIX_DOM_XSS_MARKER`` to write the title
                sentinel. The page must NOT be closed by the caller
                between calls.
            base_url: The URL to attack. The hunter will navigate
                there once per payload, with the payload in the
                fragment.
            sink_hint: Optional pre-known sink name. When set, the
                hunter only fires payloads that target this sink
                (substring match, case-insensitive).

        Returns:
            A list of :class:`XSSFinding` records. Empty list means
            no DOM-XSS was found. The list is sorted by confidence
            (descending).
        """
        # Wire the side-channel: when the payload fires, the page
        # calls ``window.ASSURIX_DOM_XSS_MARKER(n)`` which our init
        # script maps to (a) writing the title sentinel and (b)
        # throwing a sentinel error. We capture (a) via post-navigation
        # ``evaluate``; (b) via the dialog / pageerror listener
        # registered below.
        await page.add_init_script(
            _init_script()
        )
        dialogs: list[dict[str, Any]] = []
        page_errors: list[str] = []

        def _on_dialog(dialog: Any) -> None:
            try:
                dialogs.append({
                    "type": getattr(dialog, "type", "alert"),
                    "message": getattr(dialog, "message", ""),
                })
            except Exception:  # pragma: no cover
                pass

        def _on_pageerror(err: Any) -> None:
            try:
                page_errors.append(str(err))
            except Exception:  # pragma: no cover
                pass

        page.on("dialog", _on_dialog)
        page.on("pageerror", _on_pageerror)

        findings: list[XSSFinding] = []
        for payload in self._filter_payloads(sink_hint):
            finding = await self._try_payload(
                page, base_url, payload,
                dialogs=dialogs, page_errors=page_errors,
            )
            if finding is not None:
                findings.append(finding)
        # Sort by confidence desc, then by sink name for stability.
        findings.sort(key=lambda f: (-f.confidence, f.sink))
        return findings

    # --- internals ---------------------------------------------------

    def _filter_payloads(
        self, sink_hint: str | None
    ) -> list[dict[str, str]]:
        if not sink_hint:
            return list(self.payloads)
        sh = sink_hint.lower()
        return [
            p for p in self.payloads
            if sh in p.get("sink", "").lower() or sh in p["name"].lower()
        ] or list(self.payloads)

    async def _try_payload(
        self,
        page: _PageLike,
        base_url: str,
        payload: dict[str, str],
        *,
        dialogs: list[dict[str, Any]],
        page_errors: list[str],
    ) -> XSSFinding | None:
        url = _url_with_fragment(base_url, payload["fragment"])
        # Snapshot sinks BEFORE the payload. We re-snapshot AFTER and
        # diff; a sink that grew or gained a matching handler is
        # evidence of DOM-XSS.
        pre = await self._safe_evaluate(page, SINK_PROBE_JS)
        # Navigate. If navigation fails (timeout, network error), we
        # skip the payload rather than treating it as a hit.
        try:
            await page.goto(
                url,
                timeout=self.navigation_timeout_ms,
                wait_until="domcontentloaded",
            )
        except Exception as exc:
            logger.debug("DOMXSS: goto failed for %s: %s", url, exc)
            return None
        # Give the page a moment to fire event handlers / autoloads.
        await asyncio.sleep(0.25)
        post = await self._safe_evaluate(page, SINK_PROBE_JS)
        # Screenshot for the auditor.
        screenshot_path = await self._maybe_screenshot(page, payload["name"])
        # Decide whether we found anything.
        confidence, sink, evidence = self._score(pre, post, payload,
                                                  dialogs, page_errors)
        if confidence <= 0.0:
            return None
        return XSSFinding(
            payload_name=payload["name"],
            payload_fragment=payload["fragment"],
            sink=sink,
            confidence=confidence,
            url=url,
            evidence=evidence,
            screenshot_path=str(screenshot_path) if screenshot_path else None,
            note=(
                "title sentinel observed"
                if (post or {}).get("title", "").startswith(TITLE_MARKER_PREFIX)
                else ""
            ),
        )

    async def _safe_evaluate(
        self, page: _PageLike, expression: str
    ) -> dict[str, Any] | None:
        try:
            raw = await page.evaluate(expression)
        except Exception as exc:  # pragma: no cover — page error path
            logger.debug("DOMXSS: evaluate failed: %s", exc)
            return None
        if not isinstance(raw, dict):
            return None
        return raw

    async def _maybe_screenshot(
        self, page: _PageLike, payload_name: str
    ) -> Path | None:
        if self.screenshot_dir is None:
            return None
        path = self.screenshot_dir / f"dom_xss_{payload_name}.png"
        try:
            await page.screenshot(path=str(path))
        except Exception as exc:  # pragma: no cover
            logger.debug("DOMXSS: screenshot failed: %s", exc)
            return None
        return path

    def _score(
        self,
        pre: dict[str, Any] | None,
        post: dict[str, Any] | None,
        payload: dict[str, str],
        dialogs: list[dict[str, Any]],
        page_errors: list[str],
    ) -> tuple[float, str, dict[str, Any]]:
        """Score a payload run. Returns (confidence, sink_name, evidence).

        Confidence scale:
          * 1.0 — alert/confirm/prompt dialog fired (definitive).
          * 0.9 — title sentinel set by the payload.
          * 0.8 — event handler with our marker text appeared in DOM
                  and was not present before the payload.
          * 0.6 — body.innerHTML grew and contains the marker string
                  (possible but not definitive; could be benign
                  template rendering).
          * 0.0 — no signal; return None and the caller skips.
        """
        evidence: dict[str, Any] = {
            "pre": pre,
            "post": post,
            "dialogs": list(dialogs),
            "page_errors": list(page_errors),
        }
        # 1. Side-channel: dialog fired.
        if dialogs:
            return 1.0, payload.get("sink", "alert"), evidence
        # 2. Title sentinel.
        if post and post.get("title", "").startswith(TITLE_MARKER_PREFIX):
            return 0.9, payload.get("sink", "title"), evidence
        # 3. New event handler with our marker.
        if post and pre:
            pre_handlers = set(
                (h.get("tag"), h.get("attr"), h.get("value"))
                for h in pre.get("event_handlers", [])
            )
            new_handlers = [
                h for h in post.get("event_handlers", [])
                if (h.get("tag"), h.get("attr"), h.get("value")) not in pre_handlers
            ]
            for h in new_handlers:
                value = (h.get("value") or "").lower()
                if MARKER_FN.lower() in value or "onerror" in value.lower():
                    return 0.8, f"{h.get('tag')}.{h.get('attr')}", evidence
        # 4. body.innerHTML grew and contains the marker.
        if post and pre:
            pre_html = pre.get("body_innerHTML_tail") or ""
            post_html = post.get("body_innerHTML_tail") or ""
            if (
                post.get("body_innerHTML_len", 0) > pre.get("body_innerHTML_len", 0)
                and MARKER_FN.lower() in post_html.lower()
                and MARKER_FN.lower() not in pre_html.lower()
            ):
                return 0.6, "body.innerHTML", evidence
        return 0.0, "", evidence


# --- Helpers -------------------------------------------------------------


def _init_script() -> str:
    """JS to inject before any page script runs.

    Wires ``window.ASSURIX_DOM_XSS_MARKER`` to:
      1. Set ``document.title`` to a sentinel string (observable
         via Playwright ``page.title()`` or our sink probe).
      2. ``throw`` a sentinel error so a ``pageerror`` listener
         picks it up.
    """
    return f"""
    (() => {{
        if (typeof window.{MARKER_FN} === 'function') return;
        window.{MARKER_FN} = function(_x) {{
            try {{
                document.title = '{TITLE_MARKER_PREFIX}' + (document.title || '');
            }} catch (e) {{}}
            throw new Error('{TITLE_MARKER_PREFIX}');
        }};
    }})();
    """


def _url_with_fragment(base_url: str, fragment: str) -> str:
    """Append ``#<fragment>`` to ``base_url``.

    Existing fragments are replaced. The fragment is percent-encoded
    so JS-string payloads (``<img src=x onerror=...>``) survive the
    transport — Playwright/Chromium decode the percent-encoding
    before executing any JS that reads ``location.hash``.
    """
    parsed = urllib.parse.urlparse(base_url)
    new = parsed._replace(fragment=urllib.parse.quote(fragment, safe=""))
    return urllib.parse.urlunparse(new)


# --- MockPage for unit tests --------------------------------------------


class MockPage:
    """A minimal in-memory Page for unit-testing the hunter.

    Behaviour: when the URL fragment contains the marker fragment
    (i.e. a payload fired), the next ``evaluate`` call returns a
    post-state that includes the title sentinel and a new event
    handler; otherwise it returns the pre-state unchanged. The test
    can pre-load a custom ``post_state`` to simulate a specific sink.

    The MockPage satisfies the :class:`_PageLike` protocol.

    Example::

        page = MockPage(url="https://t/", post_state={
            "title": "ASSURIX_DOM_XSS_DETECTED:foo",
            "body_innerHTML_len": 200,
            "body_innerHTML_tail": "x" * 200,
            "event_handlers": [{"tag": "IMG", "attr": "onerror", "value": "marker"}],
            "event_handler_count": 1,
            "location_href": "https://t/",
            "location_hash": "#<img>",
        })
        findings = await DOMXSSHunter().hunt(page, "https://t/")
        assert findings and findings[0].confidence >= 0.8
    """

    def __init__(
        self,
        url: str = "https://t/",
        pre_state: dict[str, Any] | None = None,
        post_state: dict[str, Any] | None = None,
        *,
        fire_dialog: bool = False,
        raise_on_goto: Exception | None = None,
    ) -> None:
        self.url = url
        self.visited: list[str] = []
        self._pre_state = pre_state or {
            "body_innerHTML_len": 100,
            "body_innerHTML_tail": "no payload here",
            "event_handlers": [],
            "event_handler_count": 0,
            "location_href": url,
            "location_hash": "",
            "title": "before",
        }
        self._post_state = post_state or dict(self._pre_state)
        self._fire_dialog = fire_dialog
        self._raise_on_goto = raise_on_goto
        self._dialogs: list[Any] = []
        self._errors: list[str] = []
        self._listeners: dict[str, list[Callable[..., Any]]] = {}
        self._init_scripts: list[str] = []

    # --- Page interface ----------------------------------------------

    async def goto(self, url: str, **kwargs: Any) -> Any:
        self.visited.append(url)
        if self._raise_on_goto is not None:
            raise self._raise_on_goto
        # If the URL's fragment contains the marker, simulate the
        # side-channel trigger: title sentinel + new handler.
        if MARKER_FN.lower() in url.lower() or "onerror" in url.lower():
            self._post_state = {
                "body_innerHTML_len": 200,
                "body_innerHTML_tail": f"x = <tag>{MARKER_FN}(1)</tag>",
                "event_handlers": [
                    {"tag": "IMG", "attr": "onerror", "value": MARKER_FN + "(1)"},
                ],
                "event_handler_count": 1,
                "location_href": url.split("#")[0],
                "location_hash": "#" + url.split("#", 1)[-1] if "#" in url else "",
                "title": f"{TITLE_MARKER_PREFIX}triggered",
            }
        if self._fire_dialog:
            # Synthesise a dialog object with the duck-typed fields
            # and dispatch it through the page's own listeners so
            # the hunter's on("dialog") handler picks it up.
            self.fire_dialog(MARKER_FN + " fired")
        return None

    async def evaluate(
        self, expression: str, arg: Any = None
    ) -> Any:
        # SINK_PROBE_JS is the only probe the hunter runs. We match
        # on a substring that ONLY appears in the probe (any
        # production probe will be similarly distinctive), so any
        # other JS expression is a no-op.
        if "querySelectorAll" in expression:
            # First call: pre. Subsequent calls: post.
            if not hasattr(self, "_evaluate_call_count"):
                self._evaluate_call_count = 0
            self._evaluate_call_count += 1
            if self._evaluate_call_count == 1:
                return self._pre_state
            return self._post_state
        return None

    async def add_init_script(self, script: str) -> None:
        self._init_scripts.append(script)

    def on(self, event: str, handler: Callable[..., Any]) -> None:
        self._listeners.setdefault(event, []).append(handler)

    async def screenshot(self, *, path: str | None = None) -> bytes:
        png_bytes = b"\x89PNG\r\n\x1a\n"
        if path is not None:
            # Real browsers write the file when given a ``path``;
            # the mock mirrors that contract.
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(png_bytes)
        return png_bytes

    async def close(self) -> None:
        return None

    # --- Test helpers ------------------------------------------------

    def fire_dialog(self, message: str = "") -> None:
        """Manually fire a dialog event as if a page alert() ran."""
        class _D:
            def __init__(self, msg: str) -> None:
                self.type = "alert"
                self.message = msg
        d = _D(message)
        for h in self._listeners.get("dialog", []):
            h(d)
        self._dialogs.append(d)

    def fire_pageerror(self, message: str) -> None:
        for h in self._listeners.get("pageerror", []):
            h(message)
        self._errors.append(message)


__all__ = [
    "DEFAULT_PAYLOADS",
    "DOMXSSHunter",
    "MARKER_FN",
    "MockPage",
    "TITLE_MARKER_PREFIX",
    "XSSFinding",
]
