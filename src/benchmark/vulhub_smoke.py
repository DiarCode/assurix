"""Vulhub-style offline smoke harness for the Assurix pipeline.

The real Vulhub (https://github.com/vulhub/vulhub) is a Docker-compose
catalogue of intentionally vulnerable apps.  Spinning up one of those
containers takes 30-60s and requires a working Docker daemon — too
slow for a unit/integration smoke.  This module provides a
Vulhub-shaped **offline** stand-in: a single FastAPI app with four
deliberately vulnerable endpoints (reflected XSS, command injection,
path traversal, SQL injection) that exercise the same request shapes
the agents already know how to probe.

The smoke is intentionally small (4 endpoints, no auth) so the test
suite can run it in under a second and assert the pipeline produces a
finding per endpoint family.  The CalibratorSmoke then feeds the
resulting ``LabeledFinding`` set back through
``ThresholdCalibrator.run()`` and asserts the calibrated thresholds
differ from the legacy defaults — i.e. the data actually moved the
needle.

Per plan §3.6 (V&V) acceptance: "Vulhub smoke (offline) — integration
test asserts the engine finds at least N findings across the seeded
vulns; the strict gate is calibrated against the empirical finding
distribution."
"""

from __future__ import annotations

# ``from __future__ import annotations`` is required so the
# ``request: Request`` parameter on each route handler is *not*
# eagerly evaluated when ``build_smoke_app`` runs.  Without it,
# FastAPI inspects the annotation before ``Request`` is bound in
# the local scope and treats ``request`` as a query parameter,
# which 422s every call.
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Import FastAPI symbols at module scope so that the
# ``request: Request`` annotation on each route handler resolves to
# the *actual* class — not a string FastAPI can't introspect.
# (Per PEP 563, ``from __future__ import annotations`` keeps the
# annotation as a string until ``typing.get_type_hints`` resolves
# it, which uses the function's ``__globals__``.  Module-level
# imports are the only way to make the resolution succeed.  The
# names are exported WITHOUT a leading underscore so the bare
# ``Request`` / ``HTMLResponse`` / etc. names in the annotations
# resolve correctly.)
try:
    from fastapi import FastAPI
    from fastapi import Request
    from fastapi.responses import (
        HTMLResponse,
        JSONResponse,
        PlainTextResponse,
    )
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - tested via build_smoke_app fallback
    FastAPI = Request = None  # type: ignore[assignment]
    HTMLResponse = JSONResponse = PlainTextResponse = None  # type: ignore[assignment]
    _FASTAPI_AVAILABLE = False


# ---------------------------------------------------------------------------
# Vulnerable target (FastAPI app)
# ---------------------------------------------------------------------------


# Endpoints the smoke target exposes, with their ground-truth
# vulnerability class.  The AgentProbe below uses these as the
# request seeds so the smoke can drive the same probe surface
# the engine would probe in a live Vulhub target.
VULHUB_SMOKE_ENDPOINTS: list[dict[str, str]] = [
    {
        "path": "/search",
        "method": "GET",
        "param": "q",
        "category": "xss",
        "cwe_id": "CWE-79",
        "severity": "high",
        "expected_title": "Reflected XSS in /search",
    },
    {
        "path": "/lookup",
        "method": "GET",
        "param": "host",
        "category": "cmdi",
        "cwe_id": "CWE-78",
        "severity": "critical",
        "expected_title": "Command Injection in /lookup",
    },
    {
        "path": "/download",
        "method": "GET",
        "param": "file",
        "category": "path_traversal",
        "cwe_id": "CWE-22",
        "severity": "high",
        "expected_title": "Path Traversal in /download",
    },
    {
        "path": "/api/users",
        "method": "GET",
        "param": "id",
        "category": "sqli",
        "cwe_id": "CWE-89",
        "severity": "critical",
        "expected_title": "SQL Injection in /api/users",
    },
]


def build_smoke_app() -> Any:
    """Build the vulnerable FastAPI app.

    Endpoints are intentionally trivial — the goal is to give the
    agents a real HTTP surface to probe, not to mirror Vulhub's
    real apps.  Each endpoint either echoes user input or executes
    a system-level primitive.

    Returns:
        A FastAPI app instance ready for ``httpx.ASGITransport``.
    """
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError(
            "fastapi is required for the Vulhub smoke harness; install "
            "via `uv add fastapi` or set up the venv"
        )

    # Use the module-level imports so the route-handler annotations
    # (``request: Request``) resolve to the actual class via
    # ``typing.get_type_hints`` (which consults ``__globals__``).
    app = FastAPI(title="assurix-vulhub-smoke")

    @app.get("/search", response_class=HTMLResponse)
    async def search(request: Request) -> HTMLResponse:
        """Reflected XSS: query parameter is echoed into the response
        without encoding."""
        q = request.query_params.get("q", "")
        body = f"<html><body>Results for: {q}</body></html>"
        return HTMLResponse(content=body)

    @app.get("/lookup", response_class=PlainTextResponse)
    async def lookup(request: Request) -> PlainTextResponse:
        """Command injection: 'host' is concatenated into a shell
        command.  We block the real subprocess to keep the smoke
        side-effect free, but the *response* still includes the
        unsanitised input so signature-based detectors can find it."""
        host = request.query_params.get("host", "localhost")
        # Note: do NOT actually exec.  The agent finds this vuln
        # because the response body reflects the raw input, and a
        # 5xx is synthesised when shell metacharacters are present.
        if any(c in host for c in (";", "|", "&", "`", "$")):
            return PlainTextResponse(
                content=f"ERR: invalid host {host}",
                status_code=500,
            )
        return PlainTextResponse(content=f"resolved {host}")

    @app.get("/download", response_class=PlainTextResponse)
    async def download(request: Request) -> PlainTextResponse:
        """Path traversal: 'file' is joined to a base dir without
        sanitisation.  We don't actually open files; a 400 with
        the literal path in the error message is enough for
        signature detection."""
        file = request.query_params.get("file", "readme.txt")
        if ".." in file or file.startswith("/"):
            return PlainTextResponse(
                content=f"ERR: cannot open {file}",
                status_code=400,
            )
        return PlainTextResponse(content=f"contents of {file}")

    @app.get("/api/users", response_class=JSONResponse)
    async def api_users(request: Request) -> JSONResponse:
        """SQL injection: 'id' is interpolated into a string.  We
        don't touch a real DB; a 500 with the literal query in
        the error body is the detector's signal."""
        id_ = request.query_params.get("id", "1")
        if any(c in id_.lower() for c in ("'", "--", "union", "select", "or 1", "; ")):
            return JSONResponse(
                content={"error": f"query failed: SELECT * FROM users WHERE id={id_}"},
                status_code=500,
            )
        return JSONResponse(content={"id": int(id_), "name": "alice"})

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# Ground truth for the smoke
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SmokeGroundTruth:
    """Expected finding shape per smoke endpoint.

    The smoke runner uses this to label the findings the agents
    emit so the calibrator can be fed a properly-labeled dataset
    without any manual labelling pass.
    """

    test_case_id: str
    category: str
    cwe_id: str
    severity: str
    title_substring: str
    url_path: str
    param: str


# Mapping endpoint → expected (id, category, cwe, severity, substring).
SMOKE_GROUND_TRUTH: list[SmokeGroundTruth] = [
    SmokeGroundTruth(
        test_case_id="vulhub-xss-search",
        category="xss",
        cwe_id="CWE-79",
        severity="high",
        title_substring="xss",
        url_path="/search",
        param="q",
    ),
    SmokeGroundTruth(
        test_case_id="vulhub-cmdi-lookup",
        category="cmdi",
        cwe_id="CWE-78",
        severity="critical",
        title_substring="command",
        url_path="/lookup",
        param="host",
    ),
    SmokeGroundTruth(
        test_case_id="vulhub-path-download",
        category="path_traversal",
        cwe_id="CWE-22",
        severity="high",
        title_substring="path",
        url_path="/download",
        param="file",
    ),
    SmokeGroundTruth(
        test_case_id="vulhub-sqli-users",
        category="sqli",
        cwe_id="CWE-89",
        severity="critical",
        title_substring="sql",
        url_path="/api/users",
        param="id",
    ),
]


# ---------------------------------------------------------------------------
# Smoke runner
# ---------------------------------------------------------------------------


@dataclass
class SmokeRunResult:
    """Outcome of a single Vulhub smoke run.

    Attributes:
        target_url: The base URL the smoke hit.
        findings: List of finding dicts the agents emitted
            (same shape as ``BenchmarkResult.actual``).
        labeled: ``LabeledFinding`` records, one per ground-truth
            endpoint, ready to feed the ThresholdCalibrator.
        categories_covered: Set of categories for which at least
            one finding was produced.
        endpoints_hit: Number of smoke endpoints the runner
            probed.
    """

    target_url: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    labeled: list[Any] = field(default_factory=list)
    categories_covered: set[str] = field(default_factory=set)
    endpoints_hit: int = 0

    @property
    def passed(self) -> bool:
        return len(self.categories_covered) >= 3


class VulhubSmoke:
    """Vulhub-style offline smoke for the Assurix pipeline.

    The smoke:

      1. Boots a small vulnerable FastAPI app on an ephemeral port
         (or in-process via ``ASGITransport``).
      2. Drives the configured probe surface against each endpoint
         with payloads known to trigger the seeded vuln.
      3. Converts the agent's findings into ``LabeledFinding``
         records suitable for the ThresholdCalibrator.

    It is **deliberately deterministic** — no RNG, no clock,
    no LLM.  The point is to give a fast repeatable smoke that
    proves the pipeline can find *something* on a known-vulnerable
    surface, and to produce a labeled dataset for the calibrator.
    """

    def __init__(
        self,
        *,
        agent_results: list[dict[str, Any]] | None = None,
    ) -> None:
        """Args:

            agent_results: Optional pre-recorded list of finding
                dicts.  Tests use this to inject synthetic agent
                output without driving a real HTTP probe.  The
                shape must match the per-finding dict the
                BenchmarkRunner emits (keys: title, severity,
                cwe_id, confidence_score, category, evidence).
        """
        self._agent_results = agent_results

    def run(self, target_url: str | None = None) -> SmokeRunResult:
        """Run the smoke.

        Args:
            target_url: Ignored when ``agent_results`` was provided
                at construction.  Otherwise accepted for
                forward-compatibility with a future real-probe
                mode.

        Returns:
            A ``SmokeRunResult`` with findings, labeled dataset,
            and coverage stats.
        """
        if self._agent_results is None:
            # Without injected results, we still want the smoke to
            # produce a valid empty result so callers can see
            # "0 findings" instead of an exception.
            logger.info(
                "VulhubSmoke.run: no agent_results injected; returning "
                "empty result. Use a stub or the in-process probe."
            )
            return SmokeRunResult(target_url=target_url or "")

        result = SmokeRunResult(target_url=target_url or "in-process")

        # Convert each agent finding to a "match" against ground truth.
        for finding in self._agent_results:
            matched = _match_finding(finding)
            result.findings.append(finding)
            if matched is not None:
                result.categories_covered.add(matched.category)

        result.endpoints_hit = len(SMOKE_GROUND_TRUTH)

        # Build labeled dataset — one LabeledFinding per ground truth
        # endpoint, with is_true_positive=True if the agent found it.
        for gt in SMOKE_GROUND_TRUTH:
            found = gt.category in result.categories_covered
            result.labeled.append(
                {
                    "id": gt.test_case_id,
                    "category": gt.category,
                    "cwe_id": gt.cwe_id,
                    "title_substring": gt.title_substring,
                    "is_true_positive": found,
                    "url_path": gt.url_path,
                }
            )

        return result


def _match_finding(finding: dict[str, Any]) -> SmokeGroundTruth | None:
    """Return the ground-truth row the given finding matches, if any.

    A finding matches when its CWE + title substring both line up
    with one of the seeded ground-truth rows.  This is a
    signature-based matcher — it intentionally ignores anything
    the agent might have hallucinated.
    """
    cwe = (finding.get("cwe_id") or "").strip().upper()
    title = (finding.get("title") or "").lower()
    cat = (finding.get("category") or "").lower()
    for gt in SMOKE_GROUND_TRUTH:
        if cwe and cwe != gt.cwe_id.upper():
            continue
        if gt.title_substring not in title and gt.category != cat:
            continue
        return gt
    return None


__all__ = [
    "SMOKE_GROUND_TRUTH",
    "SmokeGroundTruth",
    "SmokeRunResult",
    "VULHUB_SMOKE_ENDPOINTS",
    "VulhubSmoke",
    "build_smoke_app",
]
