#!/usr/bin/env python3
"""Run a direct Assurix scan — executes agents individually with per-agent timeouts.

This bypasses the WorkflowEngine loop and runs each agent directly,
collecting findings incrementally so nothing is lost on timeout.

Usage:
    python scripts/run_scan_direct.py <target_url> [--timeout 120]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("assurix-direct-scan")


async def run_with_timeout(coro, timeout: int, label: str):
    """Run a coroutine with a timeout, returning result or None."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %ds", label, timeout)
        return None
    except Exception as exc:
        logger.error("%s failed: %s", label, exc)
        return None


async def run_direct_scan(target_url: str, timeout_per_agent: int = 120) -> dict:
    """Run each Assurix agent directly with per-agent timeouts."""
    from src.db.session import init_db, dispose_engine
    from src.agents.recon import ReconAgent
    from src.agents.webapp import WebappAgent
    from src.agents.pentester import PentesterAgent
    from src.agents.reasoner import ReasonerAgent
    from src.agents.validation import ValidationAgent
    from src.benchmark.capability_scorer import score_finding

    await init_db()
    start_time = time.monotonic()

    # Mock session for agents (they need it for audit logging but we don't persist through it)
    from unittest.mock import AsyncMock, MagicMock, patch
    mock_session = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.add = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.get = AsyncMock()

    # The agents call log_action(session=...) on completion. The mock session
    # can't satisfy log_action's real SQL (it expects a row with .current_hash
    # attribute, not a coroutine). Python binds `from X import Y` at import
    # time, so we must patch the SYMBOL in each agent's namespace, not just
    # in src.core.audit. The engine-driven scan path doesn't have this
    # problem (real DB session).
    import contextlib
    _patchers: list = []
    # Only agents that do `from src.core.audit import log_action` carry the
    # symbol in their module namespace. pentester and validation do not.
    _AGENT_LOG_ACTION_MODULES = [
        "src.agents.recon",
        "src.agents.webapp",
        "src.agents.reasoner",
    ]
    for _modname in _AGENT_LOG_ACTION_MODULES:
        _p = patch(f"{_modname}.log_action", new=AsyncMock(return_value=None))
        _p.start()
        _patchers.append(_p)
    # Also patch the audit module itself for any code that calls it via
    # the audit module namespace.
    _patchers.append(patch("src.core.audit.log_action", new=AsyncMock(return_value=None)))
    _patchers[-1].start()

    all_findings: list[dict[str, Any]] = []
    surface: dict[str, Any] = {}
    scan_log: list[dict] = []

    # --- Phase 1: Reconnaissance ---
    logger.info("=" * 50)
    logger.info("PHASE 1: Reconnaissance (timeout: %ds)", timeout_per_agent)
    logger.info("=" * 50)
    recon = ReconAgent()
    recon_result = await run_with_timeout(
        recon.execute({"target_url": target_url}, mock_session),
        timeout_per_agent, "Recon",
    )
    if recon_result:
        surface = recon_result.get("surface", {})
        recon_findings = recon_result.get("findings", [])
        all_findings.extend(recon_findings)
        scan_log.append({
            "phase": "recon",
            "duration_s": "...",
            "findings": len(recon_findings),
            "pages": len(surface.get("pages", [])),
            "endpoints": len(surface.get("endpoints", [])),
            "forms": len(surface.get("forms", [])),
            "auth_pages": len(surface.get("auth_pages", [])),
        })
        logger.info(
            "Recon complete: %d pages, %d endpoints, %d forms, %d auth pages",
            len(surface.get("pages", [])),
            len(surface.get("endpoints", [])),
            len(surface.get("forms", [])),
            len(surface.get("auth_pages", [])),
        )
    else:
        logger.warning("Recon produced no results")

    # --- Phase 2: Webapp Agent ---
    logger.info("=" * 50)
    logger.info("PHASE 2: Webapp Security Testing (timeout: %ds)", timeout_per_agent)
    logger.info("=" * 50)
    webapp = WebappAgent()
    webapp_payload = {
        "target_url": target_url,
        "previous_result": {"surface": surface, "target_url": target_url},
    }
    webapp_result = await run_with_timeout(
        webapp.execute(webapp_payload, mock_session),
        timeout_per_agent, "Webapp",
    )
    if webapp_result:
        webapp_findings = webapp_result.get("findings", [])
        all_findings.extend(webapp_findings)
        scan_log.append({
            "phase": "webapp",
            "findings": len(webapp_findings),
            "tests_run": len(webapp_result.get("tests_run", [])),
        })
        logger.info("Webapp complete: %d findings", len(webapp_findings))

    # --- Phase 3: Pentester Agent ---
    logger.info("=" * 50)
    logger.info("PHASE 3: Active Pentesting (timeout: %ds)", timeout_per_agent * 3)
    logger.info("=" * 50)
    pentester = PentesterAgent()
    pentester_payload = {
        "target_url": target_url,
        "previous_result": {
            "surface": surface,
            "target_url": target_url,
            "suspicious_points": [],
        },
    }
    pentester_result = await run_with_timeout(
        pentester.execute(pentester_payload, mock_session),
        timeout_per_agent * 3, "Pentester",
    )
    if pentester_result:
        pentester_findings = pentester_result.get("findings", [])
        all_findings.extend(pentester_findings)
        scan_log.append({
            "phase": "pentester",
            "findings": len(pentester_findings),
        })
        logger.info("Pentester complete: %d findings", len(pentester_findings))

    # --- Phase 4: Validation ---
    logger.info("=" * 50)
    logger.info("PHASE 4: Validation (timeout: %ds)", timeout_per_agent)
    logger.info("=" * 50)
    validation = ValidationAgent()
    validation_payload = {
        "target_url": target_url,
        "previous_result": {
            "surface": surface,
            "findings": all_findings,
            "target_url": target_url,
        },
    }
    validation_result = await run_with_timeout(
        validation.execute(validation_payload, mock_session),
        timeout_per_agent, "Validation",
    )
    if validation_result:
        validated_findings = validation_result.get("findings", [])
        # Replace all_findings with validated set if available
        if validated_findings:
            all_findings = validated_findings
        scan_log.append({
            "phase": "validation",
            "findings": len(all_findings),
        })
        logger.info("Validation complete: %d validated findings", len(all_findings))

    elapsed_total = time.monotonic() - start_time

    # Deduplicate findings by title
    seen_titles: set[str] = set()
    unique_findings: list[dict] = []
    for f in all_findings:
        title = f.get("title", "")
        if title not in seen_titles:
            seen_titles.add(title)
            unique_findings.append(f)

    # Score with capability ladder
    cap_scores = [score_finding(f) for f in unique_findings]

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in unique_findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Risk rating
    if severity_counts["critical"] > 0:
        risk_rating = "critical"
    elif severity_counts["high"] > 2:
        risk_rating = "critical"
    elif severity_counts["high"] > 0:
        risk_rating = "high"
    elif severity_counts["medium"] > 3:
        risk_rating = "high"
    elif severity_counts["medium"] > 0:
        risk_rating = "medium"
    elif severity_counts["low"] > 0:
        risk_rating = "low"
    else:
        risk_rating = "informational"

    result = {
        "engagement_id": f"direct-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
        "target_url": target_url,
        "status": "completed",
        "elapsed_seconds": round(elapsed_total, 1),
        "findings": unique_findings,
        "capability_scores": [
            {
                "finding_type": cs.finding_type,
                "capability_tier": cs.capability_tier,
                "tier_label": cs.tier_label,
                "tier_name": cs.tier_name,
                "confidence": cs.confidence,
                "evidence": cs.evidence,
            }
            for cs in cap_scores
        ],
        "severity_counts": severity_counts,
        "risk_rating": risk_rating,
        "surface": surface,
        "total_findings": len(unique_findings),
        "scan_log": scan_log,
    }

    logger.info(
        "Scan complete: %d unique findings (C:%d H:%d M:%d L:%d I:%d) — risk: %s",
        len(unique_findings),
        severity_counts["critical"], severity_counts["high"],
        severity_counts["medium"], severity_counts["low"], severity_counts["info"],
        risk_rating.upper(),
    )

    await dispose_engine()
    for _p in _patchers:
        try:
            _p.stop()
        except Exception:
            pass  # idempotent stop
    return result


def generate_reports(result: dict, output_dir: Path | None = None) -> dict[str, Path]:
    """Generate all report formats."""
    from src.reporting.md_report import generate_report
    from src.reporting.html_report import generate_html_report

    engagement_id = result["engagement_id"]
    artifacts_dir = output_dir or Path("./data/artifacts")

    md_path = generate_report(
        engagement_id=engagement_id,
        target_url=result["target_url"],
        findings=result["findings"],
        surface=result.get("surface"),
        risk_rating=result["risk_rating"],
        artifacts_dir=artifacts_dir,
    )
    logger.info("Markdown report: %s", md_path)

    html_path = generate_html_report(
        engagement_id=engagement_id,
        target_url=result["target_url"],
        findings=result["findings"],
        capability_scores=result.get("capability_scores"),
        surface=result.get("surface"),
        risk_rating=result["risk_rating"],
        artifacts_dir=artifacts_dir,
    )
    logger.info("HTML report: %s", html_path)

    json_dir = artifacts_dir / engagement_id
    json_dir.mkdir(parents=True, exist_ok=True)
    json_path = json_dir / "report.json"
    json_path.write_text(
        json.dumps(result, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("JSON report: %s", json_path)

    return {"markdown": md_path, "html": html_path, "json": json_path}


def main():
    parser = argparse.ArgumentParser(description="Run direct Assurix security scan")
    parser.add_argument("target_url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=120, help="Per-agent timeout in seconds (default: 120)")
    parser.add_argument("--output", type=str, default=None, help="Output directory (default: ./data/artifacts)")
    args = parser.parse_args()

    target_url = args.target_url.rstrip("/")
    logger.info("=" * 60)
    logger.info("ASSURIX — Direct Security Scan")
    logger.info("Target:          %s", target_url)
    logger.info("Per-agent timeout: %ds", args.timeout)
    logger.info("=" * 60)

    result = asyncio.run(run_direct_scan(
        target_url=target_url,
        timeout_per_agent=args.timeout,
    ))

    output_dir = Path(args.output) if args.output else None
    report_paths = generate_reports(result, output_dir)

    sc = result["severity_counts"]
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print(f"  Target:     {result['target_url']}")
    print(f"  Status:     {result['status']}")
    print(f"  Duration:    {result['elapsed_seconds']}s")
    print(f"  Risk:       {result['risk_rating'].upper()}")
    print(f"\n  Findings:   {result['total_findings']}")
    print(f"    CRITICAL: {sc['critical']}")
    print(f"    HIGH:     {sc['high']}")
    print(f"    MEDIUM:   {sc['medium']}")
    print(f"    LOW:      {sc['low']}")
    print(f"    INFO:     {sc['info']}")
    print(f"\n  Capability Ladder:")
    for cs in result.get("capability_scores", []):
        print(f"    [{cs['tier_label']}] {cs['finding_type']}: {cs['tier_name']} (conf: {cs['confidence']:.0%})")
    print(f"\n  Reports:")
    for fmt, path in report_paths.items():
        print(f"    {fmt.upper():8s} {path}")
    print("=" * 60)


if __name__ == "__main__":
    main()