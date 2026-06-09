#!/usr/bin/env python3
"""Run a full Assurix security scan against a target and generate reports.

Usage:
    python scripts/run_scan.py <target_url> [--timeout 600] [--research-loop]

Example:
    python scripts/run_scan.py https://dj1naq.sytes.net --timeout 600 --research-loop
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

# Add project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("assurix-scan")


async def run_scan(target_url: str, timeout: int = 600, use_research_loop: bool = False) -> dict:
    """Run the full Assurix pipeline against a target and return all results."""
    from sqlalchemy import select

    from src.db.models import Engagement, EngagementStatus, Finding, Target
    from src.db.session import get_db_session, init_db, dispose_engine
    from src.orchestrator.engine import WorkflowEngine
    from src.agents.planner import PlannerAgent
    from src.agents.planner_mcts import MCTSPlannerAgent
    from src.agents.reasoner import ReasonerAgent
    from src.agents.recon import ReconAgent
    from src.agents.reporter import ReporterAgent
    from src.agents.validation import ValidationAgent
    from src.agents.webapp import WebappAgent
    from src.agents.pentester import PentesterAgent
    from src.agents.research_loop import ResearchLoopAgent
    from src.benchmark.capability_scorer import score_finding

    await init_db()
    start_time = time.monotonic()

    try:
        async with get_db_session() as session:
            # Create or find target
            result = await session.execute(select(Target).where(Target.url == target_url))
            target = result.scalar_one_or_none()
            if target is None:
                target = Target(
                    name=target_url.replace("https://", "").replace("http://", "").split("/")[0],
                    url=target_url,
                    target_type="webapp",
                    verified=True,
                )
                session.add(target)
                await session.flush()
                logger.info("Created target: %s (id=%s)", target_url, target.id)
            else:
                logger.info("Found existing target: %s (id=%s)", target_url, target.id)

            # Create engagement
            config = {
                "max_iterations": 10,
                "use_research_loop": use_research_loop,
                "scan_mode": "full",
            }
            engagement = Engagement(
                target_id=target.id,
                status=EngagementStatus.PENDING,
                config=config,
            )
            session.add(engagement)
            await session.flush()
            logger.info("Created engagement: id=%s", engagement.id)

        # Set up engine with all agents
        engine = WorkflowEngine()
        engine.register("planner", PlannerAgent)
        engine.register("planner_mcts", MCTSPlannerAgent)
        engine.register("recon", ReconAgent)
        engine.register("webapp", WebappAgent)
        engine.register("pentester", PentesterAgent)
        engine.register("reasoner", ReasonerAgent)
        engine.register("validation", ValidationAgent)
        engine.register("reporter", ReporterAgent)
        engine.register("research_loop", ResearchLoopAgent)

        # Start engagement
        async with get_db_session() as session:
            await engine.start_engagement(
                session, engagement.id,
                target_url=target_url,
                extra_payload={"scan_mode": "full"},
            )
        engine.start()

        logger.info("Scan started — waiting for completion (timeout=%ds)...", timeout)

        # Wait for completion with timeout
        deadline = time.monotonic() + timeout
        last_status = "running"
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            async with get_db_session() as check_session:
                eng = await check_session.get(Engagement, engagement.id)
                if eng and eng.status in ("completed", "failed"):
                    last_status = eng.status
                    break
                if eng:
                    last_status = eng.status.value if hasattr(eng.status, "value") else str(eng.status)
                    elapsed = int(time.monotonic() - start_time)
                    logger.info(
                        "  [%ds] Engagement %s — status: %s, iterations: %d",
                        elapsed, engagement.id[:8], last_status, eng.iteration_count,
                    )
        else:
            logger.warning("Timeout reached after %ds — stopping engine", timeout)
            await engine.stop()

        await engine.stop()
        elapsed_total = time.monotonic() - start_time

        # Collect findings
        async with get_db_session() as session:
            rows = await session.execute(
                select(Finding).where(Finding.engagement_id == engagement.id)
            )
            db_findings = rows.scalars().all()

        findings_list = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
                "description": f.description,
                "evidence": f.finding_metadata or {},
                "confidence_score": f.confidence_score,
                "source_agent": f.source_agent,
                "remediation": f.remediation,
                "validated": f.validated,
            }
            for f in db_findings
        ]

        # Score with capability ladder
        cap_scores = [score_finding(f) for f in findings_list]

        # Determine risk rating
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_list:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

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

        # Surface data from recon (best effort — grab from the first finding metadata)
        surface = {}
        for f in db_findings:
            meta = f.finding_metadata or {}
            if "surface" in meta:
                surface = meta["surface"]
                break

        result = {
            "engagement_id": engagement.id,
            "target_url": target_url,
            "status": last_status,
            "elapsed_seconds": round(elapsed_total, 1),
            "findings": findings_list,
            "capability_scores": [
                {
                    "finding_type": cs.finding_type,
                    "capability_tier": cs.capability_tier,
                    "tier_label": cs.tier_label,
                    "tier_name": cs.tier_name,
                    "confidence": cs.confidence,
                }
                for cs in cap_scores
            ],
            "severity_counts": severity_counts,
            "risk_rating": risk_rating,
            "surface": surface,
            "total_findings": len(findings_list),
        }

        logger.info(
            "Scan complete: %d findings (%d critical, %d high, %d medium, %d low, %d info) — risk: %s",
            len(findings_list),
            severity_counts["critical"], severity_counts["high"],
            severity_counts["medium"], severity_counts["low"], severity_counts["info"],
            risk_rating.upper(),
        )

        return result

    finally:
        await dispose_engine()


def generate_reports(result: dict, output_dir: Path | None = None) -> dict[str, Path]:
    """Generate Markdown, JSON, and HTML reports from scan results."""
    from src.reporting.md_report import generate_report
    from src.reporting.html_report import generate_html_report

    engagement_id = result["engagement_id"]
    artifacts_dir = output_dir or Path("./data/artifacts")

    # Markdown report
    md_path = generate_report(
        engagement_id=engagement_id,
        target_url=result["target_url"],
        findings=result["findings"],
        surface=result.get("surface"),
        risk_rating=result["risk_rating"],
        artifacts_dir=artifacts_dir,
    )
    logger.info("Markdown report: %s", md_path)

    # HTML report
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

    # JSON report
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
    parser = argparse.ArgumentParser(description="Run full Assurix security scan")
    parser.add_argument("target_url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=600, help="Scan timeout in seconds (default: 600)")
    parser.add_argument("--research-loop", action="store_true", help="Use ResearchLoop (Mythos) for hypothesis-driven scanning")
    parser.add_argument("--output", type=str, default=None, help="Output directory for reports (default: ./data/artifacts)")
    args = parser.parse_args()

    target_url = args.target_url.rstrip("/")
    logger.info("=" * 60)
    logger.info("ASSURIX — Full Security Scan")
    logger.info("Target:    %s", target_url)
    logger.info("Timeout:   %ds", args.timeout)
    logger.info("ResearchLoop: %s", "ON" if args.research_loop else "OFF")
    logger.info("=" * 60)

    result = asyncio.run(run_scan(
        target_url=target_url,
        timeout=args.timeout,
        use_research_loop=args.research_loop,
    ))

    # Generate reports
    output_dir = Path(args.output) if args.output else None
    report_paths = generate_reports(result, output_dir)

    # Print summary
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
    print(f"\n  Reports:")
    for fmt, path in report_paths.items():
        print(f"    {fmt.upper():8s} {path}")
    print("=" * 60)

    return result


if __name__ == "__main__":
    main()