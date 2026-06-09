"""HTML security report generator with styled, responsive layout."""

from __future__ import annotations

import html
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#6b7280",
}
SEVERITY_BG = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fffbeb",
    "low": "#f7fee7",
    "info": "#f3f4f6",
}

_CSS = """
:root { --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --text-dim: #94a3b8; --accent: #3b82f6; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 0; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-bottom: 1px solid var(--border); padding: 2rem 0; margin-bottom: 2rem; }
header .container { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
h1 { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.025em; }
h2 { font-size: 1.35rem; font-weight: 600; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
h3 { font-size: 1.1rem; font-weight: 600; margin: 1.5rem 0 0.75rem; }
.meta { color: var(--text-dim); font-size: 0.875rem; }
.badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.severity-badge { color: #fff; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; }
.card-value { font-size: 2rem; font-weight: 700; margin: 0.25rem 0; }
.card-label { font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }
.card.critical { border-left: 4px solid #dc2626; }
.card.high { border-left: 4px solid #ea580c; }
.card.medium { border-left: 4px solid #d97706; }
.card.low { border-left: 4px solid #65a30d; }
.card.info { border-left: 4px solid #6b7280; }
.finding { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; margin-bottom: 1rem; }
.finding-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
.finding-title { font-size: 1rem; font-weight: 600; }
.finding-meta { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 0.375rem; font-size: 0.7rem; background: var(--border); color: var(--text-dim); }
.finding-desc { color: var(--text-dim); font-size: 0.9rem; margin: 0.5rem 0; }
.evidence-block { background: #0f172a; border: 1px solid var(--border); border-radius: 0.5rem; padding: 0.75rem 1rem; margin: 0.5rem 0; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; overflow-x: auto; }
.risk-bar { height: 0.5rem; border-radius: 9999px; background: var(--border); overflow: hidden; margin: 0.5rem 0; }
.risk-fill { height: 100%; border-radius: 9999px; transition: width 0.5s; }
table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.875rem; }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }
th { color: var(--text-dim); font-weight: 500; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
.tier-badge { padding: 0.15rem 0.5rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600; }
.t1 { background: #7f1d1d; color: #fca5a5; }
.t2 { background: #78350f; color: #fdba74; }
.t3 { background: #713f12; color: #fcd34d; }
.t4 { background: #365314; color: #bef264; }
.t5 { background: #1e3a5f; color: #93c5fd; }
.attack-path { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1rem 1.25rem; margin-bottom: 0.75rem; }
.step-list { counter-reset: step; list-style: none; padding: 0; }
.step-list li { counter-increment: step; position: relative; padding-left: 2rem; margin-bottom: 0.5rem; font-size: 0.9rem; }
.step-list li::before { content: counter(step); position: absolute; left: 0; top: 0; width: 1.4rem; height: 1.4rem; border-radius: 50%; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: 600; }
footer { margin-top: 3rem; padding: 1.5rem 0; border-top: 1px solid var(--border); text-align: center; color: var(--text-dim); font-size: 0.8rem; }
@media (max-width: 640px) { .container { padding: 1rem; } .grid { grid-template-columns: repeat(2, 1fr); } }
"""


def generate_html_report(
    engagement_id: str,
    target_url: str,
    findings: list[dict[str, Any]],
    capability_scores: list[dict[str, Any]] | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
    surface: dict[str, Any] | None = None,
    mythos_metrics: dict[str, Any] | None = None,
    risk_rating: str = "medium",
    artifacts_dir: Path | None = None,
) -> Path:
    """Generate a styled HTML security assessment report.

    Returns the path to the generated HTML report file.
    """
    if artifacts_dir is None:
        artifacts_dir = Path("./data/artifacts")
    report_dir = artifacts_dir / engagement_id
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4)
    )

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in sorted_findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = sum(severity_counts.values())
    confirmed = severity_counts["critical"] + severity_counts["high"] + severity_counts["medium"]

    # Build HTML
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head>',
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"<title>Assurix Security Report — {html.escape(target_url)}</title>",
        f"<style>{_CSS}</style>",
        "</head><body>",
        # Header
        "<header><div class='container'>",
        f"<div><h1>🛡️ Assurix Security Report</h1>"
        f"<div class='meta'>{html.escape(target_url)} · {timestamp}</div></div>",
        f"<div><span class='badge severity-badge' style='background:{_risk_color(risk_rating)}'>"
        f"RISK: {html.escape(risk_rating.upper())}</span></div>",
        "</div></header>",
        "<div class='container'>",
    ]

    # --- Summary cards ---
    parts.append("<h2>📊 Executive Summary</h2>")
    parts.append("<div class='grid'>")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts[sev]
        parts.append(
            f"<div class='card {sev}'><div class='card-value'>{count}</div>"
            f"<div class='card-label'>{sev.upper()}</div></div>"
        )
    parts.append(f"<div class='card'><div class='card-value'>{total}</div><div class='card-label'>Total Findings</div></div>")
    parts.append(f"<div class='card'><div class='card-value'>{confirmed}</div><div class='card-label'>Confirmed</div></div>")
    parts.append("</div>")

    # Risk bar
    if total > 0:
        parts.append("<div class='risk-bar'>")
        offset = 0
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts[sev]
            if count > 0:
                pct = (count / total) * 100
                parts.append(
                    f"<div class='risk-fill' style='width:{pct:.1f}%;margin-left:{offset:.1f}%;"
                    f"background:{SEVERITY_COLORS[sev]}'></div>"
                )
                offset += pct
        parts.append("</div>")

    # --- Attack surface ---
    if surface:
        parts.append("<h2>🗺️ Attack Surface</h2>")
        parts.append("<div class='grid'>")
        techs = surface.get("technologies", [])
        parts.append(f"<div class='card'><div class='card-value'>{len(techs)}</div><div class='card-label'>Technologies</div></div>")
        pages = surface.get("pages", [])
        parts.append(f"<div class='card'><div class='card-value'>{len(pages)}</div><div class='card-label'>Pages</div></div>")
        endpoints = surface.get("endpoints", [])
        parts.append(f"<div class='card'><div class='card-value'>{len(endpoints)}</div><div class='card-label'>Endpoints</div></div>")
        forms = surface.get("forms", [])
        parts.append(f"<div class='card'><div class='card-value'>{len(forms)}</div><div class='card-label'>Forms</div></div>")
        parts.append("</div>")
        if techs:
            parts.append(f"<p><strong>Stack:</strong> {html.escape(', '.join(str(t) for t in techs))}</p>")

    # --- Mythos Metrics ---
    if mythos_metrics:
        parts.append("<h2>🔬 Mythos Metrics</h2>")
        parts.append("<div class='grid'>")
        for key, label, unit in [
            ("hypothesis_hit_rate", "Hypothesis Hit Rate", "%"),
            ("provenance_chain_completeness", "Provenance Completeness", "%"),
            ("novel_findings_vs_linear", "Novel vs Linear", ""),
            ("confirmed_hypotheses", "Confirmed Hypotheses", ""),
        ]:
            val = mythos_metrics.get(key, 0)
            if unit == "%":
                display = f"{val:.0%}"
            else:
                display = str(val)
            pass_key = key.replace("_", "_pass") if "pass" not in key else key
            # Find the matching pass flag
            pass_val = None
            for pk in (f"hit_rate_pass", f"provenance_pass", f"novel_pass", f"reflection_pass"):
                if pk.startswith(key.split("_")[0]):
                    pass_val = mythos_metrics.get(pk)
                    break
            status_icon = "✅" if pass_val else "❌" if pass_val is False else ""
            parts.append(
                f"<div class='card'><div class='card-value'>{display} {status_icon}</div>"
                f"<div class='card-label'>{label}</div></div>"
            )
        parts.append("</div>")
        overall = mythos_metrics.get("overall_pass", False)
        parts.append(
            f"<p>Overall Mythos: <span class='badge' style='background:{'#16a34a' if overall else '#dc2626'};color:#fff'>"
            f"{'PASS' if overall else 'FAIL'}</span></p>"
        )

    # --- Capability ladder ---
    if capability_scores:
        parts.append("<h2>🪜 Capability Ladder</h2>")
        tier_counts: dict[int, int] = {}
        for cs in capability_scores:
            tier = cs.get("capability_tier", 5)
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        tier_names = {1: "Full Control", 2: "Generic Primitive", 3: "Target-Specific", 4: "Crash/Report", 5: "Detection Only"}
        parts.append("<table><tr><th>Tier</th><th>Name</th><th>Count</th></tr>")
        for tier in sorted(tier_counts.keys()):
            count = tier_counts[tier]
            parts.append(
                f"<tr><td><span class='tier-badge t{tier}'>T{tier}</span></td>"
                f"<td>{html.escape(tier_names.get(tier, 'Unknown'))}</td>"
                f"<td>{count}</td></tr>"
            )
        parts.append("</table>")

    # --- Detailed findings ---
    parts.append("<h2>🔍 Detailed Findings</h2>")
    if not sorted_findings:
        parts.append("<p class='finding-desc'>No findings discovered.</p>")
    for i, f in enumerate(sorted_findings, 1):
        title = html.escape(f.get("title", "Unknown Finding"))
        severity = f.get("severity", "info").lower()
        sev_color = SEVERITY_COLORS.get(severity, "#6b7280")
        description = html.escape(f.get("description", ""))
        cwe_id = html.escape(f.get("cwe_id", "") or "")
        owasp = html.escape(f.get("owasp_category", "") or "")
        confidence = f.get("confidence_score", 0)
        source = html.escape(f.get("source_agent", "") or "")
        evidence = f.get("evidence", {})
        remediation = html.escape(f.get("remediation", "") or "")

        parts.append("<div class='finding'>")
        parts.append(f"<div class='finding-header'>")
        parts.append(f"<div class='finding-title'>{i}. {title}</div>")
        parts.append(f"<div class='finding-meta'>")
        parts.append(f"<span class='badge severity-badge' style='background:{sev_color}'>{severity.upper()}</span>")
        if cwe_id:
            parts.append(f"<span class='tag'>{cwe_id}</span>")
        if owasp:
            parts.append(f"<span class='tag'>{owasp}</span>")
        if source:
            parts.append(f"<span class='tag'>🤖 {source}</span>")
        parts.append("</div></div>")

        if description:
            parts.append(f"<p class='finding-desc'>{description}</p>")

        parts.append(f"<p style='font-size:0.8rem;color:var(--text-dim)'>Confidence: {confidence:.0%}</p>")

        if evidence:
            ev_str = _format_evidence(evidence)
            if ev_str:
                parts.append("<div class='evidence-block'>")
                parts.append(html.escape(ev_str[:2000]))
                parts.append("</div>")

        if remediation:
            parts.append(f"<p style='font-size:0.85rem;margin-top:0.5rem'>"
                         f"<strong>Remediation:</strong> {remediation}</p>")

        parts.append("</div>")

    # --- Attack paths ---
    if attack_paths:
        parts.append("<h2>⛓️ Attack Paths</h2>")
        for ap in attack_paths:
            name = html.escape(ap.get("name", ap.get("hypothesis_class", "Unnamed Path")))
            category = html.escape(ap.get("attack_category", ""))
            tools = ap.get("tools_used", [])
            steps = ap.get("steps", [])
            parts.append("<div class='attack-path'>")
            parts.append(f"<h3>{name}</h3>")
            if category:
                parts.append(f"<p class='finding-desc'>Category: {category}</p>")
            if tools:
                parts.append(f"<p style='font-size:0.85rem'>Tools: {', '.join(html.escape(str(t)) for t in tools)}</p>")
            if steps:
                parts.append("<ol class='step-list'>")
                for step in steps:
                    parts.append(f"<li>{html.escape(str(step))}</li>")
                parts.append("</ol>")
            parts.append("</div>")

    # Footer
    parts.append(
        f"<footer>"
        f"<p>Report generated by <strong>Assurix</strong> Autonomous Security Validation Platform</p>"
        f"<p>{timestamp} · Engagement {html.escape(engagement_id)}</p>"
        f"</footer>"
    )
    parts.append("</div></body></html>")

    report_path = report_dir / "report.html"
    report_path.write_text("\n".join(parts), encoding="utf-8")
    logger.info("HTML report written to %s", report_path)
    return report_path


def _risk_color(risk: str) -> str:
    return {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d"}.get(risk, "#6b7280")


def _format_evidence(evidence: Any) -> str:
    if isinstance(evidence, dict):
        lines = []
        for key, val in evidence.items():
            val_str = str(val)[:300]
            lines.append(f"{key}: {val_str}")
        return "\n".join(lines)
    if isinstance(evidence, str):
        return evidence[:500]
    return str(evidence)[:500]