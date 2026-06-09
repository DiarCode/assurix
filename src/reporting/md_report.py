"""Markdown security report generator with LLM-enhanced narratives.

Reports are written to ``data/reports/<timestamp>_<target>_<engagement8>.md``
and a symlink to the most-recent report is maintained at
``data/reports/LATEST.md``. The collection folder is the single canonical
location for all reports — do not write reports under
``data/artifacts/<engagement_id>/`` anymore.

Deduplication (always on): when multiple findings share a ``dedup_key``,
only the highest-confidence one is rendered.

Strict finding gate (always on): findings missing (PoC, request/response,
confidence >= 0.30) are downgraded to ``info``. The strict gate is
non-negotiable — the legacy "warn-only" behavior is gone.
"""

import hashlib
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Fields the strict gate requires (top-level OR ``finding_metadata``).
_STRICT_GATE_REQUIRED_FIELDS = ("poc", "request_response")
_STRICT_GATE_MIN_CONFIDENCE = 0.30

# Canonical reports directory — single source of truth.
DEFAULT_REPORTS_DIR = Path("data/reports")


def _compute_dedup_key(
    url: str | None,
    attack_category: str | None,
    param: str | None,
) -> str:
    """Stable identity for a finding — sha256(url|category|param)[:16].

    Mirrors ``JSONReportGenerator._compute_dedup_key`` so MD and JSON
    reports agree on dedup keys. None is treated as the empty string.
    """
    parts = [
        (url or "").strip().lower(),
        (attack_category or "").strip().lower(),
        (param or "").strip().lower(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _apply_strict_gate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Downgrade findings missing (PoC, request/response, confidence).

    The strict gate is always on. A high/critical/medium finding that
    lacks any of the required fields OR has ``confidence_score < 0.30``
    is downgraded to ``info`` with a ``strict_gate_downgraded`` marker.
    """
    out: list[dict[str, Any]] = []
    for f in findings:
        severity = f.get("severity")
        if severity not in ("high", "critical", "medium"):
            out.append(f)
            continue

        metadata = f.get("finding_metadata") or {}
        missing: list[str] = []
        for field in _STRICT_GATE_REQUIRED_FIELDS:
            top = f.get(field)
            nested = metadata.get(field)
            value = top if (top and (not isinstance(top, str) or top.strip())) else nested
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append(field)
        try:
            conf = float(f.get("confidence_score") or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        if conf < _STRICT_GATE_MIN_CONFIDENCE:
            missing.append("confidence_score")

        if missing:
            f = dict(f)
            f["severity"] = "info"
            f["strict_gate_downgraded"] = missing
        out.append(f)
    return out


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group by ``dedup_key``; keep the highest-confidence entry per group.

    Findings with no ``dedup_key`` are kept as-is. Ties broken by
    stable insertion order (the first-seen entry wins).
    """
    best_by_key: dict[str, dict[str, Any]] = {}
    no_key: list[dict[str, Any]] = []

    for f in findings:
        key = f.get("dedup_key")
        if not key:
            no_key.append(f)
            continue
        if key not in best_by_key:
            best_by_key[key] = f
            continue
        try:
            prev_conf = float(best_by_key[key].get("confidence_score") or 0.0)
        except (TypeError, ValueError):
            prev_conf = 0.0
        try:
            cur_conf = float(f.get("confidence_score") or 0.0)
        except (TypeError, ValueError):
            cur_conf = 0.0
        if cur_conf > prev_conf:
            best_by_key[key] = f

    return list(best_by_key.values()) + no_key


def _sanitize_target_for_filename(target: str, max_len: int = 60) -> str:
    """Sanitize a target URL or domain for use in a filename."""
    s = target.strip()
    s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
    s = re.sub(r"[/\\:?&=#%<>|\s]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("._")
    if len(s) > max_len:
        s = s[:max_len].rstrip("_")
    return s or "unknown"


def _report_filename(engagement_id: str, target_url: str, now: datetime) -> str:
    """Build the canonical report filename.

    Pattern: ``<YYYYMMDD_HHMMSS>_<sanitized_target>_<engagement8>.md``
    where ``engagement8`` is the first 8 hex chars of the engagement id
    (UUID without dashes).
    """
    ts = now.strftime("%Y%m%d_%H%M%S")
    safe_target = _sanitize_target_for_filename(target_url)
    eng8 = engagement_id.replace("-", "")[:8]
    return f"{ts}_{safe_target}_{eng8}.md"


def _update_latest_symlink(report_path: Path, reports_dir: Path) -> None:
    """Point ``data/reports/LATEST.md`` at the freshly-written report."""
    latest = reports_dir / "LATEST.md"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(report_path.name)
    except OSError as exc:
        # Symlink may fail on some filesystems (e.g. Windows without
        # developer mode); fall back to copying is intentionally not
        # done — the symlink is best-effort.
        logger.debug("Could not update LATEST.md symlink: %s", exc)


def generate_report(
    engagement_id: str,
    target_url: str,
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]] | None = None,
    surface: dict[str, Any] | None = None,
    analysis_notes: str = "",
    risk_rating: str = "medium",
    artifacts_dir: Path | None = None,
    proofs_of_concept: list[dict[str, Any]] | None = None,
    *,
    raw_analysis_notes: str = "",
    llm_narrative: dict[str, Any] | None = None,
    methodology: dict[str, Any] | None = None,
    config: Any | None = None,
) -> Path:
    """Generate a structured Markdown security report.

    The report is written to ``data/reports/<timestamp>_<target>_<eng8>.md``
    and ``data/reports/LATEST.md`` is updated to point at it. Returns the
    absolute path of the generated report.

    Args:
        engagement_id: The engagement UUID.
        target_url: The target that was scanned.
        findings: List of validated findings (dicts).
        attack_paths: Optional list of attack-path dicts.
        surface: Optional attack-surface dict (technologies, pages, etc.).
        analysis_notes: Kept for API compatibility; superseded by
            ``raw_analysis_notes``. New callers should pass raw analyst
            notes through ``raw_analysis_notes`` so they render in the
            dedicated "Analyst Notes" section instead of the executive
            summary.
        risk_rating: One of "critical", "high", "medium", "low".
        artifacts_dir: Kept for API compatibility; ignored — the report
            always lands in ``data/reports/``.
        proofs_of_concept: Optional list of PoC dicts.
        raw_analysis_notes: Raw analyst notes from the previous agent's
            ``analysis_notes`` field. Rendered in their own section
            after the methodology so the LLM-driven executive summary
            isn't conflated with the raw notes (W1-C).
        llm_narrative: Optional pre-rendered narrative dict with keys
            ``executive_summary``, ``risk_assessment``, ``key_findings``,
            ``remediation_priority``, ``compliance_notes``. When the LLM
            fails to produce one, the caller passes None and the
            template falls back to a deterministic summary.
        methodology: Optional dict describing the kill-chain steps
            (timestamps, what was attempted, what was found).
        config: Kept for API compatibility; the strict gate is always on
            and the depth pass is always run by default.
    """
    # ``artifacts_dir`` is no longer honored; the canonical location is
    # ``data/reports/``. We accept the kwarg so older callers don't break.
    _ = artifacts_dir  # noqa: F841 — intentionally ignored

    reports_dir = DEFAULT_REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Apply strict gate + dedup before severity sorting. This mirrors
    # JSONReportGenerator's ordering so the two reports agree.
    findings = _apply_strict_gate(findings)
    findings = _deduplicate_findings(findings)

    now = datetime.now(UTC)
    timestamp_human = now.strftime("%Y-%m-%d %H:%M UTC")
    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4)
    )

    severity_counts: dict[str, int] = {}
    for f in sorted_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines: list[str] = [
        f"# Security Assessment Report",
        f"",
        f"**Target**: {target_url}  ",
        f"**Date**: {timestamp_human}  ",
        f"**Risk Rating**: {risk_rating.upper()}  ",
        f"**Engagement ID**: `{engagement_id}`",
        f"",
        f"---",
        f"",
    ]

    # Executive Summary — LLM narrative if present, deterministic fallback
    # if not. The template must always render, even if the LLM call failed
    # or returned garbage.
    lines.extend(_format_executive_summary(
        llm_narrative=llm_narrative,
        findings=sorted_findings,
        target_url=target_url,
        severity_counts=severity_counts,
    ))

    # Findings overview table
    lines.extend([
        f"### Findings Overview",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ])
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")

    # Methodology / kill-chain
    if methodology:
        lines.extend(_format_methodology(methodology))

    if surface:
        lines.extend(_format_surface(surface))

    # Raw analyst notes from the previous agent's ``analysis_notes``
    # field. Rendered after methodology, before findings, so the reader
    # sees the kill-chain summary, the surface map, and the operator's
    # notes in that order. The executive summary above is the LLM's
    # narrative; this section is the operator's raw notes — the two
    # must not be conflated (W1-C).
    if raw_analysis_notes:
        lines.extend(_format_analyst_notes(raw_analysis_notes))

    if sorted_findings:
        lines.extend([f"## Detailed Findings", f""])
        for i, f in enumerate(sorted_findings, 1):
            lines.extend(_format_finding(i, f))
    else:
        lines.extend(_format_zero_findings(target_url, surface, methodology))

    if attack_paths:
        lines.extend([f"## Attack Paths", f""])
        for ap in attack_paths:
            lines.extend(_format_attack_path(ap))

    if proofs_of_concept:
        lines.extend([f"## Proof of Concept", f""])
        for i, poc in enumerate(proofs_of_concept, 1):
            lines.extend(_format_poc(i, poc))

    lines.extend([
        f"---",
        f"",
        f"*Report generated by Assurix Autonomous Security Validation Platform*  ",
        f"*{timestamp_human}*",
    ])

    filename = _report_filename(engagement_id, target_url, now)
    report_path = reports_dir / filename
    report_path.write_text("\n".join(lines), encoding="utf-8")
    _update_latest_symlink(report_path, reports_dir)
    logger.info("Report written to %s", report_path)
    return report_path


def _format_executive_summary(
    llm_narrative: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    target_url: str,
    severity_counts: dict[str, Any],
) -> list[str]:
    """Render the executive summary section.

    Uses the LLM narrative when present and well-formed; otherwise
    falls back to a deterministic summary derived from the findings.
    The technical template MUST always render — a missing LLM is not a
    blocker for the report.

    Note: ``analysis_notes`` is no longer rendered here. The reporter
    passes raw analyst notes as a separate ``raw_analysis_notes``
    argument to ``generate_report``; they are rendered in their own
    ``## Analyst Notes`` section further down the report so the LLM
    summary and the raw notes are not conflated (W1-C).
    """
    lines: list[str] = [f"## Executive Summary", f""]
    has_findings = bool(findings)

    if llm_narrative and isinstance(llm_narrative, dict):
        exec_sum = (llm_narrative.get("executive_summary") or "").strip()
        risk_assess = (llm_narrative.get("risk_assessment") or "").strip()
        key_findings = llm_narrative.get("key_findings") or []
        if exec_sum:
            lines.append(exec_sum)
            lines.append("")
        if risk_assess:
            lines.append(f"**Risk assessment**: {risk_assess}")
            lines.append("")
        if key_findings:
            lines.append("**Key findings**:")
            for kf in key_findings[:5]:
                lines.append(f"- {kf}")
            lines.append("")
    else:
        # Deterministic fallback. The report is still useful — the
        # technical sections below carry the real evidence.
        total = sum(severity_counts.values())
        crit_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        if has_findings:
            lines.append(
                f"Assurix assessed **{target_url}** and identified **{total} "
                f"finding{'s' if total != 1 else ''}**, of which **{crit_high}** "
                f"are critical or high severity. The detailed findings section "
                f"below contains the full evidence, including request/response "
                f"excerpts and proof-of-concept payloads where available."
            )
        else:
            lines.append(
                f"Assurix assessed **{target_url}** end-to-end. The methodology "
                f"section below documents the kill-chain steps that were "
                f"attempted. No exploitable vulnerabilities were confirmed during "
                f"this assessment; the surface map and probed endpoints are "
                f"catalogued in the **Attack Surface** section for future "
                f"reference."
            )
        lines.append("")

    return lines


def _format_analyst_notes(raw_analysis_notes: str) -> list[str]:
    """Render the raw analyst notes in their own section.

    W1-C: the reporter used to conflate the LLM's ``executive_summary``
    with the raw notes (it passed ``analysis_notes=report_data.get(
    "executive_summary", analysis_notes)`` to ``generate_report``),
    which made the same narrative appear in two places. Now the raw
    notes — sourced from the previous agent's ``analysis_notes`` field
    or the kill-chain log — are rendered in their own section, after
    the methodology, so the executive summary stays a single
    non-duplicated narrative.
    """
    notes = (raw_analysis_notes or "").strip()
    if not notes:
        return []
    return [
        "## Analyst Notes",
        "",
        notes,
        "",
    ]


def _format_methodology(methodology: dict[str, Any]) -> list[str]:
    """Render the kill-chain methodology section with timestamps and what was attempted."""
    lines: list[str] = [f"## Methodology", f""]
    steps = methodology.get("steps") or []
    if steps:
        for i, step in enumerate(steps, 1):
            ts = step.get("timestamp", "")
            phase = step.get("phase", f"Step {i}")
            action = step.get("action", "")
            outcome = step.get("outcome", "")
            lines.append(f"### {i}. {phase}")
            if ts:
                lines.append(f"*Timestamp: {ts}*  ")
            if action:
                lines.append("")
                lines.append(action)
            if outcome:
                lines.append("")
                lines.append(f"**Outcome**: {outcome}")
            lines.append("")
    summary = methodology.get("summary", "")
    if summary:
        lines.append(f"### Summary")
        lines.append("")
        lines.append(summary)
        lines.append("")
    return lines


def _format_zero_findings(
    target_url: str,
    surface: dict[str, Any] | None,
    methodology: dict[str, Any] | None,
) -> list[str]:
    """Render the explicit 'no findings' section.

    This is the section that distinguishes a clean target from an
    inconclusive scan — the methodology is always documented, so a
    reader can see what was actually tried.
    """
    lines: list[str] = [
        f"## Findings",
        f"",
        f"**No exploitable vulnerabilities were confirmed during this assessment.**",
        f"",
        f"The reconnaissance and exploitation phases completed without "
        f"producing a finding that passed the strict validation gate "
        f"(see Methodology above for the full kill-chain recap). The "
        f"attack surface, all probed endpoints, and all credentials "
        f"tested are catalogued above. Re-running the scan against this "
        f"target may produce different results if the application's "
        f"behavior changes.",
        f"",
    ]
    return lines


def _format_surface(surface: dict[str, Any]) -> list[str]:
    lines: list[str] = ["## Attack Surface", ""]
    techs = surface.get("technologies", [])
    if techs:
        lines.append(f"**Technologies**: {', '.join(techs)}  ")
    pages = surface.get("pages", [])
    if pages:
        lines.append(f"**Pages discovered**: {len(pages)}  ")
    forms = surface.get("forms", [])
    if forms:
        lines.append(f"**Forms**: {len(forms)}  ")
    endpoints = surface.get("endpoints", [])
    if endpoints:
        lines.append(f"**Endpoints**: {len(endpoints)}  ")
    auth_pages = surface.get("auth_pages", [])
    if auth_pages:
        lines.append(f"**Auth pages**: {len(auth_pages)}  ")
    probed_paths = surface.get("probed_paths", [])
    if probed_paths:
        lines.append("")
        lines.append("**Paths probed** (returned 200):")
        for p in probed_paths[:50]:
            lines.append(f"- `{p}`")
    tested_credentials = surface.get("tested_credentials", [])
    if tested_credentials:
        lines.append("")
        lines.append("**Credentials tested against auth forms**:")
        for c in tested_credentials:
            lines.append(f"- `{c}`")
    lines.append("")
    return lines


def _format_finding(index: int, f: dict[str, Any]) -> list[str]:
    title = f.get("title", "Unknown Finding")
    severity = f.get("severity", "info").upper()
    description = f.get("description", "")
    owasp = f.get("owasp_category", "")
    cwe = f.get("cwe_id", "")
    confidence = f.get("confidence_score", 0)
    evidence = f.get("evidence", {})
    remediation = f.get("remediation", "")
    source = f.get("source_agent", "")

    lines = [
        f"### {index}. {title}",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Severity | **{severity}** |",
    ]
    if owasp:
        lines.append(f"| OWASP | {owasp} |")
    if cwe:
        lines.append(f"| CWE | {cwe} |")
    lines.append(f"| Confidence | {confidence:.0%} |")
    if source:
        lines.append(f"| Source | {source} |")
    # Surface the strict-gate downgrade so the reader knows the finding
    # was originally higher severity and was downgraded for missing
    # evidence or low confidence.
    if f.get("strict_gate_downgraded"):
        missing = f["strict_gate_downgraded"]
        lines.append(
            f"| Strict gate | Downgraded (missing: {', '.join(missing)}) |"
        )
    lines.append("")

    if description:
        lines.append(f"{description}")
        lines.append("")

    if evidence:
        lines.append("**Evidence**:")
        lines.append("```")
        for key, val in evidence.items() if isinstance(evidence, dict) else []:
            val_str = str(val)[:200]
            lines.append(f"  {key}: {val_str}")
        lines.append("```")
        lines.append("")

    if remediation:
        lines.append(f"**Remediation**: {remediation}")
        lines.append("")

    lines.append("---")
    lines.append("")
    return lines


def _format_attack_path(ap: dict[str, Any]) -> list[str]:
    name = ap.get("name", "Unnamed Attack Path")
    severity = ap.get("severity", "medium").upper()
    description = ap.get("description", "")
    steps = ap.get("steps", [])

    lines = [
        f"### {name} [{severity}]",
        "",
        f"{description}",
        "",
    ]
    if steps:
        lines.append("**Steps**:")
        for step in steps:
            lines.append(f"1. {step}")
        lines.append("")
    lines.append("---")
    lines.append("")
    return lines


def _format_poc(index: int, poc: dict[str, Any]) -> list[str]:
    title = poc.get("title", f"PoC {index}")
    poc_type = poc.get("poc_type", "unknown")
    command = poc.get("command", "")
    html_poc = poc.get("html_poc", "")
    description = poc.get("description", "")
    severity = poc.get("severity", "medium").upper()

    lines = [
        f"### {index}. {title} [{severity}]",
        "",
        f"**Type**: {poc_type}",
        "",
    ]
    if description:
        lines.append(f"{description}")
        lines.append("")
    if command:
        lines.append("**Command**:")
        lines.append("```bash")
        lines.append(command)
        lines.append("```")
        lines.append("")
    if html_poc:
        lines.append("**HTML Proof**:")
        lines.append("```html")
        lines.append(html_poc[:500])
        lines.append("```")
        lines.append("")
    lines.append("---")
    lines.append("")
    return lines
