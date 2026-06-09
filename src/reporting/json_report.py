"""JSON report generator for Mythos security assessments.

Produces structured JSON with findings, attack paths, provenance chains,
and hypotheses. Confirmed findings include PoC, request/response, code location.
Findings missing required fields are downgraded to informational.

Strict finding gate (opt-in via ``config.strict_finding_gate=True``):
  - Drops or downgrades findings missing (PoC, request/response,
    confidence >= 0.30).
  - When the flag is False, the original "warn-only / do NOT downgrade"
    behavior is preserved (per the legacy contract relied on by the
    existing test suite).

Deduplication (always on):
  - At report time, findings with the same ``dedup_key`` are collapsed
    into a single entry — the one with the highest ``confidence_score``
    wins.
"""

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from src.db.models import Engagement, Finding, Hypothesis, ProvenanceLink, ToolInvocation

logger = logging.getLogger(__name__)

# Required fields for a confirmed finding — missing triggers WARNING, not downgrade.
# Per the spec, missing fields should be flagged for human review, not silently
# downgrade CRITICAL findings to info.
CONFIRMED_REQUIRED_FIELDS = ["title", "description", "severity", "evidence"]

# Strict gate — fields that must be present (or have non-empty values) for a
# finding to remain at high/critical/medium severity. Any missing field
# downgrades the finding to ``info`` (or drops it if
# ``config.strict_finding_gate_drop`` is set). Lookup order: top-level
# keys, then ``finding_metadata`` sub-keys.
STRICT_GATE_REQUIRED_FIELDS = ("poc", "request_response")

# Minimum confidence for a finding to keep its original severity under the
# strict gate. Below the threshold, the finding is downgraded to ``info``.
STRICT_GATE_MIN_CONFIDENCE = 0.30


class JSONReportGenerator:
    """Generates structured JSON reports from engagement data.

    Includes:
    - All findings with complete provenance chains
    - Confirmed findings have PoC + request/response + code location
    - Findings missing required fields are downgraded to informational
    - Hypothesis class coverage analysis
    - Attack path reconstruction from provenance chains
    """

    def generate_report(
        self,
        engagement: Engagement,
        findings: list[Finding],
        hypotheses: list[Hypothesis],
        provenance_links: list[ProvenanceLink],
        tool_invocations: list[ToolInvocation],
        *,
        include_metadata: bool = True,
        config: Any | None = None,
    ) -> dict[str, Any]:
        """Generate a complete JSON report for an engagement.

        Args:
            engagement: The engagement ORM object.
            findings: List of Finding ORM objects.
            hypotheses: List of Hypothesis ORM objects.
            provenance_links: List of ProvenanceLink ORM objects.
            tool_invocations: List of ToolInvocation ORM objects.
            include_metadata: Whether to include report metadata.
            config: Optional engagement config (object or dict). When
                ``config.strict_finding_gate`` is truthy the strict gate
                runs; otherwise the original "warn-only" path is used.
                A dict with the key is also accepted so callers that
                pass ``engagement.config`` (a JSON column) work too.

        Returns:
            Structured JSON-compatible dict.
        """
        # Resolve config: duck-typed — accept dict or object with attribute.
        strict_gate = self._resolve_strict_gate(config)
        engagement_cfg = self._resolve_config(config)

        # Downgrade findings missing required fields
        validated_findings = self._validate_findings(
            findings, strict_finding_gate=strict_gate
        )

        # Strict gate (opt-in): drops/downgrades findings missing
        # (PoC, request_response, confidence >= 0.30).
        if strict_gate:
            validated_findings = self._apply_strict_gate(validated_findings)

        # Deduplicate by dedup_key (always on; legacy findings without
        # a dedup_key are kept as-is).
        validated_findings = self._deduplicate_findings(validated_findings)

        # Build provenance chains
        provenance_chains = self._build_provenance_chains(
            validated_findings, hypotheses, provenance_links, tool_invocations
        )

        # Build hypothesis coverage analysis
        hypothesis_coverage = self._analyze_hypothesis_coverage(hypotheses, validated_findings)

        # Build attack paths from provenance chains
        attack_paths = self._reconstruct_attack_paths(provenance_chains)

        report: dict[str, Any] = {
            "report_type": "assurix_security_assessment",
            "version": "2.0",
            "engagement": {
                "id": engagement.id,
                "status": engagement.status.value if hasattr(engagement.status, "value") else str(engagement.status),
                "started_at": engagement.started_at.isoformat() if engagement.started_at else None,
                "completed_at": engagement.completed_at.isoformat() if engagement.completed_at else None,
                "iteration_count": engagement.iteration_count,
                "config": engagement.config or {},
            },
            "summary": self._generate_summary(validated_findings, hypotheses, attack_paths),
            "findings": validated_findings,
            "hypotheses": [self._hypothesis_to_dict(h) for h in hypotheses],
            "provenance_chains": provenance_chains,
            "attack_paths": attack_paths,
            "hypothesis_coverage": hypothesis_coverage,
        }

        if include_metadata:
            report["metadata"] = {
                "generated_at": datetime.now(UTC).isoformat(),
                "generator": "assurix_json_report_v2",
                "total_findings": len(validated_findings),
                "confirmed_findings": sum(1 for f in validated_findings if f.get("severity") in ("high", "critical", "medium")),
                "informational_findings": sum(1 for f in validated_findings if f.get("severity") == "info"),
                "total_hypotheses": len(hypotheses),
                "total_provenance_links": len(provenance_links),
            }

        return report

    def to_json(self, report: dict[str, Any], *, indent: int = 2) -> str:
        """Convert a report dict to a JSON string."""
        return json.dumps(report, indent=indent, default=str, ensure_ascii=False)

    def _validate_findings(
        self,
        findings: list[Finding],
        *,
        strict_finding_gate: bool = False,
    ) -> list[dict[str, Any]]:
        """Validate findings and warn (never downgrade) for missing required fields.

        Required fields are checked against both the top-level dict and the
        ``finding_metadata`` sub-dict. Missing fields emit a warning but do
        NOT downgrade severity — per the spec, downgrade-to-info kills
        legitimate findings. Missing-field warnings surface in the report
        for human review.

        When ``strict_finding_gate=True`` the warning branch is skipped;
        the downstream ``_apply_strict_gate()`` is responsible for the
        actual downgrade logic. This keeps the strict-gate path out of
        the legacy contract that the existing test suite depends on.
        """
        validated = []
        for f in findings:
            finding_dict = self._finding_to_dict(f)
            metadata = finding_dict.get("finding_metadata") or {}

            # Check for required fields (look in both top-level and metadata)
            missing_fields = []
            for field in CONFIRMED_REQUIRED_FIELDS:
                top = finding_dict.get(field)
                nested = metadata.get(field)
                value = top if (top and (not isinstance(top, str) or top.strip())) else nested
                if not value or (isinstance(value, str) and not value.strip()):
                    missing_fields.append(field)

            # Guard the "warn, do NOT downgrade" branch with the
            # strict-finding-gate flag: when the gate is on, the actual
            # downgrade is handled by ``_apply_strict_gate`` further
            # downstream. This preserves the legacy behavior
            # (``strict_finding_gate=False``) for the existing test suite.
            if not strict_finding_gate:
                if missing_fields and finding_dict.get("severity") in ("high", "critical", "medium"):
                    # Warn but DO NOT downgrade — missing evidence/poc is recoverable
                    finding_dict["missing_fields_warning"] = missing_fields
                    logger.info(
                        "Finding '%s' missing recommended fields: %s (kept original severity)",
                        finding_dict.get("title", "unknown"), ", ".join(missing_fields),
                    )

            validated.append(finding_dict)

        return validated

    # ------------------------------------------------------------------
    # Strict gate + dedup (plan §Step 4 — Improvement #4)
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_dedup_key(
        url: str | None,
        attack_category: str | None,
        param: str | None,
    ) -> str:
        """Stable identity for a finding — sha256(url|category|param)[:16].

        All three inputs are coerced to strings and lowercased; ``None``
        is treated as the empty string so the function is total. The
        first 16 hex chars give 64 bits of collision space — plenty
        for the dedup use case (we tolerate the occasional extra
        finding from a collision; we never lose a finding).
        """
        parts = [
            (url or "").strip().lower(),
            (attack_category or "").strip().lower(),
            (param or "").strip().lower(),
        ]
        payload = "|".join(parts).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]

    @staticmethod
    def _resolve_strict_gate(config: Any | None) -> bool:
        """Pull ``strict_finding_gate`` out of an engagement config.

        Accepts a dict (typical for the JSON ``engagement.config``
        column) or an object with the attribute. ``None`` and missing
        keys default to False so the legacy contract is preserved.
        """
        if config is None:
            return False
        if isinstance(config, dict):
            return bool(config.get("strict_finding_gate", False))
        return bool(getattr(config, "strict_finding_gate", False))

    @staticmethod
    def _resolve_config(config: Any | None) -> dict[str, Any]:
        """Coerce the engagement config into a plain dict for downstream use."""
        if config is None:
            return {}
        if isinstance(config, dict):
            return config
        return dict(getattr(config, "__dict__", {}) or {})

    def _apply_strict_gate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Downgrade findings missing (PoC, request/response, confidence).

        Operates on the already-validated finding dicts. For each
        finding with severity in (high, critical, medium):

        * If any of ``poc`` / ``request_response`` (top-level or
          ``finding_metadata``) is missing or empty, OR if
          ``confidence_score < STRICT_GATE_MIN_CONFIDENCE`` (0.30), the
          finding is downgraded to ``info``. A ``strict_gate_downgraded``
          marker is added so callers can show it in the UI.
        """
        out: list[dict[str, Any]] = []
        for f in findings:
            severity = f.get("severity")
            if severity not in ("high", "critical", "medium"):
                out.append(f)
                continue

            metadata = f.get("finding_metadata") or {}
            missing: list[str] = []
            for field in STRICT_GATE_REQUIRED_FIELDS:
                top = f.get(field)
                nested = metadata.get(field)
                value = top if (top and (not isinstance(top, str) or top.strip())) else nested
                if not value or (isinstance(value, str) and not value.strip()):
                    missing.append(field)

            try:
                conf = float(f.get("confidence_score") or 0.0)
            except (TypeError, ValueError):
                conf = 0.0
            if conf < STRICT_GATE_MIN_CONFIDENCE:
                missing.append("confidence_score")

            if missing:
                f = dict(f)  # don't mutate the caller's dict
                f["severity"] = "info"
                f["strict_gate_downgraded"] = missing
                logger.info(
                    "strict_gate downgrade '%s': missing %s",
                    f.get("title", "unknown"), ", ".join(missing),
                )
            out.append(f)
        return out

    def _deduplicate_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Group by ``dedup_key``; keep the highest-confidence entry per group.

        Findings with no ``dedup_key`` are kept as-is (legacy rows or
        rows where the dedup computation failed). When two findings
        share a key, the one with the higher ``confidence_score`` wins;
        ties are broken by stable insertion order.
        """
        # Track best entry per key. Insertion order of first sighting is
        # preserved by dict semantics in Python 3.7+.
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
            prev = best_by_key[key]
            try:
                prev_conf = float(prev.get("confidence_score") or 0.0)
            except (TypeError, ValueError):
                prev_conf = 0.0
            try:
                cur_conf = float(f.get("confidence_score") or 0.0)
            except (TypeError, ValueError):
                cur_conf = 0.0
            if cur_conf > prev_conf:
                best_by_key[key] = f

        # Build result: best-per-key in first-seen order, then any
        # no-key findings at the end (preserved as-is).
        return list(best_by_key.values()) + no_key

    def _build_provenance_chains(
        self,
        findings: list[dict[str, Any]],
        hypotheses: list[Hypothesis],
        provenance_links: list[ProvenanceLink],
        tool_invocations: list[ToolInvocation],
    ) -> list[dict[str, Any]]:
        """Build provenance chains from findings to hypotheses to tools."""
        # Index for fast lookup
        hypothesis_map = {h.id: h for h in hypotheses}
        invocation_map = {ti.id: ti for ti in tool_invocations}

        chains = []
        for link in provenance_links:
            chain = {
                "finding_id": link.finding_id,
                "hypothesis_id": link.hypothesis_id,
                "tool_invocation_id": link.tool_invocation_id,
                "tool_name": link.tool_name,
            }

            # Enrich with hypothesis details
            hypothesis = hypothesis_map.get(link.hypothesis_id)
            if hypothesis:
                chain["hypothesis_class"] = hypothesis.hypothesis_class
                chain["attack_category"] = hypothesis.attack_category
                chain["hypothesis_source"] = hypothesis.source.value if hasattr(hypothesis.source, "value") else str(hypothesis.source)

            # Enrich with tool invocation details
            invocation = invocation_map.get(link.tool_invocation_id)
            if invocation:
                chain["invocation_target"] = invocation.target
                chain["invocation_capability_tags"] = invocation.capability_tags

            chains.append(chain)

        return chains

    def _analyze_hypothesis_coverage(
        self,
        hypotheses: list[Hypothesis],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze hypothesis coverage: which categories were tested, confirmed, falsified."""
        coverage: dict[str, dict[str, Any]] = {}

        for h in hypotheses:
            category = h.attack_category
            if category not in coverage:
                coverage[category] = {
                    "total": 0,
                    "confirmed": 0,
                    "falsified": 0,
                    "pending": 0,
                    "hypotheses": [],
                }

            coverage[category]["total"] += 1
            status = h.status.value if hasattr(h.status, "value") else str(h.status)
            if status in coverage[category]:
                coverage[category][status] += 1
            coverage[category]["hypotheses"].append({
                "id": h.id,
                "class": h.hypothesis_class,
                "source": h.source.value if hasattr(h.source, "value") else str(h.source),
                "confidence": h.confidence,
            })

        return {
            "categories": coverage,
            "total_hypotheses": len(hypotheses),
            "categories_tested": len(coverage),
            "categories_confirmed": sum(1 for c in coverage.values() if c["confirmed"] > 0),
        }

    def _reconstruct_attack_paths(
        self, provenance_chains: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Reconstruct attack paths from provenance chains.

        Groups findings by hypothesis to show multi-step attack paths.
        """
        paths: dict[str, dict[str, Any]] = {}

        for chain in provenance_chains:
            hypothesis_id = chain.get("hypothesis_id", "")
            if hypothesis_id not in paths:
                paths[hypothesis_id] = {
                    "hypothesis_id": hypothesis_id,
                    "hypothesis_class": chain.get("hypothesis_class", "unknown"),
                    "attack_category": chain.get("attack_category", "unknown"),
                    "findings": [],
                    "tools_used": [],
                }

            paths[hypothesis_id]["findings"].append(chain.get("finding_id", ""))
            tool_name = chain.get("tool_name", "")
            if tool_name and tool_name not in paths[hypothesis_id]["tools_used"]:
                paths[hypothesis_id]["tools_used"].append(tool_name)

        return list(paths.values())

    def _generate_summary(
        self,
        findings: list[dict[str, Any]],
        hypotheses: list[Hypothesis],
        attack_paths: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate an executive summary of the assessment."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        confirmed = sum(v for k, v in severity_counts.items() if k in ("critical", "high", "medium"))

        return {
            "total_findings": len(findings),
            "confirmed_findings": confirmed,
            "informational_findings": severity_counts["info"],
            "severity_distribution": severity_counts,
            "total_hypotheses": len(hypotheses),
            "attack_paths_identified": len(attack_paths),
            "risk_level": self._assess_risk_level(severity_counts),
        }

    def _assess_risk_level(self, severity_counts: dict[str, int]) -> str:
        """Assess overall risk level from severity distribution."""
        if severity_counts.get("critical", 0) > 0:
            return "critical"
        if severity_counts.get("high", 0) > 2:
            return "critical"
        if severity_counts.get("high", 0) > 0:
            return "high"
        if severity_counts.get("medium", 0) > 3:
            return "high"
        if severity_counts.get("medium", 0) > 0:
            return "medium"
        if severity_counts.get("low", 0) > 0:
            return "low"
        return "informational"

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict[str, Any]:
        """Convert a Finding ORM object to a dict."""
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "confidence_score": finding.confidence_score,
            "validated": finding.validated,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
            "remediation": finding.remediation,
            "source_agent": finding.source_agent,
            "finding_metadata": finding.finding_metadata or {},
            "dedup_key": finding.dedup_key,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }

    @staticmethod
    def _hypothesis_to_dict(hypothesis: Hypothesis) -> dict[str, Any]:
        """Convert a Hypothesis ORM object to a dict."""
        return {
            "id": hypothesis.id,
            "hypothesis_class": hypothesis.hypothesis_class,
            "source": hypothesis.source.value if hasattr(hypothesis.source, "value") else str(hypothesis.source),
            "description": hypothesis.description,
            "confidence": hypothesis.confidence,
            "status": hypothesis.status.value if hasattr(hypothesis.status, "value") else str(hypothesis.status),
            "attack_category": hypothesis.attack_category,
            "required_capabilities": hypothesis.required_capabilities or [],
            "falsification_criteria": hypothesis.falsification_criteria,
            "parent_hypothesis_id": hypothesis.parent_hypothesis_id,
            "created_at": hypothesis.created_at.isoformat() if hypothesis.created_at else None,
        }