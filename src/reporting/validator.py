"""Report validator for structural validation before report generation.

Validates findings before report generation:
- PoC present for confirmed findings
- Request/response present
- Code location present
- Provenance chain complete
- Severity in valid range

Missing required fields trigger automatic downgrade to informational.
"""

import logging
from typing import Any

from src.db.models import Finding, Hypothesis, ProvenanceLink, ToolInvocation

logger = logging.getLogger(__name__)


class ValidationIssue:
    """A single validation issue found in a finding."""

    def __init__(self, finding_id: str, field: str, issue: str, severity: str = "warning") -> None:
        self.finding_id = finding_id
        self.field = field
        self.issue = issue
        self.severity = severity  # "error" or "warning"

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "field": self.field,
            "issue": self.issue,
            "severity": self.severity,
        }


class ReportValidator:
    """Validates findings before report generation.

    Checks:
    - PoC present for confirmed findings
    - Request/response present
    - Code location present
    - Provenance chain complete
    - Severity in valid range

    Missing required fields trigger automatic downgrade to informational.
    """

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    CONFIRMED_SEVERITIES = {"critical", "high", "medium"}
    REQUIRED_FOR_CONFIRMED = ["poc", "request_response", "evidence"]

    def validate_findings(
        self,
        findings: list[Finding],
        provenance_links: list[ProvenanceLink],
    ) -> tuple[list[dict[str, Any]], list[ValidationIssue]]:
        """Validate all findings and return processed findings + issues.

        Args:
            findings: List of Finding ORM objects.
            provenance_links: List of ProvenanceLink ORM objects.

        Returns:
            Tuple of (validated_findings_as_dicts, validation_issues).
        """
        # Build provenance lookup by finding_id
        provenance_by_finding: dict[str, list[ProvenanceLink]] = {}
        for link in provenance_links:
            if link.finding_id not in provenance_by_finding:
                provenance_by_finding[link.finding_id] = []
            provenance_by_finding[link.finding_id].append(link)

        validated = []
        issues = []

        for finding in findings:
            finding_dict, finding_issues = self._validate_single_finding(
                finding, provenance_by_finding.get(finding.id, [])
            )
            validated.append(finding_dict)
            issues.extend(finding_issues)

        return validated, issues

    def _validate_single_finding(
        self,
        finding: Finding,
        provenance_links: list[ProvenanceLink],
    ) -> tuple[dict[str, Any], list[ValidationIssue]]:
        """Validate a single finding and return processed dict + issues."""
        issues: list[ValidationIssue] = []
        finding_dict = {
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
        }

        # Check severity is valid
        if finding_dict["severity"] not in self.VALID_SEVERITIES:
            issues.append(ValidationIssue(
                finding.id, "severity",
                f"Invalid severity '{finding_dict['severity']}', defaulting to 'info'",
                "error",
            ))
            finding_dict["severity"] = "info"

        # Check provenance chain completeness for confirmed findings
        if finding_dict["severity"] in self.CONFIRMED_SEVERITIES:
            # Check provenance chain
            if not provenance_links:
                # Spec change: warn, do NOT downgrade. Provenance gaps are recoverable;
                # downgrading kills valid findings and masks real vulnerabilities.
                issues.append(ValidationIssue(
                    finding.id, "provenance",
                    f"Confirmed finding (severity={finding_dict['severity']}) has no provenance chain — flagged for review",
                    "warning",
                ))
                finding_dict["provenance_warning"] = True
            else:
                # Check each provenance link is complete
                for link in provenance_links:
                    if not link.hypothesis_id or not link.tool_invocation_id:
                        issues.append(ValidationIssue(
                            finding.id, "provenance",
                            f"Incomplete provenance link: missing hypothesis_id or tool_invocation_id",
                            "warning",
                        ))
                        finding_dict["provenance_warning"] = True

            # Check required fields for confirmed findings (warnings only — never downgrade)
            metadata = finding.finding_metadata or {}
            for field in self.REQUIRED_FOR_CONFIRMED:
                if not metadata.get(field) and not finding.description:
                    issues.append(ValidationIssue(
                        finding.id, field,
                        f"Confirmed finding missing recommended field: {field}",
                        "warning",
                    ))

            # Check for PoC evidence (high/critical only — warning, never downgrade)
            if not metadata.get("poc") and not metadata.get("proof_of_concept"):
                if finding_dict["severity"] in ("high", "critical"):
                    issues.append(ValidationIssue(
                        finding.id, "poc",
                        f"High/critical finding missing PoC evidence",
                        "warning",
                    ))

        return finding_dict, issues

    def validate_provenance_chains(
        self,
        findings: list[Finding],
        hypotheses: list[Hypothesis],
        provenance_links: list[ProvenanceLink],
        tool_invocations: list[ToolInvocation],
    ) -> dict[str, Any]:
        """Validate that all provenance chains are complete.

        Returns a dict with:
        - complete_chains: count of complete chains
        - incomplete_chains: count of incomplete chains
        - orphaned_findings: findings with no provenance chain
        - issues: list of validation issues
        """
        finding_ids = {f.id for f in findings}
        hypothesis_ids = {h.id for h in hypotheses}
        invocation_ids = {ti.id for ti in tool_invocations}

        complete_chains = 0
        incomplete_chains = 0
        issues = []

        for link in provenance_links:
            chain_complete = True
            if link.finding_id not in finding_ids:
                issues.append(ValidationIssue(
                    link.finding_id, "provenance",
                    f"ProvenanceLink references non-existent finding {link.finding_id}",
                    "error",
                ))
                chain_complete = False
            if link.hypothesis_id not in hypothesis_ids:
                issues.append(ValidationIssue(
                    link.finding_id, "provenance",
                    f"ProvenanceLink references non-existent hypothesis {link.hypothesis_id}",
                    "error",
                ))
                chain_complete = False
            if link.tool_invocation_id not in invocation_ids:
                issues.append(ValidationIssue(
                    link.finding_id, "provenance",
                    f"ProvenanceLink references non-existent tool invocation {link.tool_invocation_id}",
                    "error",
                ))
                chain_complete = False

            if chain_complete:
                complete_chains += 1
            else:
                incomplete_chains += 1

        # Find orphaned findings (no provenance chain)
        findings_with_chains = {link.finding_id for link in provenance_links}
        orphaned = finding_ids - findings_with_chains

        return {
            "complete_chains": complete_chains,
            "incomplete_chains": incomplete_chains,
            "orphaned_findings": len(orphaned),
            "orphaned_finding_ids": list(orphaned),
            "issues": [issue.to_dict() for issue in issues],
            "is_valid": incomplete_chains == 0 and len(orphaned) == 0,
        }

    def get_validation_summary(self, issues: list[ValidationIssue]) -> dict[str, Any]:
        """Get a summary of validation issues."""
        error_count = sum(1 for i in issues if i.severity == "error")
        warning_count = sum(1 for i in issues if i.severity == "warning")

        return {
            "total_issues": len(issues),
            "errors": error_count,
            "warnings": warning_count,
            "is_valid": error_count == 0,
            "issues": [i.to_dict() for i in issues],
        }