"""HypothesisGenerator: Generates hypothesis classes from pattern matching + LLM creativity.

The core of the Mythos ResearchLoop. Produces hypothesis classes by combining
pattern matching from VulnerabilityPatternLibrary with LLM-generated novel classes.
Merges and deduplicates the results.

Each hypothesis class represents a category of vulnerabilities to investigate,
e.g., "auth_bypass", "xss_reflected", "business_logic_workflow_skip".
"""

import logging
from typing import Any

from src.patterns.library import VulnerabilityPatternLibrary
from src.llm.frontier_client import UnifiedLLMClient
from src.llm.json_utils import extract_json_from_response

logger = logging.getLogger(__name__)

HYPOTHESIS_GENERATION_PROMPT = """You are a security research hypothesis generator for an autonomous penetration testing system.

Given the following target information, generate novel vulnerability hypothesis classes that go beyond
known OWASP patterns. Focus on business logic flaws, cross-service interactions, race conditions,
and other non-obvious vulnerabilities that pattern matching would miss.

Target surface data:
{surface_data}

Previous findings:
{findings_data}

Attack categories already covered by pattern matching:
{pattern_categories}

Generate a JSON array of hypothesis classes. Each hypothesis must have:
- "hypothesis_class": A short kebab-case name (e.g., "cart-price-manipulation", "payment-race-condition")
- "attack_category": One of: auth_bypass, injection, xss, csrf, ssrf, business_logic, race_condition,
  idor, misconfig, data_exposure, privilege_escalation, api_abuse, crypto_flaw
- "description": One sentence explaining what this hypothesis investigates
- "required_capabilities": List of tool capability tags needed to investigate (e.g., ["xss", "injection"], ["auth_bypass"])
- "falsification_criteria": How to determine this hypothesis is falsified (e.g., "No price manipulation possible after 3 attempts")
- "confidence": Initial confidence score (0.0-1.0)

IMPORTANT: Generate ONLY hypotheses that are NOT already in the pattern categories list above.
Focus on creative, non-obvious vulnerability classes that require deep understanding of business logic.
Generate 2-5 hypotheses. Return ONLY the JSON array, no other text."""

# Deduplication key components
# (attack_category, target_url_pattern, source) uniquely identifies a hypothesis


class HypothesisGenerator:
    """Generates hypothesis classes from pattern matching + LLM creativity.

    Pattern matching provides baseline coverage from VulnerabilityPatternLibrary.
    LLM creativity produces novel classes that patterns miss.
    Results are merged and deduplicated.
    """

    def __init__(self, llm_client: UnifiedLLMClient | None = None):
        self.pattern_library = VulnerabilityPatternLibrary()
        self.llm = llm_client

    async def generate_hypotheses(
        self,
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        knowledge_graph: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate hypothesis classes from both pattern matching and LLM creativity.

        Args:
            surface: Target surface data (technologies, endpoints, etc.)
            findings: Previous findings from earlier agents
            knowledge_graph: Optional knowledge graph from Codebase Intelligence

        Returns:
            List of hypothesis dicts with keys:
            - hypothesis_class: str
            - attack_category: str
            - description: str
            - source: "pattern_match" | "llm_generated"
            - required_capabilities: list[str]
            - falsification_criteria: str
            - confidence: float
        """
        # Phase 1: Pattern matching from VulnerabilityPatternLibrary
        pattern_hypotheses = self._match_patterns(surface)

        # Phase 2: LLM creativity for novel classes
        novel_hypotheses = []
        if self.llm:
            try:
                novel_hypotheses = await self._generate_novel(surface, findings, pattern_hypotheses)
            except Exception as e:
                logger.warning("LLM hypothesis generation failed: %s", e)

        # Phase 3: Merge and deduplicate
        return self._merge_and_dedup(pattern_hypotheses, novel_hypotheses)

    def _match_patterns(self, surface: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate hypothesis classes from pattern matching.

        Uses VulnerabilityPatternLibrary.get_applicable_patterns() to find
        patterns that match the target's technologies and surface data.
        """
        hypotheses = []
        applicable = self.pattern_library.get_applicable_patterns(surface)

        for pattern in applicable:
            # Map pattern category to attack_category
            hypothesis = {
                "hypothesis_class": pattern.name.lower().replace(" ", "_"),
                "attack_category": self._map_pattern_category(pattern.category),
                "description": pattern.description,
                "source": "pattern_match",
                "required_capabilities": self._infer_capabilities(pattern),
                "falsification_criteria": self._infer_falsification(pattern),
                "confidence": 0.6,  # Pattern-matched hypotheses start with medium confidence
            }
            hypotheses.append(hypothesis)

        return hypotheses

    async def _generate_novel(
        self,
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        pattern_hypotheses: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate novel hypothesis classes using LLM creativity.

        Produces hypotheses that pattern matching would miss:
        business logic flaws, cross-service interactions, race conditions, etc.
        """
        # Prepare surface data summary
        surface_data = self._summarize_surface(surface)
        findings_data = self._summarize_findings(findings)
        pattern_categories = [h["hypothesis_class"] for h in pattern_hypotheses]

        prompt = HYPOTHESIS_GENERATION_PROMPT.format(
            surface_data=surface_data,
            findings_data=findings_data,
            pattern_categories=", ".join(pattern_categories) if pattern_categories else "none",
        )

        try:
            response = await self.llm.generate(prompt)
            # UnifiedLLMClient doesn't have extract_json — call the helper directly
            hypotheses = extract_json_from_response(response)

            if not isinstance(hypotheses, list):
                logger.warning("LLM hypothesis generation returned non-list: %s", type(hypotheses))
                return []

            # Validate and clean LLM output
            valid_hypotheses = []
            for h in hypotheses:
                if not isinstance(h, dict):
                    continue
                # Ensure required fields
                if "hypothesis_class" not in h or "attack_category" not in h:
                    continue
                h["source"] = "llm_generated"
                h["confidence"] = min(1.0, max(0.0, float(h.get("confidence", 0.5))))
                h["required_capabilities"] = h.get("required_capabilities", [])
                h["falsification_criteria"] = h.get("falsification_criteria", "")
                valid_hypotheses.append(h)

            return valid_hypotheses

        except Exception as e:
            logger.error("LLM hypothesis generation failed: %s", e)
            return []

    def _merge_and_dedup(
        self,
        pattern_hypotheses: list[dict[str, Any]],
        novel_hypotheses: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Merge pattern-matched and LLM-generated hypotheses, deduplicating.

        Deduplication key: (attack_category, hypothesis_class, source)
        Two hypotheses with the same attack_category and similar hypothesis_class
        are considered duplicates regardless of source.
        """
        seen_keys: set[str] = set()
        merged: list[dict[str, Any]] = []

        # Process pattern hypotheses first (higher priority)
        for h in pattern_hypotheses:
            key = self._dedup_key(h)
            if key not in seen_keys:
                seen_keys.add(key)
                merged.append(h)

        # Then novel hypotheses, skipping duplicates
        for h in novel_hypotheses:
            key = self._dedup_key(h)
            if key not in seen_keys:
                seen_keys.add(key)
                merged.append(h)

        return merged

    @staticmethod
    def _dedup_key(hypothesis: dict[str, Any]) -> str:
        """Generate a deduplication key for a hypothesis.

        Key format: "{attack_category}:{hypothesis_class}"
        This ensures that pattern-matched and LLM-generated hypotheses
        with the same category and similar names are deduplicated.
        """
        category = hypothesis.get("attack_category", "").lower()
        hypothesis_class = hypothesis.get("hypothesis_class", "").lower()
        return f"{category}:{hypothesis_class}"

    @staticmethod
    def _map_pattern_category(owasp_category: str) -> str:
        """Map OWASP category to Mythos attack category."""
        category_map = {
            "A01:2021": "auth_bypass",       # Broken Access Control
            "A02:2021": "data_exposure",     # Cryptographic Failures
            "A03:2021": "injection",          # Injection
            "A04:2021": "business_logic",     # Insecure Design
            "A05:2021": "misconfig",          # Security Misconfiguration
            "A06:2021": "data_exposure",      # Vulnerable Components
            "A07:2021": "auth_bypass",       # Identification and Authentication Failures
            "A08:2021": "data_exposure",      # Software and Data Integrity Failures
            "A09:2021": "misconfig",          # Security Logging and Monitoring Failures
            "A10:2021": "ssrf",              # Server-Side Request Forgery
        }
        return category_map.get(owasp_category, "injection")

    @staticmethod
    def _infer_capabilities(pattern: "VulnerabilityPattern") -> list[str]:
        """Infer required tool capability tags from a vulnerability pattern."""
        name_lower = pattern.name.lower()
        capabilities = []

        if any(kw in name_lower for kw in ["xss", "script", "dom"]):
            capabilities.append("xss")
        if any(kw in name_lower for kw in ["sql", "injection", "sqli"]):
            capabilities.append("sqli")
        if any(kw in name_lower for kw in ["auth", "login", "session", "password"]):
            capabilities.append("auth_bypass")
        if any(kw in name_lower for kw in ["ssrf", "request", "fetch"]):
            capabilities.append("ssrf")
        if any(kw in name_lower for kw in ["csrf", "token", "cross-site"]):
            capabilities.append("csrf")
        if any(kw in name_lower for kw in ["idor", "object", "reference"]):
            capabilities.append("idor")
        if any(kw in name_lower for kw in ["race", "concurrent", "toctou"]):
            capabilities.append("race_condition")
        if any(kw in name_lower for kw in ["business", "logic", "workflow", "price"]):
            capabilities.append("business_logic")
        if any(kw in name_lower for kw in ["privilege", "escalation", "role"]):
            capabilities.append("privilege_escalation")
        if any(kw in name_lower for kw in ["upload", "file"]):
            capabilities.append("file_upload")
        if any(kw in name_lower for kw in ["rate", "limit", "brute"]):
            capabilities.append("rate_limiting")

        # Default to fuzzing if no specific capability matched
        if not capabilities:
            capabilities.append("fuzzing")

        return capabilities

    @staticmethod
    def _infer_falsification(pattern: "VulnerabilityPattern") -> str:
        """Infer falsification criteria from a vulnerability pattern."""
        name_lower = pattern.name.lower()

        if "xss" in name_lower:
            return "No reflected or stored script execution after 3 attempts with different payloads"
        if "sql" in name_lower or "injection" in name_lower:
            return "No SQL error messages or differential responses after 3 payload attempts"
        if "auth" in name_lower or "login" in name_lower:
            return "No unauthorized access after attempting 5 credential combinations and 2 session manipulation techniques"
        if "ssrf" in name_lower:
            return "No internal resource access or cloud metadata retrieval after 3 SSRF payload attempts"
        if "csrf" in name_lower:
            return "No state-changing action performed without valid CSRF token after 2 attempts"
        if "idor" in name_lower:
            return "No access to other users' resources after attempting 3 different ID values"
        if "race" in name_lower:
            return "No state inconsistency after 5 concurrent requests to the same endpoint"
        if "business" in name_lower or "logic" in name_lower:
            return "No business rule bypass after attempting 3 different manipulation techniques"
        if "privilege" in name_lower:
            return "No access to admin functions or other user's data after 3 privilege escalation attempts"
        return "No vulnerability confirmed after standard testing techniques"

    @staticmethod
    def _summarize_surface(surface: dict[str, Any]) -> str:
        """Create a concise summary of the target surface for LLM prompt."""
        if not surface:
            return "No surface data available"

        parts = []
        if "technologies" in surface:
            parts.append(f"Technologies: {', '.join(surface['technologies'][:10])}")
        if "pages" in surface:
            parts.append(f"Pages discovered: {len(surface['pages'])}")
        if "forms" in surface:
            parts.append(f"Forms discovered: {len(surface['forms'])}")
        if "endpoints" in surface:
            parts.append(f"Endpoints discovered: {len(surface['endpoints'])}")
        if "auth_pages" in surface:
            parts.append(f"Auth pages: {len(surface['auth_pages'])}")

        return "\n".join(parts) if parts else "Limited surface data available"

    @staticmethod
    def _summarize_findings(findings: list[dict[str, Any]]) -> str:
        """Create a concise summary of previous findings for LLM prompt."""
        if not findings:
            return "No previous findings available"

        summary_parts = []
        for f in findings[:10]:  # Limit to 10 most recent findings
            severity = f.get("severity", "unknown")
            title = f.get("title", "Unknown finding")
            category = f.get("owasp_category", "unknown")
            summary_parts.append(f"- [{severity}] {title} ({category})")

        return "\n".join(summary_parts)