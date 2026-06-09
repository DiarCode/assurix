"""ToolRegistry: Discovers, selects, and manages Mythos tools.

The registry maintains a catalog of all ToolProtocol implementations.
The ResearchLoop uses it to select tools that match a hypothesis's
required_capabilities.

During Phase 1, only the first 5 migrated tools are in the registry.
The remaining 13+ tools continue via direct method calls in PentesterAgent.
The registry grows as tools are migrated in Phase 3.
"""

import logging
from typing import Any

from src.agents.tools.protocol import ToolProtocol
from src.schemas.tools import ToolCapability, ToolResult

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Central registry for ToolProtocol implementations.

    Supports registration by name, selection by capability tags,
    and listing all available tools. Used by ResearchLoop to
    dispatch investigations to the right tool based on hypothesis
    requirements.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolProtocol] = {}
        self._capability_index: dict[str, set[str]] = {}  # tag -> set of tool names
        # Skill layer (plan §5.9). The ToolRegistry holds a
        # reference to the SkillRegistry so callers can do
        # ``tool_registry.skills_matching(caps)`` without
        # importing both modules. The SkillRegistry is its own
        # catalog with its own lifecycle (see
        # ``src/agents/tools/skill.py``); we just keep a
        # reference here for ergonomic dispatch.
        from src.agents.tools.skill import get_skill_registry
        self.skills: Any = get_skill_registry()

    def skills_matching(self, required_capabilities: list[str]) -> list[Any]:
        """Delegate to the SkillRegistry (plan §5.9).

        Returns skills whose preconditions are satisfied by
        ``required_capabilities``, ordered by coverage. The
        SkillRegistry's full API is in ``skill.py``; this method
        is the convenience pass-through.
        """
        return self.skills.skills_matching(required_capabilities)

    def register(self, tool: ToolProtocol) -> None:
        """Register a tool implementation.

        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        if tool.name in self._tools:
            logger.warning("ToolRegistry: overwriting existing tool '%s'", tool.name)

        self._tools[tool.name] = tool

        # Index by capability tags for fast lookup
        for tag in tool.capability_tags:
            if tag not in self._capability_index:
                self._capability_index[tag] = set()
            self._capability_index[tag].add(tool.name)

        logger.info("ToolRegistry: registered tool '%s' with tags %s", tool.name, tool.capability_tags)

    def get(self, name: str) -> ToolProtocol | None:
        """Get a tool by name.

        Returns:
            The tool instance, or None if not found.
        """
        return self._tools.get(name)

    def select_by_tags(self, required_capabilities: list[str]) -> list[ToolProtocol]:
        """Select tools that match any of the required capabilities.

        Returns tools ordered by how many capabilities they match
        (most specific match first).

        Args:
            required_capabilities: List of capability tags from a hypothesis.

        Returns:
            List of tools that match at least one required capability,
            ordered by match count (descending).
        """
        if not required_capabilities:
            return list(self._tools.values())

        # Score each tool by how many required capabilities it matches
        tool_scores: dict[str, int] = {}
        for tag in required_capabilities:
            matching_tool_names = self._capability_index.get(tag, set())
            for name in matching_tool_names:
                tool_scores[name] = tool_scores.get(name, 0) + 1

        # Sort by score (descending), then by name for stability
        sorted_names = sorted(tool_scores.keys(), key=lambda n: (-tool_scores[n], n))

        result = []
        for name in sorted_names:
            tool = self._tools.get(name)
            if tool is not None:
                result.append(tool)

        return result

    def select_best(self, required_capabilities: list[str]) -> ToolProtocol | None:
        """Select the single best tool for the given capabilities.

        Returns the tool with the highest match count. Ties are broken
        by registration order.

        Args:
            required_capabilities: List of capability tags from a hypothesis.

        Returns:
            The best matching tool, or None if no match.
        """
        tools = self.select_by_tags(required_capabilities)
        return tools[0] if tools else None

    def list_tools(self) -> list[dict[str, Any]]:
        """List all registered tools with their capabilities.

        Returns:
            List of dicts with 'name' and 'capabilities' keys.
        """
        return [
            {"name": name, "capabilities": tool.describe_capabilities()}
            for name, tool in self._tools.items()
        ]

    def list_capability_tags(self) -> list[str]:
        """List all unique capability tags across all tools.

        Returns:
            Sorted list of unique capability tags.
        """
        return sorted(self._capability_index.keys())

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered by name."""
        return name in self._tools

    @property
    def tool_count(self) -> int:
        """Number of registered tools."""
        return len(self._tools)


# Global singleton registry instance
_registry = ToolRegistry()


def get_registry() -> ToolRegistry:
    """Get the global ToolRegistry singleton."""
    return _registry


def register_all_native_tools() -> None:
    """Register all native ToolProtocol implementations.

    Called during application startup to populate the registry.
    Only registers tools that have been migrated to ToolProtocol;
    other tools continue via direct method calls in PentesterAgent.
    """
    from src.agents.tools.fuzzer import Fuzzer
    from src.agents.tools.auth_tester import AuthTester
    from src.agents.tools.race_hunter import RaceHunter
    from src.agents.tools.vuln_pipelines import XSSPipeline, SQLiPipeline, SSRFPipeline

    registry = get_registry()

    # Register the first batch of native tools (Phase 1)
    fuzzer = Fuzzer()
    if hasattr(fuzzer, 'capability_tags'):
        registry.register(Fuzzer())
    else:
        # Wrap existing tools that don't implement ToolProtocol yet
        registry.register(FuzzerAdapter())

    registry.register(AuthTesterAdapter())
    registry.register(XSSPipelineAdapter())
    registry.register(SQLiPipelineAdapter())
    registry.register(SSRFPipelineAdapter())
    # Week 2: race condition hunter (plan §3.2.2) — native ToolProtocol
    registry.register(RaceHunter())

    logger.info("ToolRegistry: registered %d native tools", registry.tool_count)

    # Week 3: Skill layer (plan §5.9). Registers the 9 first-class
    # Skills in the companion SkillRegistry. The SkillRegistry
    # is independent of the ToolRegistry — the ResearchLoop
    # queries both: tools for raw capability, skills for the
    # preconditions → effects mapping. The skill catalog wraps
    # the registered tools above; the wrapped tool_name on each
    # skill resolves to a real tool here.
    from src.agents.tools.skill import register_default_skills
    n_skills = register_default_skills()
    logger.info("ToolRegistry: registered %d default skills", n_skills)


class FuzzerAdapter(ToolProtocol):
    """Adapter wrapping existing Fuzzer as a ToolProtocol implementation.

    This is a native ToolProtocol implementation for the Fuzzer tool,
    providing capability tags and hypothesis-aware execution.
    """

    name = "fuzzer"
    capability_tags = ["fuzzing", "injection", "parameter_tampering"]

    async def run(self, target: str, hypothesis: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> ToolResult:
        """Execute fuzzer with hypothesis context."""
        from src.agents.tools.fuzzer import Fuzzer

        params = params or {}
        fuzzer = Fuzzer()

        # Adapt hypothesis context to fuzzer parameters
        if hypothesis:
            params.setdefault("attack_category", hypothesis.get("attack_category", ""))
            params.setdefault("hypothesis_class", hypothesis.get("hypothesis_class", ""))

        try:
            result = await fuzzer.fuzz(target_url=target, **params)
            findings = result.get("findings", []) if isinstance(result, dict) else []

            return ToolResult(
                success=True,
                findings=findings if isinstance(findings, list) else [],
                result_data=result if isinstance(result, dict) else {"raw": str(result)},
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )
        except Exception as exc:
            logger.error("FuzzerAdapter: execution failed: %s", exc)
            return ToolResult(
                success=False,
                error=str(exc),
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

    def describe_capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(tag="fuzzing", description="Parameter fuzzing for injection and tampering", priority=10),
            ToolCapability(tag="injection", description="SQL and command injection testing via fuzzing", priority=5),
            ToolCapability(tag="parameter_tampering", description="Parameter manipulation and boundary testing", priority=8),
        ]


class AuthTesterAdapter(ToolProtocol):
    """Adapter wrapping existing AuthTester as a ToolProtocol implementation."""

    name = "auth_tester"
    capability_tags = ["auth_bypass", "brute_force", "session_testing"]

    async def run(self, target: str, hypothesis: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> ToolResult:
        """Execute auth tester with hypothesis context."""
        from src.agents.tools.auth_tester import AuthTester

        params = params or {}
        tester = AuthTester()

        try:
            result = await tester.test(target_url=target, **params)
            findings = result.get("findings", []) if isinstance(result, dict) else []

            return ToolResult(
                success=True,
                findings=findings if isinstance(findings, list) else [],
                result_data=result if isinstance(result, dict) else {"raw": str(result)},
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )
        except Exception as exc:
            logger.error("AuthTesterAdapter: execution failed: %s", exc)
            return ToolResult(
                success=False,
                error=str(exc),
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

    def describe_capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(tag="auth_bypass", description="Authentication bypass testing", priority=10),
            ToolCapability(tag="brute_force", description="Credential brute-force testing", priority=7),
            ToolCapability(tag="session_testing", description="Session management vulnerability testing", priority=8),
        ]


class XSSPipelineAdapter(ToolProtocol):
    """Adapter wrapping existing XSSPipeline as a ToolProtocol implementation."""

    name = "xss_pipeline"
    capability_tags = ["xss", "injection", "reflected", "stored", "dom"]

    async def run(self, target: str, hypothesis: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> ToolResult:
        """Execute XSS pipeline with hypothesis context."""
        from src.agents.tools.vuln_pipelines import XSSPipeline

        params = params or {}
        pipeline = XSSPipeline()

        try:
            result = await pipeline.run(target_url=target, **params)
            findings = result.findings if hasattr(result, 'findings') else []
            findings_dicts = [f if isinstance(f, dict) else vars(f) for f in findings]

            return ToolResult(
                success=True,
                findings=findings_dicts,
                result_data={"vuln_type": "xss", "result": str(result)[:2000]},
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )
        except Exception as exc:
            logger.error("XSSPipelineAdapter: execution failed: %s", exc)
            return ToolResult(
                success=False,
                error=str(exc),
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

    def describe_capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(tag="xss", description="Cross-site scripting detection and testing", priority=10),
            ToolCapability(tag="injection", description="Script injection testing", priority=6),
            ToolCapability(tag="reflected", description="Reflected XSS testing", priority=9),
            ToolCapability(tag="stored", description="Stored XSS testing", priority=8),
            ToolCapability(tag="dom", description="DOM-based XSS testing", priority=7),
        ]


class SQLiPipelineAdapter(ToolProtocol):
    """Adapter wrapping existing SQLiPipeline as a ToolProtocol implementation."""

    name = "sqli_pipeline"
    capability_tags = ["sqli", "injection", "auth_bypass"]

    async def run(self, target: str, hypothesis: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> ToolResult:
        """Execute SQL injection pipeline with hypothesis context."""
        from src.agents.tools.vuln_pipelines import SQLiPipeline

        params = params or {}
        pipeline = SQLiPipeline()

        try:
            result = await pipeline.run(target_url=target, **params)
            findings = result.findings if hasattr(result, 'findings') else []
            findings_dicts = [f if isinstance(f, dict) else vars(f) for f in findings]

            return ToolResult(
                success=True,
                findings=findings_dicts,
                result_data={"vuln_type": "sqli", "result": str(result)[:2000]},
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )
        except Exception as exc:
            logger.error("SQLiPipelineAdapter: execution failed: %s", exc)
            return ToolResult(
                success=False,
                error=str(exc),
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

    def describe_capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(tag="sqli", description="SQL injection detection and exploitation", priority=10),
            ToolCapability(tag="injection", description="Injection vulnerability testing", priority=7),
            ToolCapability(tag="auth_bypass", description="Authentication bypass via SQL injection", priority=6),
        ]


class SSRFPipelineAdapter(ToolProtocol):
    """Adapter wrapping existing SSRFPipeline as a ToolProtocol implementation."""

    name = "ssrf_pipeline"
    capability_tags = ["ssrf", "injection", "internal_access"]

    async def run(self, target: str, hypothesis: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> ToolResult:
        """Execute SSRF pipeline with hypothesis context."""
        from src.agents.tools.vuln_pipelines import SSRFPipeline

        params = params or {}
        pipeline = SSRFPipeline()

        try:
            result = await pipeline.run(target_url=target, **params)
            findings = result.findings if hasattr(result, 'findings') else []
            findings_dicts = [f if isinstance(f, dict) else vars(f) for f in findings]

            return ToolResult(
                success=True,
                findings=findings_dicts,
                result_data={"vuln_type": "ssrf", "result": str(result)[:2000]},
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )
        except Exception as exc:
            logger.error("SSRFPipelineAdapter: execution failed: %s", exc)
            return ToolResult(
                success=False,
                error=str(exc),
                tool_name=self.name,
                hypothesis_id=hypothesis.get("hypothesis_id") if hypothesis else None,
            )

    def describe_capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(tag="ssrf", description="Server-side request forgery detection and testing", priority=10),
            ToolCapability(tag="injection", description="URL injection testing", priority=5),
            ToolCapability(tag="internal_access", description="Internal network access via SSRF", priority=8),
        ]