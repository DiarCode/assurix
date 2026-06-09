"""ToolProtocol: Abstract base class for all Mythos tools.

Every tool that implements ToolProtocol provides:
- name: Human-readable tool identifier
- capability_tags: Tags used by ToolRegistry to match hypotheses to tools
- run(): Async method that executes the tool with hypothesis context
- describe_capabilities(): Returns metadata about what the tool can do

During Phase 1, the first 5 tools (Fuzzer, AuthTester, XSSPipeline,
SQLiPipeline, SSRFPipeline) are migrated to this protocol. The remaining
tools continue via direct method calls until Phase 3.

Plan §5.11 update: ``run()`` accepts an optional ``auth:
AuthorizationContext`` parameter. The default is ``None`` for
backward compatibility — existing implementations that don't take
the parameter continue to work. New tools SHOULD accept the parameter
and use it to gate scope / role / capability checks.
"""

from abc import ABC, abstractmethod
from typing import Any

from src.schemas.tools import ToolCapability, ToolInvocationRequest, ToolResult


class ToolProtocol(ABC):
    """Abstract base class for all Mythos tools.

    Tools implement this protocol to participate in the ResearchLoop's
    hypothesis-driven investigation workflow. The ToolRegistry matches
    hypotheses to tools based on capability_tags.

    Provenance is recorded in every ToolResult, linking findings back
    to the hypothesis and engagement that triggered the invocation.
    """

    name: str = "base_tool"
    capability_tags: list[str] = []

    @abstractmethod
    async def run(
        self,
        target: str,
        hypothesis: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: "AuthorizationContext | None" = None,
    ) -> ToolResult:
        """Execute the tool against a target with optional hypothesis context.

        Args:
            target: Target URL or identifier to test.
            hypothesis: Optional hypothesis dict providing investigation context.
                       Contains hypothesis_class, attack_category, required_capabilities,
                       falsification_criteria.
            params: Optional tool-specific parameters.
            auth: Optional ``AuthorizationContext`` (plan §5.11). When
                provided, tools MUST honour its scope / role /
                capability constraints. When ``None`` (the default for
                backward compat), the tool runs in the legacy
                "trust-the-caller" mode.

        Returns:
            ToolResult with findings, artifacts, and provenance metadata.
        """
        ...

    @abstractmethod
    def describe_capabilities(self) -> list[ToolCapability]:
        """Return metadata about what this tool can do.

        Used by ToolRegistry to match hypotheses to appropriate tools
        based on required_capabilities tags.
        """
        ...

    def matches_capabilities(self, required_capabilities: list[str]) -> bool:
        """Check if this tool matches any of the required capabilities.

        A tool matches if any of its capability_tags appear in the
        required_capabilities list.
        """
        if not required_capabilities:
            return True  # No requirements = any tool can handle it
        return any(tag in required_capabilities for tag in self.capability_tags)

    def check_authorization(self, auth: "AuthorizationContext | None") -> tuple[bool, str]:
        """Check whether this tool can run under the given auth context.

        Default implementation: pass-through (no auth-required). Tools
        that require a specific role / capability override this method.

        Returns:
            (ok, reason). When ``ok`` is False, ``reason`` is a
            human-readable explanation suitable for the audit log.
        """
        if auth is None:
            return True, "no auth context provided (legacy mode)"
        if not auth.is_in_scope():
            return False, f"target not in scope: {auth.target_url}"
        return True, "ok"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r}, tags={self.capability_tags})>"


# Re-export the type so existing call sites that do
# ``from src.agents.tools.protocol import ToolProtocol`` continue to
# work, and tools that want the auth type don't have to import the
# authorization module separately.
from src.agents.tools.authorization import AuthorizationContext  # noqa: E402  (re-export)
