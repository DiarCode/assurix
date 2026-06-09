"""Tool protocol and result schemas for the Mythos tool framework.

These schemas define the ToolProtocol interface that all migrated tools
must implement. During Phase 1, the first 5 tools (Fuzzer, AuthTester,
XSSPipeline, SQLiPipeline, SSRFPipeline) are migrated to this protocol.
The remaining tools continue via direct method calls until Phase 3.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ToolCapability(BaseModel):
    """A capability that a tool provides.

    Used by ToolRegistry to match hypotheses to appropriate tools
    based on required_capabilities tags.
    """

    tag: str = Field(..., description="Capability tag (e.g., 'xss', 'injection', 'auth_bypass')")
    description: str = Field(default="", description="Human-readable description")
    priority: int = Field(default=0, description="Priority for tool selection (higher = preferred)")


class ToolResult(BaseModel):
    """Result returned by a ToolProtocol tool invocation.

    Includes provenance metadata linking the result back to
    the hypothesis and engagement it was invoked for.
    """

    success: bool = Field(default=False, description="Whether the tool invocation succeeded")
    findings: list[dict[str, Any]] = Field(default_factory=list, description="Findings from this invocation")
    artifacts: list[dict[str, Any]] = Field(default_factory=list, description="Evidence artifacts")
    result_data: dict[str, Any] = Field(default_factory=dict, description="Raw result data")
    error: str | None = Field(default=None, description="Error message if invocation failed")
    # Provenance metadata
    tool_name: str = Field(default="", description="Name of the tool that produced this result")
    hypothesis_id: str | None = Field(default=None, description="Hypothesis that triggered this invocation")
    engagement_id: str | None = Field(default=None, description="Engagement this invocation belongs to")
    invocation_id: str | None = Field(default=None, description="ToolInvocation ID for provenance")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


class ToolInvocationRequest(BaseModel):
    """Request to invoke a tool via ToolProtocol.

    Created by the ResearchLoop when dispatching an investigation.
    Includes hypothesis context so tools can tailor their behavior.
    """

    tool_name: str = Field(..., description="Name of the tool to invoke")
    target: str = Field(..., description="Target URL or identifier")
    hypothesis_class: str | None = Field(default=None, description="Hypothesis class being investigated")
    attack_category: str | None = Field(default=None, description="Attack category being investigated")
    required_capabilities: list[str] = Field(default_factory=list, description="Required capability tags")
    params: dict[str, Any] = Field(default_factory=dict, description="Tool-specific parameters")
    falsification_criteria: str | None = Field(default=None, description="What constitutes falsification")
    engagement_id: str | None = Field(default=None, description="Engagement ID for provenance")
    hypothesis_id: str | None = Field(default=None, description="Hypothesis ID for provenance")