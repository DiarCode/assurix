"""Provenance schemas for end-to-end evidence tracing.

Every confirmed finding must have a complete provenance chain:
  finding → hypothesis → tool invocation → tool

This enables the Mythos evidence bar: no orphaned results.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ProvenanceStatus(StrEnum):
    """Status of a provenance chain."""
    COMPLETE = "complete"      # finding → hypothesis → tool_invocation → tool
    PARTIAL = "partial"        # missing some links
    ORPHANED = "orphaned"      # finding with no provenance chain


class ToolInvocationRecord(BaseModel):
    """Record of a tool invocation within the research loop.

    Links a hypothesis to the specific tool that was used to investigate it.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    engagement_id: str
    hypothesis_id: str
    tool_name: str
    capability_tags: list[str] = Field(default_factory=list)
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


class ProvenanceChain(BaseModel):
    """Complete provenance chain linking a finding to its investigation context.

    Enables tracing: finding → hypothesis → tool invocation → tool.
    Required for the Mythos evidence bar — every confirmed finding
    must have a complete provenance chain.
    """

    finding_id: str
    hypothesis_id: str
    tool_invocation_id: str
    tool_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Chain completeness check
    status: ProvenanceStatus = ProvenanceStatus.COMPLETE

    def is_complete(self) -> bool:
        """Check if the provenance chain is complete."""
        return all([
            self.finding_id,
            self.hypothesis_id,
            self.tool_invocation_id,
            self.tool_name,
        ])