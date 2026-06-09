"""Pydantic schemas for Assurix agent payloads, hypotheses, provenance, and tools.

Based on Phase 0's observed data flows — these schemas formalize the interfaces
that emerged from the prototype, not speculative designs.
"""

from src.schemas.payload import AgentPayload, AgentResult, HypothesisPayload, FindingPayload
from src.schemas.hypothesis import HypothesisClass, HypothesisSource, HypothesisStatus as HypothesisStatusSchema
from src.schemas.provenance import ProvenanceChain, ToolInvocationRecord, ProvenanceStatus
from src.schemas.surface import AttackSurface, EndpointNode, DataFlowEdge, TrustBoundary
from src.schemas.tools import ToolResult, ToolCapability, ToolInvocationRequest
from src.schemas.chain import Chain, ChainStep, SkillLevel, Likelihood, BusinessImpact

__all__ = [
    "AgentPayload", "AgentResult", "HypothesisPayload", "FindingPayload",
    "HypothesisClass", "HypothesisSource", "HypothesisStatusSchema",
    "ProvenanceChain", "ToolInvocationRecord", "ProvenanceStatus",
    "AttackSurface", "EndpointNode", "DataFlowEdge", "TrustBoundary",
    "ToolResult", "ToolCapability", "ToolInvocationRequest",
    "Chain", "ChainStep", "SkillLevel", "Likelihood", "BusinessImpact",
]