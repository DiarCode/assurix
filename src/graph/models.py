"""Pydantic models for graph-native reasoning."""

from pydantic import BaseModel, Field


class GraphNodeModel(BaseModel):
    """Represents a node in the knowledge graph."""

    id: str
    engagement_id: str
    node_type: str = Field(..., pattern=r"^[a-z_]+$")
    label: str
    properties: dict = Field(default_factory=dict)


class GraphEdgeModel(BaseModel):
    """Represents a directed edge in the knowledge graph."""

    id: str
    engagement_id: str
    source_id: str
    target_id: str
    edge_type: str = Field(..., pattern=r"^[A-Z_]+$")
    properties: dict = Field(default_factory=dict)


class AttackPath(BaseModel):
    """A chain of nodes representing an exploit path."""

    nodes: list[GraphNodeModel]
    edges: list[GraphEdgeModel]
    length: int
    score: float = Field(..., ge=0.0, le=1.0)


class GraphStats(BaseModel):
    """Summary statistics for an engagement graph."""

    engagement_id: str
    node_count: int
    edge_count: int
    node_type_counts: dict[str, int]
    edge_type_counts: dict[str, int]
    density: float
    avg_degree: float
