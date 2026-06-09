"""Attack surface and knowledge graph schemas.

These schemas model the target's attack surface, including endpoints,
data flows, trust boundaries, and the knowledge graph built by
Codebase Intelligence.
"""

from typing import Any

from pydantic import BaseModel, Field


class EndpointNode(BaseModel):
    """A single endpoint in the attack surface.

    Represents a URL endpoint with its HTTP method, auth requirements,
    data sensitivity, and technology markers.
    """

    url: str = Field(..., description="Full URL of the endpoint")
    method: str = Field(default="GET", description="HTTP method")
    path: str = Field(default="", description="URL path component")
    auth_required: bool = Field(default=False, description="Whether auth is required")
    content_type: str | None = Field(default=None, description="Response content type")
    parameters: list[dict[str, Any]] = Field(default_factory=list, description="Query/form params")
    data_sensitivity: str = Field(default="low", description="low/medium/high data sensitivity")
    technologies: list[str] = Field(default_factory=list, description="Detected technologies")
    response_codes: list[int] = Field(default_factory=list, description="Observed HTTP status codes")


class DataFlowEdge(BaseModel):
    """A data flow between endpoints or services.

    Models how data moves between endpoints, including
    authentication boundaries and data transformations.
    """

    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    edge_type: str = Field(default="call", description="call/data_flow/auth_boundary")
    data_types: list[str] = Field(default_factory=list, description="Types of data flowing")
    auth_boundary: bool = Field(default=False, description="Whether this crosses an auth boundary")
    properties: dict[str, Any] = Field(default_factory=dict)


class TrustBoundary(BaseModel):
    """A trust boundary in the attack surface.

    Defines where privilege levels change, such as
    between authenticated and unauthenticated zones.
    """

    id: str
    name: str = Field(..., description="Human-readable boundary name")
    boundary_type: str = Field(default="auth", description="auth/network/data/process")
    inside_nodes: list[str] = Field(default_factory=list, description="Node IDs inside the boundary")
    outside_nodes: list[str] = Field(default_factory=list, description="Node IDs outside the boundary")
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackSurface(BaseModel):
    """Complete attack surface model for a target.

    Combines endpoints, data flows, trust boundaries,
    and technology profiles into a queryable surface model.
    Used by HypothesisGenerator to seed hypothesis classes.
    """

    target_url: str
    endpoints: list[EndpointNode] = Field(default_factory=list)
    data_flows: list[DataFlowEdge] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list, description="Detected technologies")
    auth_pages: list[str] = Field(default_factory=list, description="Authentication page URLs")
    forms: list[dict[str, Any]] = Field(default_factory=list, description="Detected forms")
    scripts: list[str] = Field(default_factory=list, description="JavaScript URLs")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP response headers")
    raw_surface: dict[str, Any] = Field(default_factory=dict, description="Original surface data from recon")

    def endpoint_count(self) -> int:
        """Number of discovered endpoints."""
        return len(self.endpoints)

    def auth_required_count(self) -> int:
        """Number of endpoints requiring authentication."""
        return sum(1 for e in self.endpoints if e.auth_required)

    def unauthenticated_endpoints(self) -> list[EndpointNode]:
        """Endpoints accessible without authentication — highest priority targets."""
        return [e for e in self.endpoints if not e.auth_required]

    def high_sensitivity_endpoints(self) -> list[EndpointNode]:
        """Endpoints handling sensitive data."""
        return [e for e in self.endpoints if e.data_sensitivity in ("high", "medium")]