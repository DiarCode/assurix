"""Chain schemas for the Mythos ExploitChainer (plan §3.3.1).

The chainer produces ``Chain`` objects from BFS over (finding, capability)
edges. Each chain has a name, ordered steps, severity, and metadata used
by the reporter and reasoner.

Skill level, likelihood, and business_impact are derived from the
chain's component findings — they are first-class because the plan
calls for "skill_level" / "likelihood" / "business_impact" outputs
in the chain report (see Chain pattern table in plan §3.3.1).
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


SkillLevel = Literal["novice", "intermediate", "advanced", "expert"]
Likelihood = Literal["rare", "possible", "probable", "certain"]
BusinessImpact = Literal["minimal", "moderate", "high", "critical"]


class ChainStep(BaseModel):
    """A single step in an exploit chain.

    Each step is the application of one finding to produce (or grant)
    a capability used by the next step. ``grants_capability`` is the
    key the BFS uses to find the next pattern that consumes it.
    """

    order: int = Field(..., description="0-indexed position in the chain")
    finding_class: str = Field(..., description="The vuln class (e.g. 'xss', 'ssrf')")
    finding_title: str = Field(..., description="Human-readable finding title")
    severity: str = Field(default="info", description="Per-step severity")
    grants_capability: str | None = Field(
        default=None,
        description="The capability this step grants to the next step",
    )
    url: str = Field(default="", description="Affected URL or path")
    evidence: str = Field(default="", description="Cue / evidence summary")


class Chain(BaseModel):
    """An exploit chain assembled from findings.

    Chains are produced by ``ExploitChainer.find_chains``. The
    ``pattern`` field is the name of the ``ChainPattern`` subclass
    that produced the chain (e.g. ``XSSPlusCSPGap``). The
    ``capability_path`` records the sequence of capabilities
    granted at each step — useful for debugging the BFS.
    """

    name: str = Field(..., description="Human-readable chain name")
    pattern: str = Field(..., description="ChainPattern subclass name")
    steps: list[ChainStep] = Field(default_factory=list)
    severity: str = Field(default="medium", description="Combined severity")
    skill_level: SkillLevel = Field(default="intermediate")
    likelihood: Likelihood = Field(default="possible")
    business_impact: BusinessImpact = Field(default="moderate")
    capability_path: list[str] = Field(
        default_factory=list,
        description="Sequence of capabilities granted at each step",
    )
    description: str = Field(default="", description="Chain narrative")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


__all__ = [
    "Chain",
    "ChainStep",
    "SkillLevel",
    "Likelihood",
    "BusinessImpact",
]
