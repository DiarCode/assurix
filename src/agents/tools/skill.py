"""Skill layer — composed tools with typed preconditions, effects, and
fallback chains (plan §5.9 / plan §3.3.1).

A ``Skill`` is a named, composable investigation unit that wraps one
or more existing ``ToolProtocol`` implementations. Skills are the
"outer ring" of the tool layer — the ResearchLoop queries
``ToolRegistry.skills_matching(capabilities)`` to pick the best skill
for a hypothesis, then the skill invokes its underlying tool with
preconditions verified and effects recorded.

Three structural pieces (per plan §5.9):

  1. ``Skill`` — Pydantic model with:
       - ``name`` (str, unique)
       - ``tool_name`` (str, the underlying ToolProtocol name)
       - ``preconditions`` (list[str], capability tags that must be
         present in the world model for the skill to apply)
       - ``effects`` (list[SkillEffect], what the skill produces —
         beliefs it sets, capabilities it grants)
       - ``fallback_chain`` (list[str], other skill names to try on
         failure, in order)

  2. ``SkillEffect`` — typed effect: ``kind`` from a closed
     vocabulary (``belief`` / ``capability``), plus a payload
     (``belief:<key>:<value>`` or ``capability:<name>:<confidence>``).

  3. ``SkillRegistry`` — companion to ``ToolRegistry``. Stores
     skills by name, supports lookup by required capabilities, and
     resolves the fallback chain. The ResearchLoop calls
     ``skill_registry.skills_matching(caps)`` to get skills sorted
     by coverage.

The 9 first-class skills shipped in Week 3:

  1-7. The 7 ``ChainPattern`` subclasses from
       ``src.graph.exploit_chains`` — each becomes a Skill that
       consumes a capability and grants the next one in the chain.
  8.    ``APIEndpointExtractor`` (plan §3.1.4) — extracts JS API
       endpoints from the live target.
  9.    ``DOMXSSHunter`` (plan §3.2.1) — DOM-XSS via real browser.

The Skill layer does NOT replace the existing 18 tools — it wraps
them. Each Skill is a thin adapter that calls its underlying tool
with the right hypothesis context.

Failure modes (per plan §5.9):
  - Preconditions not met → return ``SkillNotApplicable``.
  - Underlying tool raises → record the failure, try the next entry
    in ``fallback_chain``.
  - Fallback chain exhausted → return ``AllFallbacksFailed``.
"""
from __future__ import annotations

import logging
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Effect schema
# ---------------------------------------------------------------------------


EffectKind = Literal["belief", "capability"]


class SkillEffect(BaseModel):
    """A typed effect a skill produces when it succeeds.

    Two kinds:

      * ``belief`` — sets a key/value belief in the world model
        (e.g. ``{"kind": "belief", "key": "endpoint:idor",
        "value": "true", "confidence": 0.9}``).
      * ``capability`` — grants a downstream capability (e.g.
        ``{"kind": "capability", "name": "privilege_escalation",
        "confidence": 0.8}``). These are what ``ExploitChainer``'s
        BFS matches on.

    The ``key`` + ``value`` pair for ``belief`` effects is
    conventional (no vocabulary check) so skills can record
    arbitrary world-model state. The ``name`` field for
    ``capability`` effects is run through ``guard_capability`` at
    construction time so a typo crashes immediately rather than
    silently producing zero matches in the BFS.
    """

    kind: EffectKind
    key: str | None = Field(
        default=None,
        description="Belief key (when kind=belief).",
    )
    value: str | None = Field(
        default=None,
        description="Belief value (when kind=belief).",
    )
    name: str | None = Field(
        default=None,
        description="Capability name (when kind=capability).",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence in [0, 1].",
    )

    @field_validator("name")
    @classmethod
    def _validate_capability_name(cls, v: str | None) -> str | None:
        """Capability names MUST come from the closed vocabulary in
        ``src/graph/capabilities.py``. A typo here would silently
        produce zero matches in the ExploitChainer BFS — so we
        fail at construction time with a loud error.
        """
        if v is None:
            return v
        # Local import to avoid a circular dependency at module load
        # (capabilities.py imports nothing from us, but the test
        # suite sometimes loads skills.py before capabilities.py).
        from src.graph.capabilities import guard_capability

        if guard_capability(v) is None:
            raise ValueError(
                f"SkillEffect name={v!r} is not in the closed "
                f"capability vocabulary (see "
                f"src/graph/capabilities.py)"
            )
        return v


# ---------------------------------------------------------------------------
# Skill schema
# ---------------------------------------------------------------------------


class SkillNotApplicable(Exception):
    """Raised when a skill's preconditions are not satisfied.

    The ``SkillRegistry.apply_with_fallback`` helper catches this
    and tries the next entry in the skill's fallback chain.
    """

    def __init__(self, skill_name: str, reason: str) -> None:
        self.skill_name = skill_name
        self.reason = reason
        super().__init__(f"skill {skill_name!r} not applicable: {reason}")


class AllFallbacksFailed(Exception):
    """Raised when a skill and every fallback in its chain have
    failed or been declared not-applicable."""

    def __init__(self, tried: list[str], last_error: str) -> None:
        self.tried = tried
        self.last_error = last_error
        super().__init__(
            f"all fallbacks exhausted {tried!r}, last error: {last_error}"
        )


class Skill(BaseModel):
    """A named, composable investigation unit.

    A Skill wraps an existing ``ToolProtocol`` implementation
    (``tool_name``) with typed preconditions and effects. Skills
    form the outer ring of the tool layer; the ResearchLoop picks
    a Skill based on hypothesis ``required_capabilities``, then the
    Skill invokes the underlying tool.

    Example::

        skill = Skill(
            name="xss_plus_csp_gap",
            tool_name="xss_pipeline",
            preconditions=["xss", "session_hijack"],
            effects=[
                SkillEffect(
                    kind="capability",
                    name="privilege_escalation",
                    confidence=0.9,
                ),
            ],
            fallback_chain=["jwt_alg_none", "idor_plus_admin"],
        )
    """

    name: str = Field(..., min_length=1, max_length=100)
    tool_name: str = Field(..., min_length=1, max_length=100)
    preconditions: list[str] = Field(
        default_factory=list,
        description="Capability tags that must be present in the world model.",
    )
    effects: list[SkillEffect] = Field(
        default_factory=list,
        description="What this skill produces when it succeeds.",
    )
    fallback_chain: list[str] = Field(
        default_factory=list,
        description="Other skill names to try on failure, in order.",
    )
    description: str = Field(
        default="",
        description="Human-readable description (for the catalog).",
    )

    def applies_to(self, capabilities: list[str]) -> bool:
        """True if every precondition is satisfied by ``capabilities``.

        Empty preconditions means the skill always applies (the
        skill is unconditional).
        """
        if not self.preconditions:
            return True
        return all(p in capabilities for p in self.preconditions)

    def granted_capability(self) -> str | None:
        """The single capability this skill grants, if any.

        Most Skills grant exactly one capability (the one the
        ExploitChainer BFS uses). For Skills that grant multiple
        capabilities (or none), this returns the first capability
        effect's name; the full list is in ``self.effects``.

        Returns:
            The capability name, or ``None`` if the skill grants
            no capability (only beliefs).
        """
        for eff in self.effects:
            if eff.kind == "capability" and eff.name:
                return eff.name
        return None

    def granted_capabilities(self) -> list[str]:
        """All capabilities this skill grants, in declared order."""
        return [
            eff.name for eff in self.effects
            if eff.kind == "capability" and eff.name
        ]

    def granted_belief(self, key: str) -> SkillEffect | None:
        """Return the belief effect for ``key`` if the skill grants
        one, else ``None``."""
        for eff in self.effects:
            if eff.kind == "belief" and eff.key == key:
                return eff
        return None


# ---------------------------------------------------------------------------
# Skill registry (companion to ToolRegistry)
# ---------------------------------------------------------------------------


class SkillRegistry:
    """Companion to ``ToolRegistry`` — stores Skills by name and
    supports capability-based lookup.

    The SkillRegistry is a thin layer over the ToolRegistry. The
    ResearchLoop queries it via :meth:`skills_matching` to get the
    skills that satisfy a hypothesis's ``required_capabilities``.

    The registry does NOT execute skills — that is the caller's
    job (typically the ResearchLoop). The registry's job is just
    catalog management and fallback resolution.
    """

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        """Register a skill. Re-registering with the same name is
        a hard error (silent overwrite would be a slop vector —
        a future contributor changes a skill's preconditions and
        doesn't realise the new version is shadowed by the old)."""
        if skill.name in self._skills:
            raise ValueError(
                f"SkillRegistry: skill {skill.name!r} already "
                f"registered; cannot overwrite. Unregister first "
                f"if you intentionally want to replace it."
            )
        # Validate that the underlying tool_name is non-empty —
        # we can't validate the tool actually exists without
        # importing the ToolRegistry, and that would create a
        # circular dependency. The SkillRegistry's job is the
        # catalog; missing tools surface at apply time.
        self._skills[skill.name] = skill
        logger.info(
            "SkillRegistry: registered skill %r (tool=%r, %d effects, "
            "%d fallbacks)",
            skill.name, skill.tool_name, len(skill.effects),
            len(skill.fallback_chain),
        )

    def unregister(self, name: str) -> None:
        """Remove a skill. Idempotent: missing names are ignored."""
        self._skills.pop(name, None)

    def get(self, name: str) -> Skill | None:
        """Get a skill by name. ``None`` if not registered."""
        return self._skills.get(name)

    def has(self, name: str) -> bool:
        return name in self._skills

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    def __len__(self) -> int:
        return len(self._skills)

    def all_skills(self) -> list[Skill]:
        """All registered skills, in registration order."""
        return list(self._skills.values())

    def skills_matching(
        self, required_capabilities: list[str],
    ) -> list[Skill]:
        """Return skills whose preconditions are satisfied by
        ``required_capabilities``, ordered by *coverage* (how many
        of the required capabilities each skill's effects grant).

        Coverage is a proxy for usefulness: a skill that grants
        two required capabilities is more useful than one that
        grants one, even if both are applicable.
        """
        if not required_capabilities:
            return self.all_skills()
        required_set = set(required_capabilities)
        applicable: list[tuple[int, int, Skill]] = []
        for idx, skill in enumerate(self._skills.values()):
            if not skill.applies_to(required_capabilities):
                continue
            granted = set(skill.granted_capabilities())
            coverage = len(required_set & granted)
            applicable.append((coverage, -idx, skill))
        # Highest coverage first; ties broken by registration order
        # (earlier = first, hence the -idx).
        applicable.sort(key=lambda t: (-t[0], t[1]))
        return [s for _, _, s in applicable]

    def skills_granting(self, capability: str) -> list[Skill]:
        """Return all skills that grant ``capability`` (regardless
        of whether their preconditions are satisfied)."""
        return [
            s for s in self._skills.values()
            if capability in s.granted_capabilities()
        ]

    def resolve_fallback_chain(
        self, skill: Skill, max_depth: int = 5,
    ) -> list[Skill]:
        """Resolve a skill's fallback chain into the actual Skill
        objects, dropping missing names and deduping to avoid
        cycles.

        The primary skill's name is pre-seeded in the seen-set so
        a self-reference (``fallback_chain=["self", "other"]``)
        is silently deduped. The depth cap prevents an
        A→B→A→B chain from looping forever; an over-long chain
        is also a smell (a skill with 5+ fallbacks is probably
        a candidate for a rewrite).
        """
        if max_depth <= 0:
            return []
        chain: list[Skill] = []
        # Seed with the primary's own name so any self-reference
        # in the chain list is dropped on the first iteration.
        seen: set[str] = {skill.name}
        for name in skill.fallback_chain:
            if name in seen:
                continue
            seen.add(name)
            if len(chain) >= max_depth:
                break
            nxt = self._skills.get(name)
            if nxt is None:
                # Missing fallback — log and continue. A typo in
                # a skill's fallback_chain should not crash the
                # skill at registration time (we don't want
                # circular dependencies on import order), but it
                # should be loud.
                logger.warning(
                    "SkillRegistry: fallback %r for skill %r is "
                    "not registered; skipping",
                    name, skill.name,
                )
                continue
            chain.append(nxt)
        return chain

    def apply_with_fallback(
        self,
        skill_name: str,
        *,
        capabilities: list[str],
        apply_fn: "ApplyFn",
    ) -> tuple[Skill, Any]:
        """Try to apply ``skill_name`` (and its fallbacks) under
        ``capabilities``, returning the first successful
        ``(skill, result)`` pair.

        ``apply_fn(skill, capabilities)`` is the caller-supplied
        function that actually runs the skill. It must raise
        :class:`SkillNotApplicable` if the skill's preconditions
        are not met, or any other exception on failure.

        The returned ``Skill`` is the one that actually
        succeeded (which may be a fallback), not necessarily the
        one named in ``skill_name``. The caller can use the
        returned skill's name to record the audit trail.

        Raises:
            AllFallbacksFailed: every entry in the fallback chain
                either raised ``SkillNotApplicable`` or some other
                exception. The last error is preserved.
        """
        primary = self._skills.get(skill_name)
        if primary is None:
            raise AllFallbacksFailed(
                tried=[skill_name],
                last_error=f"skill {skill_name!r} not registered",
            )

        chain = [primary, *self.resolve_fallback_chain(primary)]
        tried: list[str] = []
        last_error = "no attempt made"
        for sk in chain:
            tried.append(sk.name)
            try:
                result = apply_fn(sk, capabilities)
            except SkillNotApplicable as exc:
                logger.debug(
                    "skill %r not applicable: %s; trying next fallback",
                    sk.name, exc.reason,
                )
                last_error = exc.reason
                continue
            except Exception as exc:
                logger.debug(
                    "skill %r raised: %s; trying next fallback",
                    sk.name, exc,
                )
                last_error = str(exc)
                continue
            return sk, result
        raise AllFallbacksFailed(tried=tried, last_error=last_error)


# Type alias for the apply_fn argument to ``apply_with_fallback``.
# Declared as a string so we don't have to import ``Any`` into the
# type-namespace at module load.
ApplyFn = Any


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------


_registry: SkillRegistry | None = None


def get_skill_registry() -> SkillRegistry:
    """Get the global SkillRegistry singleton.

    The singleton is lazily created; tests that want isolation
    should construct their own ``SkillRegistry()`` rather than
    calling this function.
    """
    global _registry
    if _registry is None:
        _registry = SkillRegistry()
    return _registry


def reset_skill_registry() -> None:
    """Reset the global singleton. Tests use this to ensure
    isolation between cases; production code should never need
    to call this."""
    global _registry
    _registry = None


# ---------------------------------------------------------------------------
# First-class Skills: the 7 chain patterns (§3.3.1) + 2 ad-hoc skills.
# ---------------------------------------------------------------------------


def build_default_skill_catalog() -> list[Skill]:
    """Build the 9 first-class Skills (plan §3.3.1 + §3.1.4 + §3.2.1).

    This function is the single source of truth for the Week 3
    skill catalog. It is called by ``register_default_skills`` and
    by tests that want to assert the catalog shape.

    The 7 chain patterns are derived from the
    ``src.graph.exploit_chains`` patterns — each becomes a Skill
    that consumes a capability and grants the next one. The
    mapping is:

        XSSPlusCSPGap            -> xss_plus_csp_gap
        SSRFPlusCloudMetadata    -> ssrf_plus_cloud_metadata
        IDORPlusAdmin            -> idor_plus_admin
        SSTIPlusLFI              -> ssti_plus_lfi
        JWTAlgNone               -> jwt_alg_none
        GraphQLIntrospection     -> graphql_introspection
        OpenRedirectPlusOAuth    -> open_redirect_plus_oauth

    Plus two ad-hoc skills:

        api_endpoint_extractor (§3.1.4)
        dom_xss_hunter          (§3.2.1)
    """
    # Local imports to keep this module's load time small and to
    # break the import cycle with src.graph.exploit_chains.
    from src.graph.exploit_chains import (
        DEFAULT_PATTERNS,
    )

    catalog: list[Skill] = []

    # 1-7: chain pattern skills.
    # Each ChainPattern declares (consumes, grants); the Skill
    # wraps that as (preconditions, effects). The underlying
    # tool_name is the chainer tool itself — the chainer applies
    # the pattern over the validated findings.
    tool_name_per_pattern: dict[str, str] = {
        "XSSPlusCSPGap": "xss_pipeline",
        "SSRFPlusCloudMetadata": "ssrf_pipeline",
        "IDORPlusAdmin": "idor_validator",
        "SSTIPlusLFI": "ssti_pipeline",
        "JWTAlgNone": "auth_tester",
        "GraphQLIntrospection": "graphql_scanner",
        "OpenRedirectPlusOAuth": "auth_tester",
    }
    for pattern_cls in DEFAULT_PATTERNS:
        instance = pattern_cls()
        consumes = [instance.consumes] if instance.consumes else []
        grants_effects: list[SkillEffect] = []
        if instance.grants:
            grants_effects.append(
                SkillEffect(
                    kind="capability",
                    name=instance.grants,
                    # Confidence for the chain-skill effect is the
                    # pattern's likelihood cast to a probability
                    # bucket. Probable -> 0.8, Possible -> 0.5,
                    # else 0.3. This is the prior the BFS uses to
                    # rank alternative paths.
                    confidence=(
                        0.8 if instance.likelihood == "probable"
                        else 0.5 if instance.likelihood == "possible"
                        else 0.3
                    ),
                )
            )
        catalog.append(Skill(
            name=instance.name,
            tool_name=tool_name_per_pattern.get(
                instance.name, "exploit_chainer",
            ),
            preconditions=consumes,
            effects=grants_effects,
            fallback_chain=[],
            description=instance.description,
        ))

    # 8: APIEndpointExtractor (§3.1.4). The browser is the entry
    # precondition: we need a JS bundle to scrape before the
    # extractor can find endpoints. The granted capability is
    # ``ssrf_primitive`` (each endpoint is a potential SSRF
    # target once the chainer pivots).
    catalog.append(Skill(
        name="api_endpoint_extractor",
        tool_name="js_source_crawler",
        preconditions=[],
        effects=[
            SkillEffect(
                kind="capability",
                name="ssrf_primitive",
                confidence=0.4,
            ),
        ],
        fallback_chain=["dom_xss_hunter"],
        description=(
            "Extracts API endpoints from the target's JS bundles "
            "and surfaces them to the chainer. Entry point for "
            "the chain-level signal amplification in plan §3.1.4."
        ),
    ))

    # 9: DOMXSSHunter (§3.2.1). Real-browser DOM-XSS detection.
    # Grants session_hijack so the XSSPlusCSPGap chain can pick up
    # downstream.
    catalog.append(Skill(
        name="dom_xss_hunter",
        tool_name="dom_xss_hunter",
        preconditions=[],
        effects=[
            SkillEffect(
                kind="belief",
                key="endpoint:dom_xss",
                value="true",
                confidence=0.7,
            ),
            SkillEffect(
                kind="capability",
                name="session_hijack",
                confidence=0.6,
            ),
        ],
        fallback_chain=["xss_plus_csp_gap"],
        description=(
            "DOM-XSS detection via a real headless browser. "
            "Plan §3.2.1 — fires fragment-based XSS vectors at "
            "the live target and observes postMessage / innerHTML "
            "side effects."
        ),
    ))

    return catalog


def register_default_skills(registry: SkillRegistry | None = None) -> int:
    """Register the 9 first-class Skills (plan §3.3.1 + §3.1.4 + §3.2.1).

    Idempotent: registering twice is a hard error (the
    SkillRegistry rejects overwrites by design). Callers that
    want a clean slate should use a fresh ``SkillRegistry``
    instance.

    Returns:
        Number of skills registered.
    """
    reg = registry if registry is not None else get_skill_registry()
    for skill in build_default_skill_catalog():
        reg.register(skill)
    return len(reg)


__all__ = [
    "Skill",
    "SkillEffect",
    "SkillNotApplicable",
    "AllFallbacksFailed",
    "SkillRegistry",
    "get_skill_registry",
    "reset_skill_registry",
    "register_default_skills",
    "build_default_skill_catalog",
]
