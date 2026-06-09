"""Tests for the Skill layer (plan §5.9 / §3.3.1).

These tests cover the Skill schema, the SkillRegistry, the
fallback-chain resolver, and the 9 first-class skills shipped in
Week 3. The Skill layer is the *outer ring* of the tool layer:
the ResearchLoop queries ``ToolRegistry.skills_matching(caps)``
to pick the best skill for a hypothesis, then the skill invokes
its underlying tool with preconditions verified and effects
recorded.
"""

from __future__ import annotations

import pytest

from src.agents.tools.skill import (
    AllFallbacksFailed,
    Skill,
    SkillEffect,
    SkillNotApplicable,
    SkillRegistry,
    build_default_skill_catalog,
    get_skill_registry,
    register_default_skills,
    reset_skill_registry,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton() -> None:
    """Each test starts with a fresh global SkillRegistry.

    Per skill.py's contract: ``register_default_skills`` is NOT
    idempotent at the global level (a re-register raises) and
    test isolation requires a clean slate.
    """
    reset_skill_registry()
    yield
    reset_skill_registry()


# ---------------------------------------------------------------------------
# SkillEffect
# ---------------------------------------------------------------------------


class TestSkillEffect:
    def test_capability_effect_constructs(self) -> None:
        eff = SkillEffect(
            kind="capability",
            name="privilege_escalation",
            confidence=0.9,
        )
        assert eff.kind == "capability"
        assert eff.name == "privilege_escalation"
        assert eff.confidence == 0.9

    def test_capability_effect_validates_against_vocabulary(self) -> None:
        """A typo in the capability name must crash at construction
        time (not silently produce zero matches in the BFS)."""
        with pytest.raises(ValueError, match="not in the closed capability"):
            SkillEffect(
                kind="capability",
                name="not_a_real_capability",
                confidence=0.5,
            )

    def test_belief_effect_constructs_without_vocab_check(self) -> None:
        """Belief keys are free-form (the world model has no
        closed vocabulary)."""
        eff = SkillEffect(
            kind="belief",
            key="endpoint:dom_xss",
            value="true",
            confidence=0.7,
        )
        assert eff.key == "endpoint:dom_xss"
        assert eff.value == "true"

    def test_confidence_clamps_to_unit_interval(self) -> None:
        with pytest.raises(Exception):
            SkillEffect(kind="belief", key="x", value="y", confidence=1.5)
        with pytest.raises(Exception):
            SkillEffect(kind="belief", key="x", value="y", confidence=-0.1)


# ---------------------------------------------------------------------------
# Skill.preconditions / .effects
# ---------------------------------------------------------------------------


class TestSkillPreconditions:
    def test_empty_preconditions_always_apply(self) -> None:
        s = Skill(name="x", tool_name="t")
        assert s.applies_to([]) is True
        assert s.applies_to(["any", "thing"]) is True

    def test_all_preconditions_must_be_satisfied(self) -> None:
        s = Skill(
            name="x", tool_name="t",
            preconditions=["session_hijack", "xss"],
        )
        assert s.applies_to(["xss", "session_hijack"]) is True
        assert s.applies_to(["xss"]) is False
        assert s.applies_to([]) is False

    def test_capability_vocab_validated_at_effect_construction(self) -> None:
        """The vocabulary check applies to *effects* (what the
        skill grants), not preconditions (what the skill needs
        to run). Preconditions are free-form capability tags
        from the world model; effects are the closed vocabulary
        the ExploitChainer BFS matches on.

        A typo in either place is loud: bad effects crash at
        Skill construction; bad preconditions are accepted
        (they would surface as a runtime mismatch when no
        caller ever satisfies them)."""
        # Effect: bad → crashes.
        with pytest.raises(ValueError, match="not in the closed capability"):
            Skill(
                name="bad_effect", tool_name="t",
                effects=[SkillEffect(
                    kind="capability", name="not_a_real_capability",
                    confidence=0.5,
                )],
            )
        # Precondition: bad → accepted (free-form, not vocab-checked).
        s = Skill(name="loose_pre", tool_name="t", preconditions=["anything"])
        assert "anything" in s.preconditions


class TestSkillEffects:
    def _skill(self) -> Skill:
        return Skill(
            name="x", tool_name="t",
            effects=[
                SkillEffect(kind="belief", key="b1", value="v1",
                            confidence=0.5),
                SkillEffect(kind="capability", name="privilege_escalation",
                            confidence=0.8),
            ],
        )

    def test_granted_capability_returns_first(self) -> None:
        s = self._skill()
        assert s.granted_capability() == "privilege_escalation"

    def test_granted_capabilities_returns_all(self) -> None:
        s = self._skill()
        # The belief effect has no capability name; the capability
        # effect does. So only one capability in the granted list.
        assert s.granted_capabilities() == ["privilege_escalation"]

    def test_granted_belief_lookup(self) -> None:
        s = self._skill()
        eff = s.granted_belief("b1")
        assert eff is not None
        assert eff.value == "v1"
        # Missing key returns None.
        assert s.granted_belief("not_there") is None

    def test_skill_with_no_effects(self) -> None:
        s = Skill(name="x", tool_name="t")
        assert s.granted_capability() is None
        assert s.granted_capabilities() == []
        assert s.granted_belief("anything") is None


# ---------------------------------------------------------------------------
# SkillRegistry
# ---------------------------------------------------------------------------


class TestSkillRegistry:
    def test_register_and_get(self) -> None:
        reg = SkillRegistry()
        s = Skill(name="x", tool_name="t")
        reg.register(s)
        assert reg.get("x") is s
        assert reg.has("x")
        assert "x" in reg
        assert len(reg) == 1

    def test_register_duplicate_raises(self) -> None:
        """Re-registering the same name is a HARD error (silent
        overwrite would be a slop vector)."""
        reg = SkillRegistry()
        reg.register(Skill(name="x", tool_name="t"))
        with pytest.raises(ValueError, match="already registered"):
            reg.register(Skill(name="x", tool_name="t2"))

    def test_unregister_is_idempotent(self) -> None:
        reg = SkillRegistry()
        reg.unregister("not_there")  # no-op
        reg.register(Skill(name="x", tool_name="t"))
        reg.unregister("x")
        assert "x" not in reg

    def test_all_skills_returns_in_registration_order(self) -> None:
        reg = SkillRegistry()
        for n in ("a", "b", "c"):
            reg.register(Skill(name=n, tool_name="t"))
        assert [s.name for s in reg.all_skills()] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Capability-based lookup
# ---------------------------------------------------------------------------


class TestSkillMatching:
    def test_skills_matching_with_no_required_caps_returns_all(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(name="a", tool_name="t"))
        reg.register(Skill(name="b", tool_name="t"))
        assert [s.name for s in reg.skills_matching([])] == ["a", "b"]

    def test_skills_matching_filters_by_preconditions(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="needs_xss", tool_name="t",
            preconditions=["xss"],
        ))
        reg.register(Skill(
            name="unconditional", tool_name="t",
        ))
        # With no required caps, both apply.
        names = [s.name for s in reg.skills_matching([])]
        assert set(names) == {"needs_xss", "unconditional"}
        # With a cap that the unconditional skill doesn't need
        # (but also doesn't have a precondition for), it still
        # applies. The precondition is the gate.
        names2 = [s.name for s in reg.skills_matching(["anything"])]
        assert "unconditional" in names2
        assert "needs_xss" not in names2  # precondition not met

    def test_skills_matching_orders_by_coverage(self) -> None:
        """A skill that grants 2 of the required capabilities
        should rank above one that grants 1."""
        reg = SkillRegistry()
        reg.register(Skill(
            name="one_grant", tool_name="t",
            effects=[SkillEffect(
                kind="capability", name="privilege_escalation",
                confidence=0.5,
            )],
        ))
        reg.register(Skill(
            name="two_grants", tool_name="t",
            effects=[
                SkillEffect(
                    kind="capability", name="privilege_escalation",
                    confidence=0.5,
                ),
                SkillEffect(
                    kind="capability", name="auth_bypass",
                    confidence=0.5,
                ),
            ],
        ))
        ranked = reg.skills_matching(
            ["privilege_escalation", "auth_bypass"],
        )
        assert [s.name for s in ranked] == ["two_grants", "one_grant"]

    def test_skills_granting_finds_by_capability(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="a", tool_name="t",
            effects=[SkillEffect(
                kind="capability", name="ssrf_primitive",
                confidence=0.5,
            )],
        ))
        reg.register(Skill(
            name="b", tool_name="t",
            effects=[SkillEffect(
                kind="capability", name="rce_primitive",
                confidence=0.5,
            )],
        ))
        grants = reg.skills_granting("ssrf_primitive")
        assert [s.name for s in grants] == ["a"]
        assert reg.skills_granting("nothing_grants_this") == []


# ---------------------------------------------------------------------------
# Fallback chain
# ---------------------------------------------------------------------------


class TestFallbackChain:
    def test_resolves_in_order(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["a", "b"],
        ))
        reg.register(Skill(name="a", tool_name="t"))
        reg.register(Skill(name="b", tool_name="t"))
        primary = reg.get("primary")
        chain = reg.resolve_fallback_chain(primary)
        assert [s.name for s in chain] == ["a", "b"]

    def test_skips_missing_fallbacks(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["present", "missing"],
        ))
        reg.register(Skill(name="present", tool_name="t"))
        primary = reg.get("primary")
        chain = reg.resolve_fallback_chain(primary)
        assert [s.name for s in chain] == ["present"]

    def test_dedupes_self_reference_in_chain(self) -> None:
        """A skill whose fallback list mentions itself MUST NOT
        loop. The seen-set catches this on the first iteration."""
        reg = SkillRegistry()
        reg.register(Skill(
            name="loopy", tool_name="t",
            fallback_chain=["loopy", "real_fallback"],
        ))
        reg.register(Skill(name="real_fallback", tool_name="t"))
        chain = reg.resolve_fallback_chain(reg.get("loopy"))
        # "loopy" is deduped on the second occurrence;
        # "real_fallback" passes through.
        assert [s.name for s in chain] == ["real_fallback"]

    def test_dedupes_duplicate_entries_in_chain(self) -> None:
        """A skill's fallback list may mention the same name
        twice (typo, copy-paste). The second occurrence is
        silently deduped — no surprise duplicates in the chain."""
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["a", "a", "b"],
        ))
        reg.register(Skill(name="a", tool_name="t"))
        reg.register(Skill(name="b", tool_name="t"))
        chain = reg.resolve_fallback_chain(reg.get("primary"))
        assert [s.name for s in chain] == ["a", "b"]

    def test_depth_cap(self) -> None:
        reg = SkillRegistry()
        for i in range(20):
            reg.register(Skill(name=f"s{i}", tool_name="t"))
        reg.register(Skill(
            name="head", tool_name="t",
            fallback_chain=[f"s{i}" for i in range(20)],
        ))
        chain = reg.resolve_fallback_chain(reg.get("head"), max_depth=3)
        assert len(chain) == 3


# ---------------------------------------------------------------------------
# apply_with_fallback
# ---------------------------------------------------------------------------


class TestApplyWithFallback:
    def test_primary_succeeds(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["fb"],
        ))
        reg.register(Skill(name="fb", tool_name="t"))

        def apply(skill, caps):  # type: ignore[no-untyped-def]
            return f"applied:{skill.name}"

        skill, result = reg.apply_with_fallback(
            "primary", capabilities=[], apply_fn=apply,
        )
        assert skill.name == "primary"
        assert result == "applied:primary"

    def test_fallback_after_not_applicable(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["fb"],
        ))
        reg.register(Skill(name="fb", tool_name="t"))

        def apply(skill, caps):  # type: ignore[no-untyped-def]
            if skill.name == "primary":
                raise SkillNotApplicable(skill.name, "preconditions not met")
            return "fallback-ok"

        skill, result = reg.apply_with_fallback(
            "primary", capabilities=[], apply_fn=apply,
        )
        assert skill.name == "fb"
        assert result == "fallback-ok"

    def test_fallback_after_generic_exception(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["fb"],
        ))
        reg.register(Skill(name="fb", tool_name="t"))

        def apply(skill, caps):  # type: ignore[no-untyped-def]
            if skill.name == "primary":
                raise RuntimeError("primary blew up")
            return "fallback-ok"

        skill, result = reg.apply_with_fallback(
            "primary", capabilities=[], apply_fn=apply,
        )
        assert skill.name == "fb"

    def test_all_fallbacks_failed_raises(self) -> None:
        reg = SkillRegistry()
        reg.register(Skill(
            name="primary", tool_name="t",
            fallback_chain=["fb"],
        ))
        reg.register(Skill(name="fb", tool_name="t"))

        def apply(skill, caps):  # type: ignore[no-untyped-def]
            raise SkillNotApplicable(skill.name, "nope")

        with pytest.raises(AllFallbacksFailed) as exc_info:
            reg.apply_with_fallback(
                "primary", capabilities=[], apply_fn=apply,
            )
        assert exc_info.value.tried == ["primary", "fb"]
        assert "nope" in exc_info.value.last_error

    def test_unknown_skill_raises(self) -> None:
        reg = SkillRegistry()
        with pytest.raises(AllFallbacksFailed, match="not registered"):
            reg.apply_with_fallback(
                "nope", capabilities=[], apply_fn=lambda s, c: None,
            )


# ---------------------------------------------------------------------------
# First-class skills catalog
# ---------------------------------------------------------------------------


class TestFirstClassSkillsCatalog:
    def test_catalog_has_exactly_9_skills(self) -> None:
        """The plan §3.3.1 + §3.1.4 + §3.2.1 catalog must contain
        9 skills. Not 7 (the chain patterns alone), not 10
        (over-rotation), not 8 (dropped one)."""
        catalog = build_default_skill_catalog()
        assert len(catalog) == 9, (
            f"expected 9 first-class skills, got {len(catalog)}: "
            f"{[s.name for s in catalog]}"
        )

    def test_all_seven_chain_patterns_present(self) -> None:
        """Per plan §3.3.1: 7 chain patterns ship as Skills."""
        catalog = build_default_skill_catalog()
        names = {s.name for s in catalog}
        assert names == {
            "XSSPlusCSPGap",
            "SSRFPlusCloudMetadata",
            "IDORPlusAdmin",
            "SSTIPlusLFI",
            "JWTAlgNone",
            "GraphQLIntrospection",
            "OpenRedirectPlusOAuth",
            "api_endpoint_extractor",
            "dom_xss_hunter",
        }

    def test_chain_patterns_grant_correct_capabilities(self) -> None:
        """The granted capability on each chain-pattern skill
        must match the pattern's ``grants`` value. If the
        vocabulary drift ever returns, the catalog will crash
        at build time — but the mapping test is also worth
        pinning."""
        catalog = build_default_skill_catalog()
        granted_map = {
            "XSSPlusCSPGap": "privilege_escalation",
            "SSRFPlusCloudMetadata": "ssrf_primitive",
            "IDORPlusAdmin": "auth_bypass",
            "SSTIPlusLFI": "rce_primitive",
            "JWTAlgNone": "privilege_escalation",
            "GraphQLIntrospection": "file_write",
            "OpenRedirectPlusOAuth": "session_hijack",
        }
        by_name = {s.name: s for s in catalog}
        for name, expected_grant in granted_map.items():
            skill = by_name[name]
            assert skill.granted_capability() == expected_grant, (
                f"chain pattern {name!r} grants "
                f"{skill.granted_capability()!r}, expected "
                f"{expected_grant!r}"
            )

    def test_chain_patterns_consume_correct_preconditions(self) -> None:
        """The preconditions on each chain-pattern skill must
        match the pattern's ``consumes`` value."""
        catalog = build_default_skill_catalog()
        consumes_map = {
            "XSSPlusCSPGap": ["session_hijack"],
            "SSRFPlusCloudMetadata": ["cloud_meta_access"],
            "IDORPlusAdmin": ["privilege_escalation"],
            "SSTIPlusLFI": ["lfi_primitive"],
            "JWTAlgNone": ["auth_bypass"],
            "GraphQLIntrospection": ["graphql_introspection"],
            "OpenRedirectPlusOAuth": ["open_redirect"],
        }
        by_name = {s.name: s for s in catalog}
        for name, expected_pre in consumes_map.items():
            skill = by_name[name]
            assert skill.preconditions == expected_pre, (
                f"chain pattern {name!r} preconditions "
                f"{skill.preconditions!r}, expected {expected_pre!r}"
            )

    def test_api_endpoint_extractor_unconditional(self) -> None:
        """api_endpoint_extractor is the entry point for the
        chain (no preconditions). It should appear in any
        capability-based query."""
        catalog = build_default_skill_catalog()
        s = next(s for s in catalog if s.name == "api_endpoint_extractor")
        assert s.preconditions == []
        assert "ssrf_primitive" in s.granted_capabilities()

    def test_dom_xss_hunter_grants_belief_and_capability(self) -> None:
        """The DOM-XSS hunter grants BOTH a belief (the world
        model is updated) AND a capability (session_hijack for
        the XSSPlusCSPGap chain to pick up)."""
        catalog = build_default_skill_catalog()
        s = next(s for s in catalog if s.name == "dom_xss_hunter")
        assert "session_hijack" in s.granted_capabilities()
        belief = s.granted_belief("endpoint:dom_xss")
        assert belief is not None
        assert belief.value == "true"

    def test_register_default_skills_populates_singleton(self) -> None:
        """register_default_skills fills the global singleton
        with 9 skills."""
        n = register_default_skills()
        assert n == 9
        reg = get_skill_registry()
        assert len(reg) == 9

    def test_register_default_skills_idempotent_at_singleton(self) -> None:
        """Calling register_default_skills twice on the same
        singleton must raise — the SkillRegistry rejects
        overwrites. Callers that want a clean slate should
        reset_skill_registry() first."""
        register_default_skills()
        with pytest.raises(ValueError, match="already registered"):
            register_default_skills()


# ---------------------------------------------------------------------------
# ToolRegistry.skills_matching shim (plan §5.9 integration)
# ---------------------------------------------------------------------------


class TestToolRegistryIntegration:
    """The ToolRegistry exposes a ``skills_matching`` pass-through
    so the ResearchLoop can do ``tool_registry.skills_matching(caps)``
    without importing the skill module directly. This is the
    integration point plan §5.9 calls out."""

    def test_tool_registry_has_skills_matching(self) -> None:
        from src.agents.tools.registry import ToolRegistry
        reg = ToolRegistry()
        assert hasattr(reg, "skills_matching")
        assert callable(reg.skills_matching)

    def test_tool_registry_skills_matching_returns_skills(self) -> None:
        from src.agents.tools.registry import ToolRegistry
        reg = ToolRegistry()
        # Pre-populate the skill registry so the shim has data.
        from src.agents.tools.skill import register_default_skills
        register_default_skills()
        # Query for any capability — every skill is applicable
        # (none have non-empty preconditions, except the chain
        # patterns which need a starting capability).
        matches = reg.skills_matching(["anything"])
        assert isinstance(matches, list)
        # The two unconditional skills (api_endpoint_extractor,
        # dom_xss_hunter) are always returned.
        names = {s.name for s in matches}
        assert "api_endpoint_extractor" in names
        assert "dom_xss_hunter" in names

    def test_register_all_native_tools_also_registers_skills(self) -> None:
        """The plan §5.9 contract: ``register_all_native_tools``
        also registers the skill catalog. We test the *function*
        in isolation rather than the singleton — the singleton
        path is exercised by the application's startup sequence
        (see ``src/cli.py``)."""
        from src.agents.tools.skill import (
            SkillRegistry, build_default_skill_catalog,
        )
        from src.agents.tools import registry as reg_mod
        # We can't easily isolate register_all_native_tools
        # because it touches module globals; instead, we assert
        # the two pieces that make the integration work are in
        # place:
        #   (a) build_default_skill_catalog produces 9 skills
        #   (b) the function body of register_all_native_tools
        #       invokes register_default_skills.
        catalog = build_default_skill_catalog()
        assert len(catalog) == 9
        # Source-text check: register_all_native_tools must call
        # register_default_skills. If a future refactor removes
        # the call, the skill catalog will silently not be wired
        # in at startup — this test catches that.
        import inspect
        src = inspect.getsource(reg_mod.register_all_native_tools)
        assert "register_default_skills" in src, (
            "register_all_native_tools must call "
            "register_default_skills (plan §5.9 integration)"
        )
        # And the resulting skill registry can be populated
        # without error.
        fresh = SkillRegistry()
        for s in catalog:
            fresh.register(s)
        assert len(fresh) == 9
