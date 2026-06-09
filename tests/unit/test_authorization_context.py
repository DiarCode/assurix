"""Unit tests for AuthorizationContext + ToolProtocol auth integration (plan §5.11).

Coverage:
  1. AuthorizationContext is frozen — mutation raises FrozenInstanceError.
  2. Role must be in the closed set.
  3. Capabilities must be in the closed vocabulary.
  4. for_engagement convenience constructor.
  5. has_capability / is_in_scope / can_act_as predicates.
  6. safe_dict excludes auth_token.
  7. __repr__ redacts the auth token.
  8. ToolProtocol.check_authorization default pass-through.
  9. ToolProtocol.run signature accepts auth parameter.
  10. ToolProtocol.check_authorization rejects out-of-scope targets.
"""
from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

import pytest

from src.agents.tools.authorization import AuthorizationContext
from src.agents.tools.protocol import ToolProtocol
from src.agents.verification.triad import ScopePolicy


# --- AuthorizationContext ---------------------------------------------

class TestAuthorizationContext:
    def test_minimal_construction(self) -> None:
        ctx = AuthorizationContext(engagement_id="e1", target_url="https://t.example/")
        assert ctx.engagement_id == "e1"
        assert ctx.target_url == "https://t.example/"
        assert ctx.role == "anonymous"
        assert ctx.auth_token is None
        assert ctx.capabilities == frozenset()

    def test_is_frozen(self) -> None:
        ctx = AuthorizationContext(engagement_id="e1", target_url="https://t.example/")
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.engagement_id = "e2"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.role = "admin"  # type: ignore[misc]

    def test_invalid_role_rejected(self) -> None:
        with pytest.raises(ValueError, match="role must be one of"):
            AuthorizationContext(
                engagement_id="e1",
                target_url="https://t.example/",
                role="superuser",  # type: ignore[arg-type]
            )

    def test_invalid_capability_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown tokens"):
            AuthorizationContext(
                engagement_id="e1",
                target_url="https://t.example/",
                capabilities=frozenset({"not_a_real_capability"}),
            )

    def test_valid_capability_accepted(self) -> None:
        ctx = AuthorizationContext(
            engagement_id="e1",
            target_url="https://t.example/",
            capabilities=frozenset({"session_hijack", "ssrf_primitive"}),
        )
        assert "session_hijack" in ctx.capabilities
        assert "ssrf_primitive" in ctx.capabilities

    def test_for_engagement_defaults(self) -> None:
        ctx = AuthorizationContext.for_engagement(
            engagement_id="e2",
            target_url="https://t.example/",
        )
        assert ctx.engagement_id == "e2"
        assert ctx.scope == ScopePolicy()  # default allow-all

    def test_for_engagement_overrides(self) -> None:
        scope = ScopePolicy(allowed_host_patterns=("acme.example",))
        ctx = AuthorizationContext.for_engagement(
            engagement_id="e3",
            target_url="https://acme.example/admin",
            role="admin",
            auth_token="secret-xyz",
            scope=scope,
            capabilities={"rce_primitive", "auth_bypass"},
        )
        assert ctx.role == "admin"
        assert ctx.auth_token == "secret-xyz"
        assert ctx.is_in_scope() is True
        assert ctx.has_capability("rce_primitive") is True

    def test_has_capability(self) -> None:
        ctx = AuthorizationContext(
            engagement_id="e1",
            target_url="https://t.example/",
            capabilities=frozenset({"session_hijack"}),
        )
        assert ctx.has_capability("session_hijack") is True
        assert ctx.has_capability("rce_primitive") is False

    def test_is_in_scope_uses_target_url_by_default(self) -> None:
        scope = ScopePolicy(allowed_host_patterns=("acme.example",))
        ctx = AuthorizationContext(
            engagement_id="e1",
            target_url="https://acme.example/admin",
            scope=scope,
        )
        assert ctx.is_in_scope() is True
        assert ctx.is_in_scope("https://other.example/") is False

    def test_can_act_as_hierarchy(self) -> None:
        admin = AuthorizationContext(
            engagement_id="e1", target_url="https://t.example/", role="admin"
        )
        user = AuthorizationContext(
            engagement_id="e1", target_url="https://t.example/", role="user"
        )
        anon = AuthorizationContext(
            engagement_id="e1", target_url="https://t.example/", role="anonymous"
        )
        # admin can act as user and anonymous
        assert admin.can_act_as("admin") is True
        assert admin.can_act_as("user") is True
        assert admin.can_act_as("anonymous") is True
        # user can act as user and anonymous but not admin
        assert user.can_act_as("user") is True
        assert user.can_act_as("anonymous") is True
        assert user.can_act_as("admin") is False
        # anonymous can only act as anonymous
        assert anon.can_act_as("anonymous") is True
        assert anon.can_act_as("user") is False
        assert anon.can_act_as("admin") is False

    def test_safe_dict_excludes_auth_token(self) -> None:
        ctx = AuthorizationContext(
            engagement_id="e1",
            target_url="https://t.example/",
            auth_token="supersecret",
        )
        d = ctx.safe_dict()
        assert "auth_token" not in d
        assert d["has_auth_token"] is True
        assert d["engagement_id"] == "e1"

    def test_repr_redacts_token(self) -> None:
        ctx = AuthorizationContext(
            engagement_id="e1",
            target_url="https://t.example/",
            auth_token="supersecret",
        )
        r = repr(ctx)
        assert "supersecret" not in r
        assert "<redacted>" in r

    def test_repr_without_token_uses_none(self) -> None:
        ctx = AuthorizationContext(engagement_id="e1", target_url="https://t.example/")
        r = repr(ctx)
        assert "auth_token=None" in r


# --- ToolProtocol integration -----------------------------------------

class _AuthAwareTool(ToolProtocol):
    """A minimal tool that records whether it received auth context."""

    name = "auth_aware"
    capability_tags = ["xss_sink"]

    def __init__(self) -> None:
        self.last_auth: AuthorizationContext | None = None
        self.last_target: str | None = None

    async def run(
        self,
        target: str,
        hypothesis: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: AuthorizationContext | None = None,
    ) -> Any:
        self.last_target = target
        self.last_auth = auth
        return {"ran": True, "had_auth": auth is not None}

    def describe_capabilities(self) -> list[Any]:
        return []


class TestToolProtocolAuth:
    def test_run_accepts_auth_parameter(self) -> None:
        """The new optional auth parameter is accepted by the protocol."""
        import inspect
        sig = inspect.signature(ToolProtocol.run)
        assert "auth" in sig.parameters
        # The parameter must be optional (have a default of None).
        assert sig.parameters["auth"].default is None

    def test_tool_receives_auth_when_provided(self) -> None:
        tool = _AuthAwareTool()
        ctx = AuthorizationContext(
            engagement_id="e1", target_url="https://t.example/", role="admin"
        )
        result = asyncio.run(tool.run(target="https://t.example/", auth=ctx))
        assert result["had_auth"] is True
        assert tool.last_auth is ctx

    def test_tool_works_without_auth_for_legacy_compat(self) -> None:
        """Existing call sites that pass no auth must still work."""
        tool = _AuthAwareTool()
        result = asyncio.run(tool.run(target="https://t.example/"))
        assert result["had_auth"] is False
        assert tool.last_auth is None

    def test_check_authorization_default_passthrough(self) -> None:
        tool = _AuthAwareTool()
        # No auth -> legacy mode -> ok
        ok, reason = tool.check_authorization(None)
        assert ok is True
        assert "legacy" in reason.lower()

    def test_check_authorization_in_scope(self) -> None:
        tool = _AuthAwareTool()
        ctx = AuthorizationContext(
            engagement_id="e1", target_url="https://acme.example/", role="user"
        )
        ok, reason = tool.check_authorization(ctx)
        assert ok is True
        assert "ok" in reason.lower() or "in scope" in reason.lower()

    def test_check_authorization_out_of_scope(self) -> None:
        tool = _AuthAwareTool()
        scope = ScopePolicy(allowed_host_patterns=("acme.example",))
        ctx = AuthorizationContext(
            engagement_id="e1",
            target_url="https://other.example/",
            scope=scope,
        )
        ok, reason = tool.check_authorization(ctx)
        assert ok is False
        assert "not in scope" in reason
