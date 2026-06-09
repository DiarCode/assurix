"""AuthorizationContext — immutable auth/scope context for tool invocations (plan §5.11).

The dataclass is the single source of truth for the "what can this
tool do right now?" question. Every ``ToolProtocol.run()`` call
receives one; tools must NOT mutate it (the dataclass is ``frozen=True``
so a runtime attempt raises ``FrozenInstanceError``).

Why a separate context object?

  - The browser's own JavaScript cannot reach it. The context is
    passed via the tool boundary (in-process) and is therefore
    completely invisible to the target application. This is a defense
    against prompt-injection attacks where an attacker plants JS that
    tries to read the auth state from the page.
  - The dataclass is part of the *tool contract* — ``ToolRegistry``
    can statically reason about which tools are eligible for which
    context (e.g. an admin-only tool cannot run under a user role).
  - ``AuthorizationContext.frozen`` is the structural enforcement of
    rule #9 ("Don't allow tools to mutate AuthorizationContext")
    from the plan's operating principles.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

from src.agents.verification.triad import ScopePolicy
from src.graph.capabilities import CAPABILITY_VOCABULARY

logger = logging.getLogger(__name__)


# Roles are a closed set. New roles require a new plan-level ADR.
Role = Literal["anonymous", "user", "admin", "system"]


@dataclass(frozen=True)
class AuthorizationContext:
    """Immutable auth/scope context for a single tool invocation.

    Fields:
        engagement_id: The Assurix engagement this invocation belongs to.
        target_url: The target URL the tool is being asked to test.
        role: The role under which the tool is running. Closed set
              (``"anonymous"``, ``"user"``, ``"admin"``, ``"system"``).
        auth_token: Optional bearer/cookie token. Treated as
            sensitive: ``__repr__`` does not log it.
        scope: The ScopePolicy derived from the engagement.
        capabilities: A frozenset of capability strings from the closed
            vocabulary in ``src/graph/capabilities.py``. Used to gate
            tools that require a specific capability (e.g. an SSRF
            tool needs ``internal_network_reachable`` to be useful).

    The dataclass is ``frozen=True`` — any attempt to mutate a field
    raises ``dataclasses.FrozenInstanceError``. This is the structural
    fix for "tools reaching in and changing the context they were
    given" (plan operating-principle #9).
    """

    engagement_id: str
    target_url: str
    role: Role = "anonymous"
    auth_token: str | None = None
    scope: ScopePolicy = field(default_factory=ScopePolicy)
    capabilities: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        # Validate the role is in the closed set.
        valid_roles: tuple[Role, ...] = ("anonymous", "user", "admin", "system")
        if self.role not in valid_roles:
            raise ValueError(
                f"AuthorizationContext.role must be one of {valid_roles}, "
                f"got {self.role!r}"
            )
        # Validate the capabilities are in the closed vocabulary.
        if self.capabilities:
            unknown = set(self.capabilities) - CAPABILITY_VOCABULARY
            if unknown:
                raise ValueError(
                    f"AuthorizationContext.capabilities contains unknown "
                    f"tokens not in CAPABILITY_VOCABULARY: {sorted(unknown)}"
                )

    # --- Convenience constructors ---------------------------------------

    @classmethod
    def for_engagement(
        cls,
        engagement_id: str,
        target_url: str,
        *,
        role: Role = "anonymous",
        auth_token: str | None = None,
        scope: ScopePolicy | None = None,
        capabilities: set[str] | frozenset[str] | None = None,
    ) -> "AuthorizationContext":
        """Build a context for a given engagement, deriving defaults.

        ``scope`` defaults to ``ScopePolicy()`` (allow-all) if not
        provided. ``capabilities`` defaults to an empty frozenset.
        """
        return cls(
            engagement_id=engagement_id,
            target_url=target_url,
            role=role,
            auth_token=auth_token,
            scope=scope or ScopePolicy(),
            capabilities=frozenset(capabilities or ()),
        )

    # --- Predicates -----------------------------------------------------

    def has_capability(self, capability: str) -> bool:
        """True if the context has the named capability."""
        return capability in self.capabilities

    def is_in_scope(self, url: str | None = None) -> bool:
        """True if the (optionally overridden) URL is in the scope policy."""
        check_url = url or self.target_url
        return self.scope.is_in_scope(check_url)

    def can_act_as(self, role: Role) -> bool:
        """Hierarchical role check: ``admin`` can act as ``user``, etc."""
        order: dict[Role, int] = {
            "anonymous": 0,
            "user": 1,
            "admin": 2,
            "system": 3,
        }
        return order.get(self.role, -1) >= order.get(role, 99)

    # --- Safe serialisation --------------------------------------------

    def safe_dict(self) -> dict[str, Any]:
        """Serialise to a dict that does NOT include the auth token.

        Use this when logging or persisting the context; the
        ``auth_token`` field is excluded by design.
        """
        return {
            "engagement_id": self.engagement_id,
            "target_url": self.target_url,
            "role": self.role,
            "has_auth_token": self.auth_token is not None,
            "scope": {
                "allowed_host_patterns": list(self.scope.allowed_host_patterns),
                "excluded_paths": list(self.scope.excluded_paths),
                "require_https": self.scope.require_https,
            },
            "capabilities": sorted(self.capabilities),
        }

    def __repr__(self) -> str:
        # Never include the auth token in repr — log scrubbers can miss
        # it if it shows up in a stack trace.
        return (
            f"AuthorizationContext(engagement_id={self.engagement_id!r}, "
            f"target_url={self.target_url!r}, role={self.role!r}, "
            f"auth_token={'<redacted>' if self.auth_token else None}, "
            f"capabilities={sorted(self.capabilities)!r})"
        )


__all__ = ["AuthorizationContext", "Role"]
