"""Closed capability vocabulary for the ExploitChainer BFS.

Per plan §5.4.bis: the chainer matches `(finding_class, capability)` pairs
across `GraphEdge.consumes` and `GraphEdge.grants`. The match is meaningless
if the LLM can emit any free-form string for `capability` (e.g.
`"bogus_capability"`, `"admin"`, `"rce"`) — that would silently produce
zero chains and the failure mode is invisible from the BFS output.

This module is the closed-set source of truth:

  - `CAPABILITY_VOCABULARY` — frozenset of the 11 valid capability strings
  - `Capability`            — StrEnum, single declaration of the same set
  - `guard_capability()`    — runtime validator: returns the input if valid,
                              or None with a logger.warning if not

The runtime guard is wired into `src/graph/attack_graph.py:AttackGraphBuilder
._extract_edges` (per plan §3.3.1.bis). The static check is wired into
`tests/unit/test_capabilities.py::test_vocabulary_is_closed_set`.

Per plan §3.3.1.bis: a runtime guard is REQUIRED, not optional. The static
check alone is not enough because the value originates from the LLM at
runtime, not from a Python source file.
"""
from __future__ import annotations

import logging
from enum import StrEnum

logger = logging.getLogger(__name__)


class Capability(StrEnum):
    """Closed set of capability strings used by the ExploitChainer BFS.

    The 11 values are intentional: each represents a primitive that
    enables a specific chain pattern. Adding a new capability requires
    (1) adding it here, (2) updating the chain pattern consumes/grants
    tables in src/graph/exploit_chains.py, and (3) updating the static
    test in tests/unit/test_capabilities.py.
    """

    # Auth / session manipulation
    SESSION_HIJACK = "session_hijack"  # XSS chain → cookie theft
    AUTH_BYPASS = "auth_bypass"        # JWTNone, OpenRedirect+OAuth, IDOR+Admin

    # Data plane
    LFI_PRIMITIVE = "lfi_primitive"          # SSTI+LFI chain
    SQLI_PRIMITIVE = "sqli_primitive"        # SQLi data extraction
    CLOUD_META_ACCESS = "cloud_meta_access"  # SSRF+CloudMeta chain

    # Server-side
    SSRF_PRIMITIVE = "ssrf_primitive"  # SSRF base primitive
    RCE_PRIMITIVE = "rce_primitive"    # SSTI+RCE, deserialization chains
    FILE_WRITE = "file_write"          # LFI→write, upload chains

    # Network / recon
    OPEN_REDIRECT = "open_redirect"        # OpenRedirect+OAuth chain
    GRAPHQL_INTROSPECTION = "graphql_introspection"  # GraphQL chain

    # Identity / privilege
    PRIVILEGE_ESCALATION = "privilege_escalation"  # IDOR+Admin chain


# Frozen at import time. The ExploitChainer imports this and uses it for
# both the runtime guard and the consumes/grants table lookups.
CAPABILITY_VOCABULARY: frozenset[str] = frozenset(c.value for c in Capability)


def guard_capability(capability_str: str | None) -> str | None:
    """Return ``capability_str`` if it is in the closed vocabulary, else None.

    Logs a WARNING when an unknown capability is rejected. Callers MUST treat
    None as "no capability grounded" — the BFS will skip edges that lack
    a valid capability match.

    This is the runtime guard specified in plan §3.3.1.bis. It is the SECOND
    line of defense (the first is the static test that verifies the
    vocabulary is closed at import time).
    """
    if capability_str is None:
        return None
    if capability_str in CAPABILITY_VOCABULARY:
        return capability_str
    logger.warning(
        "Unknown capability %r rejected; setting to NULL. "
        "Add to src/graph/capabilities.py:Capability if legitimate.",
        capability_str,
    )
    return None


__all__ = ["Capability", "CAPABILITY_VOCABULARY", "guard_capability"]
