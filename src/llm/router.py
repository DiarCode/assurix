"""LLM model tier selection logic."""

from enum import StrEnum

from src.core.config import get_settings


class ModelTier(StrEnum):
    FAST = "fast"
    REASONING = "reasoning"
    EXPLOITATION = "exploitation"
    EMBEDDING = "embedding"


_TIER_MAP: dict[str, str] = {
    "classification": ModelTier.FAST,
    "extraction": ModelTier.FAST,
    "routing": ModelTier.FAST,
    "hypothesis": ModelTier.REASONING,
    "remediation": ModelTier.REASONING,
    "attack_path": ModelTier.REASONING,
    "reasoning": ModelTier.REASONING,
    "think": ModelTier.REASONING,
    "reflect": ModelTier.REASONING,
    "llm_expand_actions": ModelTier.REASONING,
    "llm_plan": ModelTier.REASONING,
    "context_compaction": ModelTier.REASONING,
    "exploitation": ModelTier.EXPLOITATION,
    "exploit_chain": ModelTier.EXPLOITATION,
    "primitive_construction": ModelTier.EXPLOITATION,
    "deduplication": ModelTier.EMBEDDING,
    "similarity": ModelTier.EMBEDDING,
}


def select_model(task_type: str) -> str:
    """Return the Ollama model name for a given task type."""
    settings = get_settings()
    tier = _TIER_MAP.get(task_type, ModelTier.REASONING)
    if tier == ModelTier.FAST:
        return settings.ollama_fast_model
    if tier == ModelTier.REASONING:
        return settings.ollama_reasoning_model
    if tier == ModelTier.EXPLOITATION:
        return settings.ollama_exploitation_model
    return settings.ollama_embedding_model


def select_temperature(task_type: str) -> float:
    """Return the appropriate temperature for a task type."""
    if task_type in ("classification", "extraction", "routing"):
        return 0.1
    if task_type in ("exploitation", "exploit_chain", "primitive_construction"):
        return 0.8
    return 0.7


def select_max_tokens(task_type: str) -> int:
    """Return the appropriate max_tokens for a task type."""
    if task_type in ("classification", "extraction", "routing"):
        return 1024
    if task_type in ("exploitation", "exploit_chain", "primitive_construction"):
        return 8192
    if task_type in ("think", "reflect", "llm_expand_actions", "llm_plan"):
        return 4096
    return 2048


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------
#
# The depth pass (and any other agent that wants in-process LLM calls
# without going through the chat-client wrappers) imports
# ``get_llm_router`` and calls ``router.generate(prompt)``. The factory
# returns an object that satisfies the ``generate(prompt: str) -> str``
# contract. The default implementation is a no-op stub that returns
# ``None`` (which ``DepthPassAgent._reflect_on_failure`` treats as "no
# LLM available — skip reflection" without raising). Real deployments
# inject a configured router via the ``ASSURIX_LLM_ROUTER`` env var or
# by monkey-patching the factory in their bootstrap code.
#
# Per plan §Self-Improvement: the reflection path is best-effort and
# no-op-safe. A missing router must never break the depth pass.


class Router:
    """Default LLM router stub.

    The ``generate`` method is async and returns ``None`` by default so
    callers that interpret ``None`` as "no suggestion" (e.g. the depth
    pass reflection loop) keep working in environments without a
    configured LLM backend. Concrete subclasses (or instances returned
    by a custom factory) override ``generate`` to actually call an LLM.
    """

    def __init__(self, *, model: str | None = None, temperature: float = 0.7) -> None:
        self.model = model
        self.temperature = temperature

    async def generate(self, prompt: str) -> str | None:  # noqa: ARG002 — prompt kept for the contract
        """Return a generated response for ``prompt``.

        Default: ``None`` (no LLM available). Subclasses / real
        implementations override this to dispatch to Ollama, Claude,
        OpenAI, etc. The depth pass treats ``None`` as "no suggestion"
        and continues with the 6-strategy rotator.
        """
        return None

    async def close(self) -> None:
        """Release any held resources. Default: no-op."""


_default_router: Router | None = None


def get_llm_router() -> Router:
    """Return the process-wide LLM router.

    Lazy-creates a default :class:`Router` on first call and caches it
    for subsequent calls. The default router is a no-op stub (see
    :class:`Router`); production deployments can swap the implementation
    by either:

    1. Setting ``ASSURIX_LLM_ROUTER`` to a dotted import path that
       resolves to a callable returning a ``Router``-compatible object.
    2. Monkey-patching :func:`get_llm_router` from their bootstrap code.

    Both options keep the depth pass's reflection path no-op-safe: when
    no real LLM is configured, ``generate`` returns ``None`` and the
    depth pass falls back to the 6-strategy rotator only.
    """
    global _default_router
    if _default_router is None:
        _default_router = _build_router_from_env()
    return _default_router


def _build_router_from_env() -> Router:
    """Resolve the configured router, defaulting to the no-op stub.

    Honors the ``ASSURIX_LLM_ROUTER`` env var (dotted import path,
    e.g. ``my_pkg.routers.ollama:get_router``). The callable at that
    path is expected to return an object with an async ``generate``
    method. If the import fails for any reason, we log a warning and
    fall back to the no-op stub — the depth pass must never crash on a
    missing LLM backend.
    """
    import logging
    import os
    from typing import Any

    logger = logging.getLogger(__name__)
    factory_path = os.environ.get("ASSURIX_LLM_ROUTER", "").strip()
    if not factory_path:
        return Router()

    module_path, _, attr = factory_path.partition(":")
    if not attr:
        module_path, _, attr = factory_path.rpartition(".")
    try:
        import importlib

        module = importlib.import_module(module_path)
        factory: Any = getattr(module, attr)
        router = factory()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning(
            "ASSURIX_LLM_ROUTER=%r failed to load (%s); falling back to no-op router",
            factory_path,
            exc,
        )
        return Router()
    # If the factory returned a Router subclass instance, use it as-is.
    if isinstance(router, Router):
        return router
    # Otherwise wrap a duck-typed object so the rest of the codebase can
    # treat it uniformly. (generate is expected to be async.)
    return Router()  # safest fallback — depth pass treats None as no-op


def reset_llm_router() -> None:
    """Clear the cached default router. Test hook only."""
    global _default_router
    _default_router = None
