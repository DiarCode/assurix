"""LLM model tier selection logic."""

from enum import StrEnum

from src.core.config import get_settings


class ModelTier(StrEnum):
    FAST = "fast"
    REASONING = "reasoning"
    EMBEDDING = "embedding"


_TIER_MAP: dict[str, str] = {
    "classification": ModelTier.FAST,
    "extraction": ModelTier.FAST,
    "routing": ModelTier.FAST,
    "hypothesis": ModelTier.REASONING,
    "remediation": ModelTier.REASONING,
    "attack_path": ModelTier.REASONING,
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
    return settings.ollama_embedding_model


def select_temperature(task_type: str) -> float:
    """Return the appropriate temperature for a task type."""
    if task_type in ("classification", "extraction", "routing"):
        return 0.1
    return 0.7
