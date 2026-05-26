"""Embedding model wrapper for finding deduplication."""

from typing import Any

import ollama as _ollama

from src.core.config import get_settings
from src.core.exceptions import LLMError


class EmbeddingClient:
    """Async client for Ollama embedding endpoint (always local)."""

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        settings = get_settings()
        # Embeddings always use local Ollama
        host = base_url or "http://localhost:11434"
        self.model = model or settings.ollama_embedding_model
        self._kwargs: dict[str, Any] = {"host": host}

    async def _client(self) -> _ollama.AsyncClient:
        return _ollama.AsyncClient(**self._kwargs)

    async def embed(self, text: str) -> list[float]:
        """Return embedding vector for a single text."""
        try:
            client = await self._client()
            response = await client.embeddings(model=self.model, prompt=text)
            embedding = response.embedding
            if not embedding:
                raise LLMError(message="Empty embedding response", model=self.model)
            return embedding
        except LLMError:
            raise
        except Exception as exc:
            raise LLMError(message=f"Embedding error: {exc}", model=self.model) from exc

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Return embedding vectors for a batch of texts."""
        results: list[list[float]] = []
        for text in texts:
            vec = await self.embed(text)
            results.append(vec)
        return results

    async def close(self) -> None:
        pass  # ollama library manages connections internally