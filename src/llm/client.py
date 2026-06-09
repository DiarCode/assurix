"""Async Ollama client wrapper with retry and fallback."""

import asyncio
import logging
from typing import Any

import ollama as _ollama

from src.core.config import get_settings
from src.core.exceptions import LLMError
from src.llm.json_utils import extract_json_from_response
from src.llm.router import select_model, select_temperature

logger = logging.getLogger(__name__)

# Backward-compat alias — re-exported for modules that imported the regex.
# New code should import from src.llm.json_utils instead.
__all__ = ["OllamaClient"]


class OllamaClient:
    """Async client for Ollama completions with retry and model fallback."""

    def __init__(self, base_url: str | None = None, timeout: float = 120.0, max_retries: int = 3) -> None:
        settings = get_settings()
        host = (base_url or settings.ollama_host).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._kwargs: dict[str, Any] = {"host": host}
        if settings.ollama_api_key:
            self._kwargs["headers"] = {"Authorization": f"Bearer {settings.ollama_api_key}"}
        self._fast_model = settings.ollama_fast_model
        self._reasoning_model = settings.ollama_reasoning_model
        self._exploitation_model = settings.ollama_exploitation_model
        self._num_ctx = settings.ollama_num_ctx

    async def _client(self) -> _ollama.AsyncClient:
        return _ollama.AsyncClient(**self._kwargs)

    async def _call_with_retry(self, call_fn, model_name: str) -> Any:
        """Execute an LLM call with retries and model fallback on failure."""
        models_to_try = [model_name]
        if model_name == self._exploitation_model:
            models_to_try.append(self._reasoning_model)
            models_to_try.append(self._fast_model)
        elif model_name == self._reasoning_model:
            models_to_try.append(self._exploitation_model)
            models_to_try.append(self._fast_model)
        elif model_name == self._fast_model:
            models_to_try.append(self._reasoning_model)
            models_to_try.append(self._exploitation_model)

        last_error = None
        for model in models_to_try:
            for attempt in range(self.max_retries):
                try:
                    return await call_fn(model)
                except _ollama.ResponseError as exc:
                    last_error = exc
                    if exc.status_code == 503:
                        wait = 2 ** attempt
                        logger.warning("LLM 503 for %s, retry %d/%d in %ds", model, attempt + 1, self.max_retries, wait)
                        await asyncio.sleep(wait)
                        continue
                    raise LLMError(message=f"Ollama error: {exc}", model=model) from exc
                except (ConnectionError, TimeoutError, OSError) as exc:
                    last_error = exc
                    wait = 2 ** attempt
                    logger.warning("LLM connection error for %s, retry %d/%d: %s", model, attempt + 1, self.max_retries, exc)
                    await asyncio.sleep(wait)
                    continue
                except Exception as exc:
                    last_error = exc
                    logger.warning("LLM error for %s: %s", model, exc)
                    break
            logger.warning("Model %s failed all retries, trying fallback", model)
        raise LLMError(message=f"All LLM calls failed: {last_error}", model=model_name)

    async def generate(
        self,
        prompt: str,
        task_type: str = "reasoning",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int = 2048,
    ) -> str:
        """Send a completion request to Ollama and return the generated text."""
        model_name = model or select_model(task_type)
        temp = temperature if temperature is not None else select_temperature(task_type)

        async def _call(m: str) -> str:
            client = await self._client()
            options: dict[str, Any] = {"temperature": temp, "num_predict": max_tokens}
            if self._num_ctx:
                options["num_ctx"] = self._num_ctx
            response = await client.generate(
                model=m,
                prompt=prompt,
                options=options,
            )
            return response.response

        return await self._call_with_retry(_call, model_name)

    async def chat(
        self,
        messages: list[dict[str, str]],
        task_type: str = "reasoning",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int = 2048,
    ) -> str:
        """Send a chat completion request to Ollama."""
        model_name = model or select_model(task_type)
        temp = temperature if temperature is not None else select_temperature(task_type)

        async def _call(m: str) -> str:
            client = await self._client()
            options: dict[str, Any] = {"temperature": temp, "num_predict": max_tokens}
            if self._num_ctx:
                options["num_ctx"] = self._num_ctx
            response = await client.chat(
                model=m,
                messages=messages,
                options=options,
            )
            return response.message.content

        return await self._call_with_retry(_call, model_name)

    @staticmethod
    def extract_json(text: str) -> dict | list | None:
        """DEPRECATED: Use ``src.llm.json_utils.extract_json_from_response`` instead.

        Retained as a thin wrapper so legacy call sites keep working.
        """
        return extract_json_from_response(text)

    async def close(self) -> None:
        pass  # ollama library manages connections internally