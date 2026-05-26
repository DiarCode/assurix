"""Async Ollama client wrapper with retry and fallback."""

import asyncio
import json
import logging
import re
from typing import Any

import ollama as _ollama

from src.core.config import get_settings
from src.core.exceptions import LLMError
from src.llm.router import select_model, select_temperature

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


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

    async def _client(self) -> _ollama.AsyncClient:
        return _ollama.AsyncClient(**self._kwargs)

    async def _call_with_retry(self, call_fn, model_name: str) -> Any:
        """Execute an LLM call with retries and model fallback on failure."""
        models_to_try = [model_name]
        if model_name == self._reasoning_model:
            models_to_try.append(self._fast_model)
        elif model_name == self._fast_model:
            models_to_try.append(self._reasoning_model)

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
            response = await client.generate(
                model=m,
                prompt=prompt,
                options={"temperature": temp, "num_predict": max_tokens},
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
            response = await client.chat(
                model=m,
                messages=messages,
                options={"temperature": temp, "num_predict": max_tokens},
            )
            return response.message.content

        return await self._call_with_retry(_call, model_name)

    @staticmethod
    def extract_json(text: str) -> dict | list | None:
        """Extract JSON from LLM response, handling markdown fences and partial JSON."""
        text = text.strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code blocks
        match = _JSON_BLOCK_RE.search(text)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try finding JSON object boundaries with bracket matching
        start = text.find("{")
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            break

        # Try array boundaries
        arr_start = text.find("[")
        if arr_start >= 0:
            depth = 0
            for i in range(arr_start, len(text)):
                if text[i] == "[":
                    depth += 1
                elif text[i] == "]":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[arr_start:i + 1])
                        except json.JSONDecodeError:
                            break

        logger.warning("Failed to extract JSON from LLM response (first 200 chars): %s", text[:200])
        return None

    async def close(self) -> None:
        pass  # ollama library manages connections internally