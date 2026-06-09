"""Async frontier LLM client wrapper for Anthropic Claude and OpenAI.

Provides a unified interface over frontier reasoning models with automatic
fallback to Ollama when API keys are unavailable or calls fail.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from src.core.config import get_settings
from src.core.exceptions import LLMError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
MAX_RETRIES = 3


class FrontierClient:
    """Unified client for Anthropic Claude and OpenAI frontier models.

    Falls back to Ollama when frontier APIs are unavailable.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._anthropic_key = settings.anthropic_api_key
        self._openai_key = settings.openai_api_key
        self._reasoning_model = settings.frontier_reasoning_model
        self._exploitation_model = settings.frontier_exploitation_model
        self._http = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        prompt: str,
        task_type: str = "reasoning",
        temperature: float | None = None,
        max_tokens: int = 4096,
    ) -> str:
        """Send a completion request to the best available frontier model."""
        model = self._select_model(task_type)
        temp = temperature if temperature is not None else self._select_temperature(task_type)

        messages = [{"role": "user", "content": prompt}]
        return await self._chat_with_fallback(model, messages, temp, max_tokens)

    async def chat(
        self,
        messages: list[dict[str, str]],
        task_type: str = "reasoning",
        temperature: float | None = None,
        max_tokens: int = 4096,
    ) -> str:
        """Send a chat completion request to the best available frontier model."""
        model = self._select_model(task_type)
        temp = temperature if temperature is not None else self._select_temperature(task_type)
        return await self._chat_with_fallback(model, messages, temp, max_tokens)

    async def close(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _select_model(self, task_type: str) -> str:
        if task_type in ("exploitation", "exploit_chain", "primitive_construction"):
            return self._exploitation_model
        return self._reasoning_model

    @staticmethod
    def _select_temperature(task_type: str) -> float:
        if task_type in ("classification", "extraction", "routing"):
            return 0.1
        if task_type in ("exploitation", "exploit_chain"):
            return 0.8
        return 0.7

    async def _chat_with_fallback(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Try frontier APIs in order, fallback to Ollama on any failure."""
        last_error: Exception | None = None

        # Prefer Anthropic for reasoning/exploitation tasks
        if self._anthropic_key and model.startswith(("claude-", "claude_")):
            for attempt in range(MAX_RETRIES):
                try:
                    return await self._anthropic_chat(model, messages, temperature, max_tokens)
                except Exception as exc:
                    last_error = exc
                    logger.warning("Anthropic call failed (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, exc)
                    if attempt < MAX_RETRIES - 1:
                        continue
                    break

        # Try OpenAI
        if self._openai_key:
            for attempt in range(MAX_RETRIES):
                try:
                    return await self._openai_chat(model, messages, temperature, max_tokens)
                except Exception as exc:
                    last_error = exc
                    logger.warning("OpenAI call failed (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, exc)
                    if attempt < MAX_RETRIES - 1:
                        continue
                    break

        # Fallback to Ollama
        logger.info("Frontier APIs unavailable or failed (%s), falling back to Ollama", last_error)
        return await self._ollama_fallback(model, messages, temperature, max_tokens)

    async def _anthropic_chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        system_msg = ""
        user_assistant_msgs: list[dict[str, str]] = []
        for m in messages:
            if m.get("role") == "system":
                system_msg = m.get("content", "")
            else:
                user_assistant_msgs.append(m)

        headers = {
            "x-api-key": self._anthropic_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_assistant_msgs,
        }
        if system_msg:
            payload["system"] = system_msg

        response = await self._http.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        content = data.get("content", [])
        if content:
            return content[0].get("text", "")
        raise LLMError("Empty response from Anthropic", model=model)

    async def _openai_chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        headers = {
            "Authorization": f"Bearer {self._openai_key}",
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        response = await self._http.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        raise LLMError("Empty response from OpenAI", model=model)

    async def _ollama_fallback(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        from src.llm.client import OllamaClient

        client = OllamaClient()
        try:
            return await client.chat(
                messages=messages,
                task_type="reasoning",
                temperature=temperature,
                max_tokens=max_tokens,
            )
        finally:
            await client.close()


class UnifiedLLMClient:
    """Facade that auto-selects frontier vs Ollama based on task type and config."""

    def __init__(self) -> None:
        self._frontier: FrontierClient | None = None
        self._ollama: Any | None = None

    async def _get_client(self, task_type: str) -> FrontierClient | Any:
        settings = get_settings()
        if task_type in ("exploitation", "exploit_chain", "primitive_construction"):
            if settings.anthropic_api_key or settings.openai_api_key:
                if self._frontier is None:
                    self._frontier = FrontierClient()
                return self._frontier
        # Default to Ollama for everything else or when no frontier keys
        if self._ollama is None:
            from src.llm.client import OllamaClient

            self._ollama = OllamaClient()
        return self._ollama

    async def generate(
        self,
        prompt: str,
        task_type: str = "reasoning",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int = 2048,
    ) -> str:
        client = await self._get_client(task_type)
        if isinstance(client, FrontierClient):
            return await client.generate(prompt, task_type, temperature, max_tokens)
        return await client.generate(prompt, task_type, model, temperature, max_tokens)

    async def chat(
        self,
        messages: list[dict[str, str]],
        task_type: str = "reasoning",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int = 2048,
    ) -> str:
        client = await self._get_client(task_type)
        if isinstance(client, FrontierClient):
            return await client.chat(messages, task_type, temperature, max_tokens)
        return await client.chat(messages, task_type, model, temperature, max_tokens)

    async def close(self) -> None:
        if self._frontier:
            await self._frontier.close()
        if self._ollama:
            await self._ollama.close()
