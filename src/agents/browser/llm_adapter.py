"""Custom ChatOllama for browser-use that strips markdown fences from structured output."""

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from ollama import AsyncClient as OllamaAsyncClient
from ollama import Options
from pydantic import BaseModel

from browser_use.llm.exceptions import ModelProviderError
from browser_use.llm.messages import BaseMessage
from browser_use.llm.ollama.serializer import OllamaMessageSerializer
from browser_use.llm.views import ChatInvokeCompletion

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL)


def _strip_fences(text: str) -> str:
    """Remove markdown code fences wrapping JSON."""
    m = _FENCE_RE.match(text.strip())
    if m:
        return m.group(1).strip()
    return text.strip()


@dataclass
class OllamaChatLLM:
    """ChatOllama for browser-use that handles models wrapping JSON in code fences.

    Extends the native browser-use ChatOllama by stripping markdown fences
    from structured output before validation, which some cloud-hosted models
    wrap around their JSON responses.
    """

    model: str
    host: str | None = None
    timeout: float | None = None
    client_params: dict[str, Any] | None = None
    ollama_options: Mapping[str, Any] | Options | None = None
    _verified_api_keys: bool = field(default=True, init=False)

    @property
    def provider(self) -> str:
        return "ollama"

    @property
    def name(self) -> str:
        return self.model

    @property
    def model_name(self) -> str:
        return self.model

    def _get_client(self) -> OllamaAsyncClient:
        kwargs: dict[str, Any] = {}
        if self.host:
            kwargs["host"] = self.host
        if self.timeout:
            kwargs["timeout"] = self.timeout
        else:
            kwargs["timeout"] = 180.0
        if self.client_params:
            kwargs.update(self.client_params)
        return OllamaAsyncClient(**kwargs)

    async def ainvoke(
        self,
        messages: list[BaseMessage],
        output_format: type[T] | None = None,
        **kwargs: Any,
    ) -> ChatInvokeCompletion:
        ollama_messages = OllamaMessageSerializer.serialize_messages(messages)

        try:
            client = self._get_client()

            if output_format is None:
                response = await client.chat(
                    model=self.model,
                    messages=ollama_messages,
                    options=self.ollama_options,
                )
                return ChatInvokeCompletion(
                    completion=response.message.content or "", usage=None
                )
            else:
                schema = output_format.model_json_schema()
                response = await client.chat(
                    model=self.model,
                    messages=ollama_messages,
                    format=schema,
                    options=self.ollama_options,
                )

                content = response.message.content or ""
                # Strip markdown fences that some models wrap around JSON
                content = _strip_fences(content)

                try:
                    completion = output_format.model_validate_json(content)
                except Exception:
                    data = json.loads(content)
                    completion = output_format.model_validate(data)

                return ChatInvokeCompletion(completion=completion, usage=None)

        except Exception as e:
            raise ModelProviderError(message=str(e), model=self.name) from e