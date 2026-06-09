"""Standalone JSON extraction utility for LLM responses.

Extracted from OllamaClient.extract_json() so non-LLM call sites can
use it without instantiating an OllamaClient.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


def extract_json_from_response(text: str) -> dict | list | None:
    """Extract JSON from an LLM response.

    Tries (in order):
    1. Direct ``json.loads`` of the trimmed text
    2. Markdown fenced code block (```json ... ```)
    3. Bracket-matching for top-level JSON object ``{ ... }``
    4. Bracket-matching for top-level JSON array ``[ ... ]``

    Returns the parsed object, or ``None`` on failure.
    """
    if not text:
        return None
    text = text.strip()

    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Markdown fence
    match = _JSON_BLOCK_RE.search(text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 3. Object boundaries
    obj = _scan_bracketed(text, "{", "}")
    if obj is not None:
        return obj

    # 4. Array boundaries
    arr = _scan_bracketed(text, "[", "]")
    if arr is not None:
        return arr

    logger.warning(
        "Failed to extract JSON from LLM response (first 200 chars): %s",
        text[:200],
    )
    return None


def _scan_bracketed(text: str, open_ch: str, close_ch: str) -> Any | None:
    """Find a balanced ``open_ch`` ... ``close_ch`` region and parse it as JSON."""
    start = text.find(open_ch)
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None
