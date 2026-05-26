"""Policy enforcement engine."""

import asyncio
from datetime import UTC, datetime
from typing import Any

from src.core.config import get_settings
from src.core.exceptions import PolicyBlockedError


class PolicyEngine:
    """Enforces scope, rate, and safety policies."""

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        settings = get_settings()
        self.policy = policy or {}
        self.rate_rps: float = self.policy.get("rate_rps", settings.default_rate_rps)
        self.max_iterations: int = self.policy.get(
            "max_iterations", settings.max_iterations_per_scan
        )
        self.safe_mode: bool = self.policy.get("safe_mode", settings.safe_mode)
        self.allow_destructive: bool = self.policy.get("allow_destructive", False)
        self._last_request_time: float | None = None
        self._rate_lock = asyncio.Lock()

    async def check_rate(self) -> None:
        """Throttle requests to comply with rate_rps."""
        async with self._rate_lock:
            now = datetime.now(UTC).timestamp()
            if self._last_request_time is not None:
                elapsed = now - self._last_request_time
                min_interval = 1.0 / self.rate_rps
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
            self._last_request_time = datetime.now(UTC).timestamp()

    def check_safe_mode(self, action: str) -> None:
        """Block destructive actions when safe_mode is enabled."""
        destructive_patterns = [
            "drop",
            "delete",
            "truncate",
            "rm -rf",
            "exec(",
            "system(",
            "eval(",
            "file_delete",
            "database_destroy",
        ]
        lowered = action.lower()
        if self.safe_mode and any(p in lowered for p in destructive_patterns):
            raise PolicyBlockedError(
                message=f"Action blocked in safe mode: {action}",
                policy="safe_mode",
            )

    def check_iteration_limit(self, current: int) -> None:
        """Raise if iteration count exceeds policy maximum."""
        if current >= self.max_iterations:
            raise PolicyBlockedError(
                message=f"Maximum iterations ({self.max_iterations}) reached.",
                policy="max_iterations",
            )

    def check_destructive_allowed(self, action: str) -> None:
        """Raise if destructive action not explicitly allowed."""
        if not self.allow_destructive:
            raise PolicyBlockedError(
                message=f"Destructive action not allowed: {action}",
                policy="allow_destructive",
            )

    async def before_request(self, action: str) -> None:
        """Run all pre-request policy checks."""
        await self.check_rate()
        self.check_safe_mode(action)
