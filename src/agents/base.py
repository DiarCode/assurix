"""BaseAgent abstract class for all Assurix agents."""

from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession


class BaseAgent(ABC):
    """Abstract base for all security validation agents."""

    name: str = "base_agent"

    @abstractmethod
    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        """Execute the agent's task.

        Args:
            payload: Arbitrary job payload from the orchestrator.
            session: Active database session for persistence.

        Returns:
            A dict with at minimum {"findings": [...], "artifacts": [...]}.
        """
        ...
