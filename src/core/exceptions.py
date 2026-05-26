"""Custom exceptions for the Assurix platform."""


class AssurixError(Exception):
    """Base exception for all Assurix errors."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or "ASSURIX_ERROR"


class ScopeViolationError(AssurixError):
    """Raised when an agent attempts to interact with an out-of-scope target."""

    def __init__(self, message: str, target: str | None = None) -> None:
        super().__init__(message, code="SCOPE_VIOLATION")
        self.target = target


class PolicyBlockedError(AssurixError):
    """Raised when an action is blocked by a policy rule."""

    def __init__(self, message: str, policy: str | None = None) -> None:
        super().__init__(message, code="POLICY_BLOCKED")
        self.policy = policy


class AgentExecutionError(AssurixError):
    """Raised when an agent fails to execute its task."""

    def __init__(self, message: str, agent_name: str | None = None) -> None:
        super().__init__(message, code="AGENT_EXECUTION_FAILED")
        self.agent_name = agent_name


class LLMError(AssurixError):
    """Raised when the LLM layer encounters an error."""

    def __init__(self, message: str, model: str | None = None) -> None:
        super().__init__(message, code="LLM_ERROR")
        self.model = model


class ValidationError(AssurixError):
    """Raised when a finding fails deterministic validation."""

    def __init__(self, message: str, finding_id: str | None = None) -> None:
        super().__init__(message, code="VALIDATION_FAILED")
        self.finding_id = finding_id


class GraphError(AssurixError):
    """Raised when graph operations fail."""

    def __init__(self, message: str, node_id: str | None = None) -> None:
        super().__init__(message, code="GRAPH_ERROR")
        self.node_id = node_id
