"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/assurix.db",
        description="SQLite async connection string (default: project-relative ./data/assurix.db)",
    )
    database_path_override: str | None = Field(
        default=None,
        alias="ASSURIX_DATABASE_PATH",
        description=(
            "Override path for the SQLite database file. Takes precedence over "
            "database_url when set. Useful for read-only deployments."
        ),
    )
    read_only_fallback: bool = Field(
        default=True,
        description=(
            "If the configured database path is read-only/unwritable, fall back to "
            "tempfile.gettempdir()/assurix.db and log a TECHNIQUE MEMORY WILL NOT "
            "PERSIST warning."
        ),
    )
    strict_finding_gate: bool = Field(
        default=True,
        description=(
            "When True, apply the strict finding gate at report time: drop or "
            "downgrade findings missing PoC, request/response excerpt, or "
            "confidence < 0.30. When False, preserve the legacy 'DO NOT downgrade' "
            "behavior for backwards compatibility."
        ),
    )

    # Ollama
    ollama_host: str = Field(
        default="https://ollama.com",
        description="Ollama server base URL (cloud or local)",
    )
    ollama_api_key: str = Field(
        default="",
        description="Ollama cloud API key (empty = use local Ollama)",
    )
    # Single-model architecture: deepseek-v4-pro for ALL tasks via Ollama.
    ollama_fast_model: str = Field(
        default="deepseek-v4-pro",
        description="Default model for all task types (single-model architecture)",
    )
    ollama_reasoning_model: str = Field(
        default="deepseek-v4-pro",
        description="Default model for reasoning tasks (single-model architecture)",
    )
    ollama_exploitation_model: str = Field(
        default="deepseek-v4-pro",
        description="Default model for exploitation tasks (single-model architecture)",
    )
    ollama_embedding_model: str = Field(
        default="nomic-embed-text",
        description="Embedding model for finding deduplication (always local)",
    )
    ollama_num_ctx: int = Field(
        default=8192,
        ge=2048,
        le=128000,
        description="Context window size for Ollama reasoning/exploitation calls",
    )

    # Frontier LLM APIs (optional — fallback to Ollama if unset)
    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key for Claude Sonnet/Opus access",
    )
    openai_api_key: str = Field(
        default="",
        description="OpenAI API key for o3/gpt-4o access",
    )
    frontier_reasoning_model: str = Field(
        default="claude-sonnet-4-6",
        description="Frontier model for deep reasoning tasks",
    )
    frontier_exploitation_model: str = Field(
        default="claude-opus-4-6",
        description="Frontier model for exploit construction",
    )

    # Browser (Playwright — scripted)
    max_browser_contexts: int = Field(
        default=2,
        ge=1,
        le=16,
        description="Maximum concurrent Playwright browser contexts",
    )
    playwright_headless: bool = Field(
        default=True,
        description="Run Playwright in headless mode",
    )

    # Browser-use (AI-driven)
    browser_use_headless: bool = Field(
        default=True,
        description="Run browser-use agent in headless mode",
    )
    browser_use_max_steps: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum steps per browser-use agent run",
    )
    browser_use_step_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=600,
        description=(
            "Per-step budget for browser-use agent.run(). The total wall-clock "
            "ceiling is `browser_use_max_steps * browser_use_step_timeout_seconds + 60s`. "
            "Prevents indefinite hangs when the LLM schema validator retries forever."
        ),
    )
    research_loop_max_total_seconds: int = Field(
        default=1800,
        ge=60,
        le=7200,
        description=(
            "Cumulative wall-clock budget for the ResearchLoop's investigation phase. "
            "When exceeded, the loop returns whatever findings were collected so the "
            "engine can route to the reporter instead of stalling."
        ),
    )
    hypothesis_orchestrator_cumulative_budget_seconds: float = Field(
        default=900.0,
        ge=30.0,
        le=7200.0,
        description=(
            "Cumulative wall-clock budget for one HypothesisOrchestrator execution. "
            "Each per-tool call's per-call timeout is dynamically derived from the "
            "remaining budget (capped at 180s) so a slow tool call near the end of "
            "the budget cannot exceed the overall ceiling. When the budget is "
            "exhausted, the orchestrator stops dispatching and returns whatever "
            "findings were collected. Replaces the previous hardcoded 180s per-call "
            "timeout that caused the live dj1naq.sytes.net scan to hang on a single "
            "stuck tool invocation (defect 3)."
        ),
    )
    hypothesis_orchestrator_per_call_timeout_seconds: float = Field(
        default=180.0,
        ge=5.0,
        le=600.0,
        description=(
            "Maximum per-tool-call timeout the orchestrator will ever request. "
            "Actual timeout per call is "
            "min(per_call_timeout, remaining_cumulative_budget - 10s). "
            "10s of headroom is reserved so the orchestrator can finalize "
            "its result before the cumulative ceiling is hit."
        ),
    )
    browser_use_keep_alive: bool = Field(
        default=True,
        description="Keep browser session alive between agent runs",
    )
    parallel_agents: int = Field(
        default=3,
        ge=1,
        le=8,
        description="Maximum parallel browser-use sub-agents",
    )

    # Agent Cognitive Compressor
    acc_token_budget: int = Field(
        default=4000,
        ge=1000,
        le=16000,
        description="Token budget for agent context compression",
    )
    acc_max_hypotheses: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum active hypotheses in ACC",
    )

    # Suspicious Points
    sp_confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to include a suspicious point",
    )
    sp_max_points: int = Field(
        default=30,
        ge=5,
        le=100,
        description="Maximum suspicious points per investigation",
    )

    # Adversarial Validation
    adversarial_validation: bool = Field(
        default=True,
        description="Enable Red/Blue/Judge adversarial validation of findings",
    )
    adversarial_min_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to trigger adversarial validation",
    )

    # --- Verifier thresholds (plan §3.4.3) ----------------------------
    # The defaults below are the *legacy* hard-coded values; production
    # deployments should run ``ThresholdCalibrator`` against a labeled
    # held-out set and update the values via env vars
    # (``ASSURIX_VALIDATOR_SIMHASH_THRESHOLD`` etc.). The calibrator
    # emits a markdown report that can be checked into
    # ``ops/calibration_reports/``.
    validator_simhash_threshold: int = Field(
        default=10,
        ge=0,
        le=64,
        validation_alias="ASSURIX_VALIDATOR_SIMHASH_THRESHOLD",
        description=(
            "SimHash hamming distance below which two findings are "
            "considered near-duplicates. Default 10 mirrors the "
            "validator's pre-calibration hard-coded value."
        ),
    )
    validator_imagehash_threshold: int = Field(
        default=10,
        ge=0,
        le=64,
        validation_alias="ASSURIX_VALIDATOR_IMAGEHASH_THRESHOLD",
        description=(
            "Perceptual-hash hamming distance below which two "
            "screenshots are considered near-duplicates."
        ),
    )
    reproducer_min_response_size_match: int = Field(
        default=0,
        ge=0,
        validation_alias="ASSURIX_REPRODUCER_MIN_RESPONSE_SIZE_MATCH",
        description=(
            "Minimum response-size delta (bytes) between baseline and "
            "replayed request for a reproducer to accept the finding. "
            "0 = accept any size change."
        ),
    )
    adversary_max_mutation_attempts: int = Field(
        default=3,
        ge=1,
        le=20,
        validation_alias="ASSURIX_ADVERSARY_MAX_MUTATION_ATTEMPTS",
        description=(
            "How many payload mutations the Adversary verifier tries "
            "before declaring 'no break found'."
        ),
    )

    # Safety
    default_rate_rps: float = Field(
        default=10.0,
        ge=0.1,
        description="Default requests per second limit",
    )
    max_iterations_per_scan: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum agent iterations per engagement",
    )
    safe_mode: bool = Field(
        default=True,
        description="Enable safe mode (non-destructive testing only)",
    )
    offensive_mode: bool = Field(
        default=False,
        description=(
            "Enable full offensive mode (reverse shells, data exfiltration, "
            "lateral movement). Requires explicit opt-in via --mode offensive."
        ),
    )

    # Pentester Agent
    pentester_max_iterations: int = Field(
        default=50, ge=1, le=200,
        description="Maximum reasoning-acting loops for pentester agent",
    )
    pentester_parallel_tools: int = Field(
        default=3, ge=1, le=10,
        description="Maximum concurrent tool executions for pentester agent",
    )
    pentester_deep_scan: bool = Field(
        default=True,
        description="Enable deep autonomous testing (port scan, brute force, subdomain enum)",
    )
    pentester_port_scan: bool = Field(
        default=True,
        description="Enable port scanning in pentester agent",
    )
    pentester_brute_force: bool = Field(
        default=True,
        description="Enable brute-force attacks in pentester agent",
    )
    pentester_subdomain_enum: bool = Field(
        default=True,
        description="Enable subdomain enumeration in pentester agent",
    )

    # Storage
    artifacts_dir: Path = Field(
        default=Path("./data/artifacts"),
        description="Directory for evidence artifacts (HAR, screenshots, traces)",
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    )
    env: str = Field(
        default="development",
        pattern=r"^(development|staging|production)$",
    )

    # API Server
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000, ge=1, le=65535)

    @property
    def thresholds(self) -> "Thresholds":
        """Return the current verifier-thresholds as a frozen
        :class:`src.benchmark.calibrate.Thresholds` instance.

        This is the single source of truth for the four knobs tuned
        by ``ThresholdCalibrator``. Mutating the returned object is
        not allowed (frozen dataclass); the calibrator produces a new
        value and operators either update the env vars or set the
        fields on a freshly-constructed ``Settings`` instance.
        """
        # Imported lazily to keep ``Settings`` load-time side-effect-free.
        from src.benchmark.calibrate import Thresholds

        return Thresholds(
            reproducer_min_response_size_match=self.reproducer_min_response_size_match,
            adversary_max_mutation_attempts=self.adversary_max_mutation_attempts,
            validator_simhash_threshold=self.validator_simhash_threshold,
            validator_imagehash_threshold=self.validator_imagehash_threshold,
        )

    @property
    def database_path(self) -> Path:
        """Extract filesystem path from SQLite URL.

        Priority:
            1. ``ASSURIX_DATABASE_PATH`` env override (``database_path_override``)
            2. Path embedded in ``database_url`` (project-relative by default)
        """
        if self.database_path_override:
            return Path(self.database_path_override).expanduser().resolve()

        # Handle both sqlite+aiosqlite:///path and sqlite:///path
        url = self.database_url.replace("sqlite+aiosqlite://", "").replace("sqlite://", "")
        if url.startswith("///"):
            url = url[3:]
        elif url.startswith("/"):
            # Absolute path embedded in URL (e.g. sqlite+aiosqlite:////data/foo)
            url = url.lstrip("/")
        return Path(url).resolve()

    def resolve_writable_database_path(self) -> Path:
        """Return a writable path for the database, falling back to tempdir if needed.

        Honors ``read_only_fallback``: when the configured directory is not
        writable (e.g. read-only deployment), logs a warning and returns
        ``tempfile.gettempdir() / "assurix.db"``. Note: writes to the
        fallback location WILL NOT PERSIST across container restarts.
        """
        import logging
        import tempfile

        logger = logging.getLogger(__name__)
        target = self.database_path

        if not self.read_only_fallback:
            return target

        parent = target.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            # Probe writability with a unique temp file in the target dir.
            probe = parent / f".assurix_write_probe_{target.name}"
            probe.write_text("ok")
            probe.unlink()
            return target
        except (PermissionError, OSError) as exc:
            fallback = Path(tempfile.gettempdir()) / "assurix.db"
            logger.warning(
                "Database path %s is not writable (%s). Falling back to %s. "
                "TECHNIQUE MEMORY WILL NOT PERSIST across restarts.",
                target,
                exc,
                fallback,
            )
            return fallback


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
