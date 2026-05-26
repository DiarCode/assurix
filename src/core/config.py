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
        default="sqlite+aiosqlite:///data/assurix.db",
        description="SQLite async connection string",
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
    ollama_fast_model: str = Field(
        default="gemma4:31b",
        description="Lightweight model for fast tasks (classification, extraction)",
    )
    ollama_reasoning_model: str = Field(
        default="deepseek-v4-flash",
        description="Heavy model for reasoning and remediation",
    )
    ollama_embedding_model: str = Field(
        default="nomic-embed-text",
        description="Embedding model for finding deduplication (always local)",
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
    def database_path(self) -> Path:
        """Extract filesystem path from SQLite URL."""
        # Handle both sqlite+aiosqlite:///path and sqlite:///path
        url = self.database_url.replace("sqlite+aiosqlite://", "").replace("sqlite://", "")
        if url.startswith("///"):
            url = url[3:]
        return Path(url).resolve()


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
