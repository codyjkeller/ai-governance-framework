"""Centralized application configuration.

All settings are loaded from environment variables and validated at startup.
If a required variable is missing or invalid, the application refuses to start.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Required variables (no defaults - app won't start without them):
        LLM_API_KEY: Your upstream LLM provider API key.

    Optional variables (have safe defaults):
        LLM_API_URL: Upstream LLM endpoint.
        JIRA_WEBHOOK: Jira automation webhook URL (empty = disabled).
        POLICY_PATH: Path to the YAML policy file.
        AUDIT_LOG_PATH: Path to the JSONL audit log file.
        LOG_LEVEL: Logging verbosity (DEBUG, INFO, WARNING, ERROR).
        RATE_LIMIT: Requests per minute per client (0 = disabled).
        ENFORCEMENT_MODE: Override policy enforcement mode (blocking, monitoring).
        PROXY_API_KEYS: Comma-separated list of valid API keys for proxy auth.
    """

    model_config = {"env_prefix": "", "case_sensitive": False}

    # --- Required ---
    llm_api_key: str = Field(
        ...,
        description="Upstream LLM provider API key. Must be set.",
    )

    # --- Upstream LLM ---
    llm_api_url: str = Field(
        default="https://api.openai.com/v1/chat/completions",
        description="Upstream LLM API endpoint URL.",
    )

    # --- Integrations ---
    jira_webhook: str = Field(
        default="",
        description="Jira automation webhook URL. Empty string disables Jira notifications.",
    )

    # --- Policy & Audit ---
    policy_path: Path = Field(
        default=Path("policies/generative_ai_aup.yaml"),
        description="Path to the YAML policy file.",
    )
    audit_log_path: Path = Field(
        default=Path("audit_logs/governance.jsonl"),
        description="Path to the JSONL audit log output.",
    )

    # --- Operational ---
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR).",
    )
    rate_limit: int = Field(
        default=60,
        description="Max requests per minute per client IP. 0 disables rate limiting.",
        ge=0,
    )
    enforcement_mode: str = Field(
        default="",
        description="Override enforcement mode from env var. Empty = use YAML policy value.",
    )

    # --- Proxy Authentication ---
    proxy_api_keys: list[str] = Field(
        default_factory=list,
        description="Comma-separated list of valid API keys for authenticating to this proxy.",
    )

    @field_validator("llm_api_key")
    @classmethod
    def reject_placeholder_key(cls, v: str) -> str:
        """Prevent the application from starting with a placeholder API key."""
        placeholders = {"sk-proj-...", "sk-...", "your-key-here", "CHANGE_ME", ""}
        if v.strip() in placeholders:
            msg = (
                "LLM_API_KEY is set to a placeholder value. "
                "Set a real API key in your environment variables."
            )
            raise ValueError(msg)
        return v.strip()

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            msg = f"LOG_LEVEL must be one of {valid}, got '{v}'"
            raise ValueError(msg)
        return upper

    @field_validator("enforcement_mode")
    @classmethod
    def validate_enforcement_mode(cls, v: str) -> str:
        if v and v not in {"blocking", "monitoring"}:
            msg = f"ENFORCEMENT_MODE must be 'blocking' or 'monitoring', got '{v}'"
            raise ValueError(msg)
        return v

    @field_validator("proxy_api_keys", mode="before")
    @classmethod
    def parse_comma_separated_keys(cls, v: str | list[str]) -> list[str]:
        """Accept comma-separated string from env var or list from code."""
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings (singleton).

    Call this instead of constructing Settings() directly so
    the configuration is loaded and validated exactly once.
    """
    return Settings()
