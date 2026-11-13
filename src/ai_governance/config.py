"""Centralized application configuration.

All settings are loaded from environment variables and validated at startup.
If a required variable is missing or invalid, the application refuses to start.
"""

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode


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
            Write each one as name:key (for example "billing-app:3f9c...") so the
            audit log records who made each request.
        ALLOW_INSECURE_DEV: Set to true to run without the safety checks that
            stop a misconfigured proxy from starting. Local demos only.
        TLS_CERT_FILE / TLS_KEY_FILE: Certificate and private key. When set,
            the proxy serves HTTPS itself (TLS 1.2 or newer).
        TLS_TERMINATED_UPSTREAM: Set to true if a load balancer or ingress in
            front of the proxy provides HTTPS instead.
        AUDIT_HMAC_KEY: Secret used to sign every audit entry (32+ characters).
        AUDIT_ANCHOR_URL: HTTPS endpoint that receives a copy of the audit
            log's head record after every write.
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
    # NoDecode: read the env var as plain text. Without it pydantic-settings tries
    # to parse the value as JSON first and "key1,key2" stops the app at startup.
    proxy_api_keys: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated list of valid API keys for authenticating to this proxy. "
        "Each entry is either 'name:key' or just 'key'.",
    )

    # --- Transport security ---
    tls_cert_file: Path | None = Field(
        default=None,
        description="Path to the TLS certificate (PEM). With TLS_KEY_FILE, makes the proxy serve HTTPS itself.",
    )
    tls_key_file: Path | None = Field(
        default=None,
        description="Path to the TLS private key (PEM).",
    )
    tls_terminated_upstream: bool = Field(
        default=False,
        description="Set to true when a load balancer or ingress in front of the proxy provides HTTPS. "
        "The proxy then accepts plain HTTP from it. Keep that hop on a private network.",
    )

    # --- Server ---
    host: str = Field(default="0.0.0.0", description="Address to listen on.")  # noqa: S104 - container default
    port: int = Field(default=8000, ge=1, le=65535, description="Port to listen on.")
    workers: int = Field(default=1, ge=1, le=64, description="Number of server worker processes.")

    # --- Audit integrity ---
    audit_hmac_key: str = Field(
        default="",
        description="Secret used to sign audit entries so they cannot be forged or rewritten. "
        "At least 32 characters. Keep it in your secrets manager, never beside the log.",
    )
    audit_anchor_url: str = Field(
        default="",
        description="HTTPS endpoint that receives the audit log's head record after every write. "
        "A copy stored off this machine is what proves later that entries were removed.",
    )

    # --- Safety override ---
    allow_insecure_dev: bool = Field(
        default=False,
        description="Local demos only. When true the proxy starts without API keys and "
        "falls back to the built-in policy if the policy file is missing or invalid.",
    )

    @field_validator("llm_api_key")
    @classmethod
    def reject_placeholder_key(cls, v: str) -> str:
        """Prevent the application from starting with a placeholder API key."""
        placeholders = {"sk-proj-...", "sk-...", "your-key-here", "CHANGE_ME", ""}
        if v.strip() in placeholders:
            msg = "LLM_API_KEY is set to a placeholder value. Set a real API key in your environment variables."
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

    @field_validator("tls_cert_file", "tls_key_file", mode="before")
    @classmethod
    def empty_path_is_unset(cls, v: object) -> object:
        """An empty env var (TLS_CERT_FILE=) means 'not set', not 'the current folder'."""
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("llm_api_url")
    @classmethod
    def validate_llm_api_url(cls, v: str) -> str:
        """Prompts must not travel to the provider in clear text."""
        local = ("http://127.0.0.1", "http://localhost")
        if not v.startswith("https://") and not v.startswith(local):
            msg = "LLM_API_URL must start with https://"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_tls_files(self) -> "Settings":
        """A certificate without its key (or the reverse) cannot serve HTTPS."""
        if (self.tls_cert_file is None) != (self.tls_key_file is None):
            msg = "Set both TLS_CERT_FILE and TLS_KEY_FILE, or neither."
            raise ValueError(msg)
        for path in (self.tls_cert_file, self.tls_key_file):
            if path is not None and not path.is_file():
                msg = f"TLS file not found: {path}"
                raise ValueError(msg)
        return self

    @property
    def serves_tls(self) -> bool:
        """True when the proxy itself terminates TLS."""
        return self.tls_cert_file is not None and self.tls_key_file is not None

    @field_validator("audit_hmac_key")
    @classmethod
    def validate_audit_hmac_key(cls, v: str) -> str:
        """A short signing key can be guessed, which defeats the signatures."""
        if v and len(v) < 32:
            msg = "AUDIT_HMAC_KEY must be at least 32 characters."
            raise ValueError(msg)
        return v

    @field_validator("audit_anchor_url")
    @classmethod
    def validate_audit_anchor_url(cls, v: str) -> str:
        """The head record must not travel in clear text."""
        local = ("http://127.0.0.1", "http://localhost")
        if v and not v.startswith("https://") and not v.startswith(local):
            msg = "AUDIT_ANCHOR_URL must start with https://"
            raise ValueError(msg)
        return v

    def api_key_identities(self) -> dict[str, str]:
        """Map each configured API key to the name recorded in the audit log.

        'billing-app:3f9c...' gives the key '3f9c...' the name 'billing-app'.
        A bare key gets a name derived from its hash ('key-1a2b3c4d'), so
        the key itself is never written to a log.
        """
        identities: dict[str, str] = {}
        for entry in self.proxy_api_keys:
            name, separator, key = entry.partition(":")
            if separator and name.strip() and key.strip():
                identities[key.strip()] = name.strip()
            else:
                identities[entry] = "key-" + hashlib.sha256(entry.encode("utf-8")).hexdigest()[:8]
        return identities


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings (singleton).

    Call this instead of constructing Settings() directly so
    the configuration is loaded and validated exactly once.
    """
    return Settings()  # type: ignore[call-arg]  # llm_api_key loaded from env var at runtime
