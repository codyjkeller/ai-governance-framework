"""FastAPI governance proxy server.

This is the main application entrypoint. It:
- Validates configuration at startup and refuses to start if it is unsafe
  (no API keys, or a missing or invalid policy file)
- Authenticates requests via API key header
- Rate limits per API key (per client IP for requests without a valid key)
- Enforces model allowlisting from the YAML policy
- Runs input scanning (Layer 1) and output scanning (Layer 5)
- Logs all decisions to the tamper-evident audit log
- Refuses a request when its audit entry cannot be written
- Supports 'monitoring' mode (log-only: nothing is blocked or altered)
- Fires Jira webhooks for critical violations (async background task)
"""

import fnmatch
import hmac
import logging
import uuid
from typing import Any

import structlog
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from ai_governance.audit.logger import AuditLogger, AuditWriteError
from ai_governance.config import Settings, get_settings
from ai_governance.integrations.jira import notify_jira
from ai_governance.integrations.llm_client import LLMClientError, call_upstream_llm
from ai_governance.models import ChatRequest
from ai_governance.policy.loader import (
    get_allowed_models,
    get_enforcement_mode,
    load_policy,
)
from ai_governance.scanning.input_scanner import InputScanner
from ai_governance.scanning.output_scanner import OutputScanner

# --- Structured logging setup ---
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logger = structlog.get_logger()


class ConfigurationError(Exception):
    """The proxy is configured in a way that is not safe to run."""


def _identify(api_key: str, identities: dict[str, str]) -> str | None:
    """Return the name that belongs to an API key, or None if the key is not valid.

    Every configured key is compared in constant time, so response timing
    does not reveal how close a guess was.
    """
    found: str | None = None
    for known_key, name in identities.items():
        if hmac.compare_digest(api_key.encode("utf-8"), known_key.encode("utf-8")):
            found = name
    return found


def _rate_limit_key(request: Request) -> str:
    """Count requests per API key. Requests without a valid key are counted per client IP.

    Per-IP counting alone does little behind a reverse proxy, where every
    caller arrives from the same address.
    """
    identities: dict[str, str] = getattr(request.app.state, "key_identities", {})
    name = _identify(request.headers.get("X-Governance-API-Key", ""), identities)
    return f"key:{name}" if name else get_remote_address(request)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory.

    Creates and configures the FastAPI app. Using a factory function
    (instead of a module-level global) makes testing possible — tests
    can call create_app() with custom settings.

    Args:
        settings: Optional settings override (used in tests).
                  If None, loads from environment variables.

    Returns:
        Configured FastAPI application.
    """
    if settings is None:
        settings = get_settings()

    # Configure stdlib logging level from settings
    logging.basicConfig(level=getattr(logging, settings.log_level))

    # Refuse to start as an open proxy
    key_identities = settings.api_key_identities()
    if not key_identities and not settings.allow_insecure_dev:
        msg = (
            "PROXY_API_KEYS is not set, so anyone who can reach this proxy could use your LLM account. "
            "Set PROXY_API_KEYS (for example 'billing-app:<long random key>'). "
            "For a local demo only, set ALLOW_INSECURE_DEV=true."
        )
        raise ConfigurationError(msg)
    if settings.allow_insecure_dev:
        logger.warning(
            "insecure_dev_mode",
            detail="ALLOW_INSECURE_DEV is on. Safety checks are relaxed. Do not use with real data.",
        )

    # Load policy. Strict: a missing or invalid policy file stops the proxy
    # instead of quietly falling back to a weaker one.
    policy = load_policy(settings.policy_path, strict=not settings.allow_insecure_dev)
    enforcement_mode = get_enforcement_mode(policy, settings.enforcement_mode)
    allowed_models = get_allowed_models(policy)
    policy_version = policy.get("global_settings", {}).get("policy_version", "unknown")

    # Initialize components
    input_scanner = InputScanner(policy)
    output_scanner = OutputScanner(policy)
    auditor = AuditLogger(settings.audit_log_path)

    # Build app
    app = FastAPI(
        title="AI Governance Proxy",
        version="3.0.0",
        description="Policy-as-Code governance proxy for Enterprise Generative AI.",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    # --- Rate limiter ---
    # One limiter per app. A limiter shared at module level would carry the
    # limits of one app instance over to the next.
    limiter = Limiter(key_func=_rate_limit_key)
    app.state.limiter = limiter

    # Store on app state for dependency injection
    app.state.settings = settings
    app.state.key_identities = key_identities
    app.state.input_scanner = input_scanner
    app.state.output_scanner = output_scanner
    app.state.auditor = auditor
    app.state.policy = policy
    app.state.enforcement_mode = enforcement_mode
    app.state.allowed_models = allowed_models
    app.state.policy_version = policy_version

    # --- Exception handlers ---
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please slow down."},
        )

    @app.exception_handler(AuditWriteError)
    async def audit_failure_handler(request: Request, exc: AuditWriteError) -> JSONResponse:
        # Fail closed: a request that cannot be audited does not go through.
        logger.error("audit_write_failed", detail=str(exc))
        return JSONResponse(
            status_code=503,
            content={"detail": "Request refused: the audit log is unavailable."},
        )

    # --- Health check ---
    @app.get("/health")
    async def health_check() -> dict[str, Any]:
        """Health check endpoint for load balancers and container orchestration."""
        return {
            "status": "healthy",
            "version": "3.0.0",
            "enforcement_mode": enforcement_mode,
            "policy_version": policy_version,
            "insecure_dev_mode": settings.allow_insecure_dev,
        }

    # --- Audit log verification ---
    @app.get("/admin/audit/verify")
    async def verify_audit_log(request: Request) -> dict[str, Any]:
        """Verify the integrity of the audit log chain.

        Requires authentication (same API key header as the main endpoint).
        """
        _authenticate(request, key_identities)
        is_valid, count = auditor.verify_chain()
        return {
            "chain_valid": is_valid,
            "entries_verified": count,
        }

    # --- Main proxy endpoint ---
    @app.post("/v1/chat/completions")
    @limiter.limit(lambda: f"{settings.rate_limit}/minute" if settings.rate_limit > 0 else "9999/minute")
    async def proxy_chat_completion(
        request: Request,
        chat_request: ChatRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, Any]:
        """Governance-proxied chat completion.

        1. Authenticate the request
        2. Validate the requested model against the allowlist
        3. Scan every message in the conversation (Layer 1)
        4. Forward to upstream LLM
        5. Scan the output (Layer 5)
        6. Return the safe response
        """
        # The audit log records who the API key belongs to. The user_id in the
        # request body is whatever the caller typed, so it is kept separately.
        user_id = _authenticate(request, key_identities)

        transaction_id = str(uuid.uuid4())
        client_user_id = chat_request.user_id if chat_request.user_id != "anonymous" else None
        is_monitoring = enforcement_mode == "monitoring"

        def audit(event_type: str, status: str, details: str | list[Any]) -> None:
            auditor.log_event(
                event_type=event_type,
                transaction_id=transaction_id,
                status=status,
                details=details,
                user_id=user_id,
                policy_version=policy_version,
                enforced=not is_monitoring,
                client_user_id=client_user_id,
            )

        # --- Model allowlist check ---
        if allowed_models and not _model_is_allowed(chat_request.model, allowed_models):
            audit("MODEL_DENIED", "BLOCKED", f"Model '{chat_request.model}' not in allowlist: {allowed_models}")
            if not is_monitoring:
                raise HTTPException(
                    status_code=403,
                    detail=f"Model '{chat_request.model}' is not approved for use. "
                    f"Allowed model families: {', '.join(allowed_models)}",
                )

        # --- Layer 1: Input scan ---
        # Every message is scanned, not only the newest one. Sensitive data in an
        # earlier turn or in the system prompt is sent upstream just the same.
        input_violations: list[dict[str, Any]] = []
        input_blocked = False
        input_redacted = False
        for message in chat_request.messages:
            message_result = input_scanner.scan(message.content)
            input_violations.extend(message_result.violations)
            if message_result.status == "BLOCKED":
                input_blocked = True
            elif message_result.status == "REDACTED" and message_result.text is not None:
                input_redacted = True
                # Monitoring mode is log-only: the prompt is forwarded unchanged.
                if not is_monitoring:
                    message.content = message_result.text
        input_status = "BLOCKED" if input_blocked else "REDACTED" if input_redacted else "CLEAN"

        audit("INPUT_SCAN", input_status, [v["type"] for v in input_violations] if input_violations else "Clean")

        if input_blocked:
            violation_types = ", ".join(v["type"] for v in input_violations)
            background_tasks.add_task(
                notify_jira,
                settings.jira_webhook,
                transaction_id,
                user_id,
                violation_types,
            )
            if not is_monitoring:
                raise HTTPException(
                    status_code=403,
                    detail="Request blocked by AI Acceptable Use Policy.",
                )

        # --- Layer 2: Upstream LLM call ---
        try:
            upstream_response = await call_upstream_llm(
                url=settings.llm_api_url,
                api_key=settings.llm_api_key,
                request_payload=chat_request.to_upstream_dict(),
            )
        except LLMClientError as e:
            logger.error("upstream_llm_error", detail=e.internal_detail, transaction_id=transaction_id)
            raise HTTPException(status_code=502, detail=e.user_message) from e

        raw_response = upstream_response["choices"][0]["message"]["content"]

        # --- Layer 5: Output scan ---
        output_result = output_scanner.scan(raw_response)

        if output_result.status == "BLOCKED":
            audit("OUTPUT_SCAN", "BLOCKED", [v["type"] for v in output_result.violations])
            background_tasks.add_task(
                notify_jira,
                settings.jira_webhook,
                transaction_id,
                user_id,
                "Data leakage detected in LLM response",
            )
            if not is_monitoring:
                raise HTTPException(
                    status_code=502,
                    detail="Response suppressed due to Data Leakage Policy.",
                )

        # --- Success ---
        audit("TRANSACTION_COMPLETE", "SUCCESS", "Request fulfilled")

        # A blocked response never reaches this point in blocking mode. In
        # monitoring mode the response is returned exactly as the model sent it.
        return upstream_response

    return app


def _authenticate(request: Request, identities: dict[str, str]) -> str:
    """Validate the API key from the request header and return who it belongs to.

    If no keys are configured the proxy only starts with ALLOW_INSECURE_DEV=true,
    and every caller is recorded as 'unauthenticated'.

    Args:
        request: The incoming HTTP request.
        identities: API keys mapped to the name recorded in the audit log.

    Returns:
        The name that belongs to the caller's API key.

    Raises:
        HTTPException: 401 if the API key is missing or invalid.
    """
    if not identities:
        return "unauthenticated"  # Only reachable in insecure dev mode

    name = _identify(request.headers.get("X-Governance-API-Key", ""), identities)
    if name is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-Governance-API-Key header.",
        )
    return name


def _model_is_allowed(model: str, allowed_patterns: list[str]) -> bool:
    """Check if the requested model matches any allowed pattern.

    Uses fnmatch for glob-style matching (e.g., 'gpt-4*' matches 'gpt-4-turbo').

    Args:
        model: The model string from the request.
        allowed_patterns: Glob patterns from the policy (e.g., ['gpt-4*', 'claude-3*']).

    Returns:
        True if the model matches at least one allowed pattern.
    """
    return any(fnmatch.fnmatch(model, pattern) for pattern in allowed_patterns)


# --- Module-level app for uvicorn ---
# `uvicorn ai_governance.server:app` will use this.
# Tests use create_app() directly with custom settings.
#
# The app is built the first time it is asked for, not when this module is
# imported, so importing the module never fails on missing configuration.
_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main() -> None:
    """CLI entrypoint for `ai-gov-server` console script."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "ai_governance.server:app",
        host="0.0.0.0",  # noqa: S104 - Intentional: server must bind to all interfaces
        port=8000,
        log_level=settings.log_level.lower(),
        reload=False,
    )
