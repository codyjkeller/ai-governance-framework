"""FastAPI governance proxy server.

This is the main application entrypoint. It:
- Validates configuration at startup (fails fast if misconfigured)
- Authenticates requests via API key header
- Rate limits per client IP
- Enforces model allowlisting from the YAML policy
- Runs input scanning (Layer 1) and output scanning (Layer 5)
- Logs all decisions to the tamper-evident audit log
- Supports 'monitoring' mode (log-only, no blocking)
- Fires Jira webhooks for critical violations (async background task)
"""

import fnmatch
import logging
import uuid

import structlog
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from ai_governance.audit.logger import AuditLogger
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


# --- Rate limiter ---
limiter = Limiter(key_func=get_remote_address)


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

    # Load policy
    policy = load_policy(settings.policy_path)
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
    app.state.limiter = limiter

    # Store on app state for dependency injection
    app.state.settings = settings
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

    # --- Health check ---
    @app.get("/health")
    async def health_check() -> dict:
        """Health check endpoint for load balancers and container orchestration."""
        return {
            "status": "healthy",
            "version": "3.0.0",
            "enforcement_mode": enforcement_mode,
            "policy_version": policy_version,
        }

    # --- Audit log verification ---
    @app.get("/admin/audit/verify")
    async def verify_audit_log(request: Request) -> dict:
        """Verify the integrity of the audit log chain.

        Requires authentication (same API key header as the main endpoint).
        """
        _authenticate(request, settings)
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
    ) -> dict:
        """Governance-proxied chat completion.

        1. Authenticate the request
        2. Validate the requested model against the allowlist
        3. Scan the input prompt (Layer 1)
        4. Forward to upstream LLM
        5. Scan the output (Layer 5)
        6. Return the safe response
        """
        _authenticate(request, settings)

        transaction_id = str(uuid.uuid4())
        user_id = chat_request.user_id
        is_monitoring = enforcement_mode == "monitoring"

        # --- Model allowlist check ---
        if allowed_models and not _model_is_allowed(chat_request.model, allowed_models):
            auditor.log_event(
                event_type="MODEL_DENIED",
                transaction_id=transaction_id,
                status="BLOCKED",
                details=f"Model '{chat_request.model}' not in allowlist: {allowed_models}",
                user_id=user_id,
                policy_version=policy_version,
            )
            if not is_monitoring:
                raise HTTPException(
                    status_code=403,
                    detail=f"Model '{chat_request.model}' is not approved for use. "
                    f"Allowed model families: {', '.join(allowed_models)}",
                )

        # --- Layer 1: Input scan ---
        user_prompt = chat_request.messages[-1].content
        input_result = input_scanner.scan(user_prompt)

        auditor.log_event(
            event_type="INPUT_SCAN",
            transaction_id=transaction_id,
            status=input_result.status,
            details=[v["type"] for v in input_result.violations] if input_result.violations else "Clean",
            user_id=user_id,
            policy_version=policy_version,
        )

        if input_result.status == "BLOCKED":
            violation_types = ", ".join(v["type"] for v in input_result.violations)
            background_tasks.add_task(
                notify_jira, settings.jira_webhook, transaction_id, user_id, violation_types,
            )
            if not is_monitoring:
                raise HTTPException(
                    status_code=403,
                    detail="Request blocked by AI Acceptable Use Policy.",
                )

        # Apply redactions to the request
        if input_result.status == "REDACTED" and input_result.text is not None:
            chat_request.messages[-1].content = input_result.text

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
            auditor.log_event(
                event_type="OUTPUT_SCAN",
                transaction_id=transaction_id,
                status="BLOCKED",
                details=[v["type"] for v in output_result.violations],
                user_id=user_id,
                policy_version=policy_version,
            )
            background_tasks.add_task(
                notify_jira, settings.jira_webhook, transaction_id, user_id,
                "Data leakage detected in LLM response",
            )
            if not is_monitoring:
                raise HTTPException(
                    status_code=502,
                    detail="Response suppressed due to Data Leakage Policy.",
                )

        # --- Success ---
        auditor.log_event(
            event_type="TRANSACTION_COMPLETE",
            transaction_id=transaction_id,
            status="SUCCESS",
            details="Request fulfilled",
            user_id=user_id,
            policy_version=policy_version,
        )

        # Return the (possibly redacted) response
        if output_result.text is not None:
            upstream_response["choices"][0]["message"]["content"] = output_result.text
        return upstream_response

    return app


def _authenticate(request: Request, settings: Settings) -> None:
    """Validate the API key from the request header.

    If no proxy_api_keys are configured, authentication is disabled
    (open access). This allows development use without keys while
    requiring them in production.

    Args:
        request: The incoming HTTP request.
        settings: Application settings.

    Raises:
        HTTPException: 401 if the API key is missing or invalid.
    """
    if not settings.proxy_api_keys:
        return  # Auth disabled — no keys configured

    api_key = request.headers.get("X-Governance-API-Key", "")
    if api_key not in settings.proxy_api_keys:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-Governance-API-Key header.",
        )


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
app = create_app()


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
