# =============================================================================
# Multi-stage Dockerfile for AI Governance Proxy
# =============================================================================
# Stage 1: Build dependencies
# Stage 2: Slim production image with non-root user
# =============================================================================

# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy only what pip needs first (cache-friendly layer ordering)
COPY pyproject.toml .
COPY src/ ./src/

# Install the package and its dependencies into a prefix we can copy later
RUN pip install --no-cache-dir --prefix=/install .

# --- Stage 2: Production ---
FROM python:3.11-slim

# Create a non-root user (CIS Docker Benchmark requirement)
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid appuser --shell /bin/false appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy only the files the application needs at runtime
COPY src/ ./src/
COPY policies/ ./policies/

# Create audit log directory owned by appuser
RUN mkdir -p /app/audit_logs && chown appuser:appuser /app/audit_logs

# Switch to non-root user
USER appuser

# Expose the proxy port
EXPOSE 8000

# Health check - uses the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/health'); r.raise_for_status()" || exit 1

# Run with uvicorn directly (production settings)
# Workers can be overridden via UVICORN_WORKERS env var
ENTRYPOINT ["uvicorn", "ai_governance.server:app", \
    "--host", "0.0.0.0", \
    "--port", "8000", \
    "--workers", "4", \
    "--access-log", \
    "--log-level", "info"]
