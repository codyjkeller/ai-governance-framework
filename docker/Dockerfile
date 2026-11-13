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

# Apply operating system security updates released since the base image was built,
# and remove the Python packaging tools, which the proxy does not use at run time.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* && \
    pip uninstall -y setuptools wheel

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
# Uses HTTPS when the proxy serves TLS itself. Certificate checking is off for
# this one call because the certificate is issued for the public name, not localhost.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, httpx; s = 'https' if os.getenv('TLS_CERT_FILE') else 'http'; httpx.get(f'{s}://localhost:8000/health', verify=False).raise_for_status()" || exit 1

# Four workers by default. Override with the WORKERS env var.
ENV WORKERS=4

# Started through the app's own entry point so that TLS, port and worker
# settings all come from the environment.
ENTRYPOINT ["ai-gov-server"]
