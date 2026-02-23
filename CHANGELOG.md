# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-02-20

### Added
- **Authentication:** API key authentication via `X-Governance-API-Key` header. Configurable via `PROXY_API_KEYS` environment variable.
- **Rate limiting:** Per-client-IP rate limiting via `slowapi`. Configurable via `RATE_LIMIT` env var.
- **Model allowlisting enforcement:** The `allowed_model_families` policy is now actively checked. Unapproved models are rejected with HTTP 403.
- **Monitoring mode:** Set `enforcement_mode: monitoring` in the YAML policy (or `ENFORCEMENT_MODE=monitoring` env var) to log violations without blocking. Useful for rollout and testing.
- **Audit log hash chaining:** Each audit log entry includes a SHA-256 hash of the previous entry for tamper detection. Use `AuditLogger.verify_chain()` or the `/admin/audit/verify` endpoint to check integrity.
- **Health check endpoint:** `GET /health` returns proxy status, policy version, and enforcement mode.
- **Structured logging:** All application logging uses `structlog` with JSON output, suitable for log aggregation.
- **Centralized config:** All settings validated at startup via `pydantic-settings`. Placeholder API keys are rejected.
- **Test suite:** Comprehensive tests for scanners, policy loader, audit logger, and server endpoints with >80% coverage target.
- **CI/CD pipeline:** GitHub Actions with lint, test, SAST (Bandit), dependency audit (pip-audit), and container scan (Trivy).
- **Docker improvements:** Multi-stage build, non-root user, health check, `.dockerignore`, resource limits.
- **Documentation:** `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.

### Changed
- **Project structure:** Reorganized from flat files into a proper Python package under `src/ai_governance/`.
- **Scanner architecture:** Input and output scanners now implement a `BaseScanner` interface (Strategy pattern). Rich console output removed from business logic and isolated to `cli/demo.py`.
- **Pattern registry:** Regex patterns extracted into `scanning/patterns.py` with documented false-positive/false-negative notes. IP address pattern now validates octet ranges (0-255). ICD-10 pattern restricts first letter to valid code ranges. DEA number pattern restricts to valid prefix characters.
- **Policy loader:** Single shared loader eliminates duplicated code between input and output scanners. Validates YAML structure and logs warnings for invalid values.
- **Error handling:** Upstream LLM errors no longer leak internal details to the client. Generic user-facing messages with full details logged internally.
- **Request validation:** Pydantic models enforce message structure, role values, content length, and temperature range. Empty message lists and missing user messages are rejected.
- **Upstream serialization:** Internal fields (user_id) are stripped before forwarding to the LLM provider via `ChatRequest.to_upstream_dict()`.

### Removed
- `requirements.txt` (replaced by `pyproject.toml`)
- Hardcoded `"sk-proj-..."` API key placeholder in source code
- Rich dependency from core business logic (now optional, CLI-only)
- Hardcoded mock confidence score in output scanner

### Fixed
- Empty `messages` list no longer causes `IndexError` — validated by Pydantic.
- Filename typo `clli_demo.py` → `cli/demo.py`.

## [2.1.0] - Previous Release

Initial functional implementation with FastAPI proxy, regex scanning, YAML policy, and Jira integration.
