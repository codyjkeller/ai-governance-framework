# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Full OpenAI chat format.** Every field a client sends (`max_tokens`, `tools`, `response_format`, list-style content, the `developer` role and so on) is passed through unchanged. Tested with the official OpenAI client library.
- **The whole request and reply are scanned**, not just message text: content parts, tool-call arguments, tool results, tool definitions and any other field. IDs the API matches exactly are never rewritten.
- **Images, audio and files are refused by default**, since they cannot be scanned. `allow_non_text_content: true` in the policy allows them.
- **Built-in HTTPS.** With `TLS_CERT_FILE` and `TLS_KEY_FILE` the proxy serves TLS 1.2+ itself, AES-GCM suites only, and rejects plain HTTP. `TLS_TERMINATED_UPSTREAM=true` declares that a load balancer provides HTTPS instead. One of the two is required to start. `LLM_API_URL` must be HTTPS.
- **Signed audit log.** With `AUDIT_HMAC_KEY` (required) every entry and the head record carry an HMAC-SHA-256 signature, so the log cannot be rewritten by someone who can only write files.
- **Audit anchoring.** `AUDIT_ANCHOR_URL` receives the head record after every write. `/admin/audit/verify?anchor_entries=&anchor_hash=` checks any stored anchor against the log, which proves whether entries were removed or an older log was put back.
- **Control mapping** for NIST SP 800-53 Rev. 5, SOC 2, HIPAA, CJIS v6.1 and GovRAMP in `docs/COMPLIANCE_MAPPING.md`.
- **More secrets are caught:** GitHub, Slack, Google, Stripe and OpenAI/Anthropic-style keys, JWTs, bearer tokens, and private keys with the plain `BEGIN PRIVATE KEY` header.
- **HIPAA and CJIS identifiers:** medical record numbers, dates of birth, FBI numbers, state ID numbers and driver's license numbers, each matched when labelled. SSNs without dashes are caught when labelled, and American Express card numbers are covered.
- **Response rules.** Replies are checked against every pattern, and a new `output_rules` policy section sets the action per pattern. Replies can now be redacted as well as blocked.
- `HOST`, `PORT` and `WORKERS` settings. The Docker image now starts through `ai-gov-server`, so all settings come from the environment.

### Security
- **Every message is scanned.** Previously only the last message was checked, so sensitive data in an earlier turn or in the system prompt was forwarded upstream untouched.
- **The proxy fails closed.** It refuses to start without `PROXY_API_KEYS`, or with a missing or invalid policy file (including a misspelled action such as `BLOK` or a rule name that matches no pattern). It refuses any request whose audit entry cannot be written (HTTP 503). `ALLOW_INSECURE_DEV=true` relaxes the startup checks for local demos.
- **Unknown policy actions block.** An action the scanner does not recognize is treated as BLOCK instead of letting the data through.
- **Audit identity comes from the API key.** Keys are written as `name:key`; the name is recorded as `user_id`. The `user_id` in the request body is unverified and is now stored separately as `client_user_id`.
- **API keys are compared in constant time.**

### Fixed
- **Fewer false alarms.** "vitamin B12" and "room A10" are no longer redacted as diagnosis codes. Card numbers must pass the Luhn check and DEA numbers their check digit, so ordinary 16-digit numbers are left alone. SSN ranges that are never issued are skipped.
- **Jira alerts for suppressed replies were never sent**, for the same reason as blocked requests.
- **The CI security checks could not fail.** Bandit ran with `|| true` and the container scan with exit code 0. Both now fail the build. The Trivy action is pinned to a commit instead of `master`.
- **`.secrets.baseline` was missing**, so the detect-secrets pre-commit hook could not run.
- **The architecture diagram** showed layers that do not exist. It now shows what the code does.
- **A reply containing only a tool call crashed the proxy** (HTTP 500).
- **The proxy added `temperature: 0.7` to every request.** It is now forwarded only when the caller sets it.
- **Streaming requests are refused with a clear message** instead of being silently turned into non-streaming ones.
- **`PROXY_API_KEYS` could not be set from an environment variable.** A comma-separated value stopped the server at startup, so the documented way to turn on authentication did not work.
- **Audit chain with several workers.** Each worker kept its own copy of the last hash, so the shipped four-worker Docker setup produced a chain that failed verification. Writers now take a file lock and read the end of the file on every write.
- **Deleted audit entries are detected.** A head record beside the log stores the entry count and newest hash; verification fails if entries were removed from the end, and the logger refuses to write to a log that does not match its head record.
- **Monitoring mode is log-only.** It no longer rewrites prompts or replaces responses. Entries carry `"enforced": false`.
- **A match on an ALLOW rule no longer reports the prompt as REDACTED.**
- **Rate limits are counted per API key**, not per client IP, and each app instance has its own limiter.
- **Importing `ai_governance.server` no longer builds the app** or requires configuration.
- **Tests no longer call the real OpenAI API.**
- **Jira alerts for blocked requests were never sent.** The alert was queued and then discarded when the request was rejected.

### Changed
- **Test tooling:** pytest 9, to clear a published advisory in pytest 8 that was failing the dependency audit.

### Upgrade notes
- Set `PROXY_API_KEYS`, `AUDIT_HMAC_KEY`, and either the TLS files or `TLS_TERMINATED_UPSTREAM=true` before upgrading, or the proxy will not start.
- Add a `data_rules` entry for each new pattern if you maintain your own policy file. A pattern with no rule is redacted.
- Violation names in replies now follow the pattern name: `LEAKED_API_KEY` is `LEAKED_API_KEY_GENERIC` and `LEAKED_AWS_KEY` is `LEAKED_AWS_ACCESS_KEY`. Update any alert rules that match on them.
- An audit log written by 3.0.0 has no head record. `/admin/audit/verify` reports it as invalid until the proxy writes its next entry, which creates the record.

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
