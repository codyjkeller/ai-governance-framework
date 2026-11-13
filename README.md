# Enterprise AI Governance Framework

**Policy-as-Code governance proxy for securely adopting Enterprise Generative AI (LLMs) in regulated environments (CJIS, HIPAA).**

![Status](https://img.shields.io/badge/Status-Active-success.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Compliance](https://img.shields.io/badge/Compliance-HIPAA%20%7C%20NIST-blue)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Overview

As enterprises adopt Generative AI, they face the risk of **Data Leakage** (sending PII/secrets to LLM providers) and **Shadow AI** (using unapproved models).

This framework acts as a **Governance Proxy** a FastAPI middleware layer that sits between your users and the LLM APIs. It inspects every prompt in real-time to sanitize sensitive data before it leaves your network, enforces model allowlisting, and maintains a tamper-evident audit trail for GRC compliance.

## Features

- **Multi-Domain Scanning:** Regex-based detection for PII, Medical Data (HIPAA), and DevOps Secrets (AWS Keys, private keys, API tokens). Every message in the conversation is scanned, including earlier turns and the system prompt.
- **Real-Time API Proxy:** Drop-in replacement for OpenAI's `/v1/chat/completions` endpoint with governance enforcement.
- **Policy-as-Code:** DLP rules defined in YAML (`policies/generative_ai_aup.yaml`), updatable by GRC teams without code changes.
- **Model Allowlisting:** Only approved model families (defined in YAML) can be used. Unapproved models are rejected.
- **Authentication & Rate Limiting:** API key auth via `X-Governance-API-Key` header. Each key has a name, and that name is what the audit log records. Rate limiting is per API key.
- **Fails Closed:** The proxy refuses to start without API keys or with a missing or invalid policy file, and refuses any request it cannot write to the audit log.
- **Monitoring Mode:** Deploy in log-only mode to observe violations before switching to enforcement. Nothing is blocked or altered; the audit log records what would have happened.
- **Tamper-Evident Audit Logging:** SHA-256 hash-chained JSONL logs, safe with several server workers. Verification detects changed entries and entries deleted from the end of the log.
- **Smart Remediation:**
  - **BLOCK:** Stops the request entirely for critical data (SSN, secrets).
  - **REDACT:** Masks lower-risk data (emails, IPs) and forwards the sanitized prompt.
- **Jira Integration:** Async webhook notifications for policy violations.

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/codyjkeller/ai-governance-framework.git
cd ai-governance-framework
pip install -e ".[dev,cli]"
```

### 2. Configure Environment

```bash
# Required — your upstream LLM provider key
export LLM_API_KEY="sk-your-openai-key"

# Required — keys your own apps use to call this proxy, written as name:key.
# The name is what appears in the audit log. Generate a key with:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
export PROXY_API_KEYS="billing-app:my-api-key-1,support-bot:my-api-key-2"

# Optional — Jira integration
export JIRA_WEBHOOK="https://automation.atlassian.com/pro/hooks/..."
```

### 3. Run the Server

```bash
make run
# Server at http://0.0.0.0:8000
# Docs at http://0.0.0.0:8000/docs
```

The proxy will not start without `PROXY_API_KEYS`. To try it on your own machine without keys, set `ALLOW_INSECURE_DEV=true`. Never set that where real data is involved: it also lets the proxy start with a missing or broken policy file.

### 4. Send a Test Request

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Governance-API-Key: my-api-key-1" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Summarize this: Email is john@example.com"}]
  }'
```

### 5. Run the CLI Demo

```bash
make demo
```

### 6. Run with Docker

```bash
export LLM_API_KEY="sk-your-key"
export PROXY_API_KEYS="billing-app:my-api-key-1"
make docker-build
make docker-up
```

## Architecture

```
User/App ──POST /v1/chat/completions──▶ [Auth + Rate Limit]
                                              │
                                    ┌─────────▼──────────┐
                                    │  Model Allowlist    │
                                    │  Check              │
                                    └─────────┬──────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │  Layer 1: Input     │
                                    │  Scanner (Regex)    │
                                    └──┬──────┬──────┬───┘
                                       │      │      │
                                    BLOCK  REDACT  CLEAN
                                       │      │      │
                                       │      └──┬───┘
                                       │         │
                                       │  ┌──────▼──────┐
                                       │  │  Upstream    │
                                       │  │  LLM Call    │
                                       │  └──────┬──────┘
                                       │         │
                                       │  ┌──────▼──────┐
                                       │  │  Layer 5:    │
                                       │  │  Output Scan │
                                       │  └──┬──────┬───┘
                                       │     │      │
                                       │  BLOCK   CLEAN
                                       │     │      │
                                       └──┬──┘      │
                                          │         │
                                    [Audit Log]  [Return]
```

Every decision (BLOCK, REDACT, CLEAN) is recorded in the tamper-evident audit log.

## Configuration Reference

| Environment Variable | Required | Default | Description |
|---|---|---|---|
| `LLM_API_KEY` | **Yes** | — | Upstream LLM provider API key |
| `LLM_API_URL` | No | `https://api.openai.com/v1/chat/completions` | Upstream endpoint |
| `PROXY_API_KEYS` | **Yes** | — | Comma-separated keys that callers use, each written as `name:key`. The name is recorded in the audit log. A bare `key` also works and is logged as `key-<hash>`. |
| `ALLOW_INSECURE_DEV` | No | `false` | Local demos only. Lets the proxy start without `PROXY_API_KEYS` and fall back to a built-in policy if the policy file is missing or invalid. Shown on `/health`. |
| `JIRA_WEBHOOK` | No | *(empty = disabled)* | Jira automation webhook URL |
| `ENFORCEMENT_MODE` | No | *(uses YAML value)* | Override: `blocking` or `monitoring` |
| `RATE_LIMIT` | No | `60` | Max requests/minute per API key (0 = disabled). Counted separately in each server worker. |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `POLICY_PATH` | No | `policies/generative_ai_aup.yaml` | Path to policy file |

## Project Structure

```
ai-governance-framework/
├── src/ai_governance/        # Application package
│   ├── config.py             # Centralized settings (pydantic-settings)
│   ├── models.py             # Request/response Pydantic models
│   ├── server.py             # FastAPI application
│   ├── scanning/             # Input + Output scanners
│   │   ├── base.py           # Abstract scanner interface
│   │   ├── patterns.py       # Regex pattern registry
│   │   ├── input_scanner.py  # Layer 1: Prompt scanner
│   │   └── output_scanner.py # Layer 5: Response scanner
│   ├── policy/loader.py      # YAML policy loader
│   ├── audit/logger.py       # Hash-chained audit logger
│   ├── integrations/         # Jira, LLM client
│   └── cli/demo.py           # Rich CLI demo (optional)
├── tests/                    # Test suite
├── policies/                 # YAML policy files
├── docker/                   # Dockerfile + docker-compose
├── .github/workflows/        # CI pipeline
├── pyproject.toml            # Package config + all tool settings
└── Makefile                  # Dev shortcuts
```

## Development

```bash
# Setup
make dev

# Lint + type check
make lint

# Run tests
make test

# Security scan
make security

# Auto-format
make format
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development guidelines.

## Known Limitations

- **Regex-only detection.** The scanner will miss encoded, obfuscated, or context-dependent sensitive data. See `scanning/patterns.py` for per-pattern false-positive/false-negative documentation. NER model integration (e.g., Presidio) is planned.
- **No TLS built in.** Deploy behind a reverse proxy (nginx, Traefik, Envoy) for TLS termination in production.
- **Audit logs are tamper-evident, not immutable.** Hash chaining detects modification after the fact, and a head record beside the log detects entries deleted from the end. Someone able to rewrite both files can still hide a deletion. For true immutability, ship logs to S3 with Object Lock or a SIEM.
- **The `user_id` field in a request is not verified.** The audit log records the owner of the API key as `user_id` and stores the caller-supplied value separately as `client_user_id`.
- **Rate limits are per worker.** With four workers, a key can make up to four times `RATE_LIMIT` requests per minute. Use a shared store or your gateway's rate limiting if you need an exact limit.
- **Not yet a full drop-in for the OpenAI API.** Only `model`, `messages` and `temperature` are forwarded. Tools, streaming and list-style message content are not supported yet.
- **Single upstream provider format.** Currently supports OpenAI-compatible APIs. Azure OpenAI and other providers require URL/auth format changes.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

[MIT](LICENSE)

**Disclaimer:** This tool does not guarantee regulatory compliance. It is one layer in a defense-in-depth strategy. Consult your compliance team before deploying in regulated environments.
