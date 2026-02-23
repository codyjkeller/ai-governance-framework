# Enterprise AI Governance Framework

**Policy-as-Code governance proxy for securely adopting Enterprise Generative AI (LLMs) in regulated environments (CJIS, HIPAA).**

![Status](https://img.shields.io/badge/Status-Active-success.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Compliance](https://img.shields.io/badge/Compliance-HIPAA%20%7C%20NIST-blue)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Overview

As enterprises adopt Generative AI, they face the risk of **Data Leakage** (sending PII/secrets to LLM providers) and **Shadow AI** (using unapproved models).

This framework acts as a **Governance Proxy** — a FastAPI middleware layer that sits between your users and the LLM APIs. It inspects every prompt in real-time to sanitize sensitive data before it leaves your network, enforces model allowlisting, and maintains a tamper-evident audit trail for GRC compliance.

## Features

- **Multi-Domain Scanning:** Regex-based detection for PII, Medical Data (HIPAA), and DevOps Secrets (AWS Keys, private keys, API tokens).
- **Real-Time API Proxy:** Drop-in replacement for OpenAI's `/v1/chat/completions` endpoint with governance enforcement.
- **Policy-as-Code:** DLP rules defined in YAML (`policies/generative_ai_aup.yaml`), updatable by GRC teams without code changes.
- **Model Allowlisting:** Only approved model families (defined in YAML) can be used. Unapproved models are rejected.
- **Authentication & Rate Limiting:** API key auth via `X-Governance-API-Key` header. Per-client rate limiting.
- **Monitoring Mode:** Deploy in log-only mode to observe violations before switching to enforcement.
- **Tamper-Evident Audit Logging:** SHA-256 hash-chained JSONL logs. Built-in chain verification endpoint.
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
# Required
export LLM_API_KEY="sk-your-openai-key"

# Optional — enable proxy authentication
export PROXY_API_KEYS="my-api-key-1,my-api-key-2"

# Optional — Jira integration
export JIRA_WEBHOOK="https://automation.atlassian.com/pro/hooks/..."
```

### 3. Run the Server

```bash
make run
# Server at http://0.0.0.0:8000
# Docs at http://0.0.0.0:8000/docs
```

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
| `PROXY_API_KEYS` | No | *(empty = auth disabled)* | Comma-separated API keys for proxy authentication |
| `JIRA_WEBHOOK` | No | *(empty = disabled)* | Jira automation webhook URL |
| `ENFORCEMENT_MODE` | No | *(uses YAML value)* | Override: `blocking` or `monitoring` |
| `RATE_LIMIT` | No | `60` | Max requests/minute per client IP (0 = disabled) |
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
- **Audit logs are tamper-evident, not immutable.** Hash chaining detects modification after the fact. For true immutability, ship logs to S3 with Object Lock or a SIEM.
- **Single upstream provider format.** Currently supports OpenAI-compatible APIs. Azure OpenAI and other providers require URL/auth format changes.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

[MIT](LICENSE)

**Disclaimer:** This tool does not guarantee regulatory compliance. It is one layer in a defense-in-depth strategy. Consult your compliance team before deploying in regulated environments.
