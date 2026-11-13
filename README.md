# Enterprise AI Governance Framework

**Policy-as-Code governance proxy for securely adopting Enterprise Generative AI (LLMs) in regulated environments. Its safeguards are mapped to NIST SP 800-53 Rev. 5, SOC 2, HIPAA, CJIS v6.1 and GovRAMP in [docs/COMPLIANCE_MAPPING.md](docs/COMPLIANCE_MAPPING.md).**

![Status](https://img.shields.io/badge/Status-Active-success.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Control mapping](https://img.shields.io/badge/Mapped_to-NIST_800--53_%7C_SOC_2_%7C_HIPAA_%7C_CJIS_%7C_GovRAMP-blue)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Overview

As enterprises adopt Generative AI, they face the risk of **Data Leakage** (sending PII/secrets to LLM providers) and **Shadow AI** (using unapproved models).

This framework acts as a **Governance Proxy** a FastAPI middleware layer that sits between your users and the LLM APIs. It inspects every prompt in real-time to sanitize sensitive data before it leaves your network, enforces model allowlisting, and maintains a tamper-evident audit trail for GRC compliance.

## Features

- **Multi-Domain Scanning:** Regex-based detection for PII, Medical Data (HIPAA: diagnosis codes, record numbers, dates of birth), Criminal Justice identifiers (CJIS: FBI and state ID numbers, driver's licenses), and DevOps Secrets (AWS, GitHub, Slack, Google, Stripe and LLM provider keys, private keys, tokens). Card and DEA numbers are verified by their check digit. The whole request is scanned: every message, tool call, tool result and tool definition. So is everything in the model's reply.
- **Works With Existing OpenAI Clients:** Point the official SDK's `base_url` at the proxy. Tools, `max_tokens`, `response_format` and the rest of the chat format pass through unchanged.
- **Real-Time API Proxy:** Drop-in replacement for OpenAI's `/v1/chat/completions` endpoint with governance enforcement.
- **Policy-as-Code:** DLP rules defined in YAML (`policies/generative_ai_aup.yaml`), updatable by GRC teams without code changes.
- **Model Allowlisting:** Only approved model families (defined in YAML) can be used. Unapproved models are rejected.
- **Authentication & Rate Limiting:** API key auth via `X-Governance-API-Key` header. Each key has a name, and that name is what the audit log records. Rate limiting is per API key.
- **Fails Closed:** The proxy refuses to start without API keys, TLS, an audit signing key, or a valid policy file, and refuses any request it cannot write to the audit log.
- **Built-in HTTPS:** Give it a certificate and key and it serves TLS 1.2+ itself, with AES-GCM suites only. Or declare that a load balancer in front of it does.
- **Monitoring Mode:** Deploy in log-only mode to observe violations before switching to enforcement. Nothing is blocked or altered; the audit log records what would have happened.
- **Signed, Anchored Audit Logging:** Hash-chained JSONL entries, each signed with a secret key, safe with several server workers. The newest log state can be copied to another system after every write, so deleted entries or a restored older log are provable.
- **Smart Remediation:**
  - **BLOCK:** Stops the request entirely for critical data (SSN, secrets).
  - **REDACT:** Masks lower-risk data (emails, IPs) and forwards the sanitized prompt.
- **Response Rules:** The model's reply is checked against the same patterns. `output_rules` in the policy sets what is blocked, redacted or allowed in replies. By default a reply is blocked for anything a prompt would be blocked for.
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

# Required — signs every audit entry so the log cannot be rewritten. Generate with:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"
export AUDIT_HMAC_KEY="a-long-random-secret"

# Required — HTTPS. Either give the proxy a certificate and key...
export TLS_CERT_FILE="/path/to/tls.crt"
export TLS_KEY_FILE="/path/to/tls.key"
# ...or, if a load balancer in front of it provides HTTPS:
# export TLS_TERMINATED_UPSTREAM=true

# Recommended — copy the audit log's state to a system this host cannot change
export AUDIT_ANCHOR_URL="https://your-siem.example.com/collector"

# Optional — Jira integration
export JIRA_WEBHOOK="https://automation.atlassian.com/pro/hooks/..."
```

### 3. Run the Server

```bash
make serve
# Server at https://<host>:8000
# Docs at https://<host>:8000/docs
```

The proxy will not start unless `PROXY_API_KEYS`, `AUDIT_HMAC_KEY` and a TLS choice are set, and the policy file is valid.

**Just trying it on your own machine?** `make run` starts it with `ALLOW_INSECURE_DEV=true`: plain HTTP on localhost, no keys, unsigned audit log. Never use that where real data is involved. `/health` shows when it is on.

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
                                       │  BLOCK  CLEAN/REDACT
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
| `AUDIT_HMAC_KEY` | **Yes** | — | Secret that signs every audit entry and the head record. At least 32 characters. Keep it in a secrets manager, never beside the log. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | **Yes**, or the next row | — | Certificate and private key (PEM). The proxy then serves HTTPS itself: TLS 1.2+, AES-GCM suites only. |
| `TLS_TERMINATED_UPSTREAM` | **Yes**, or the row above | `false` | Set to `true` when a load balancer or ingress in front of the proxy provides HTTPS. Keep the hop between them on a private network. |
| `AUDIT_ANCHOR_URL` | Recommended | *(empty = off)* | HTTPS endpoint that receives the audit log's head record (entry count, newest hash, signature) after every write. |
| `ALLOW_INSECURE_DEV` | No | `false` | Local demos only. Lets the proxy start without keys, TLS or a signing key, and fall back to a built-in policy if the policy file is missing or invalid. Shown on `/health`. |
| `HOST`, `PORT`, `WORKERS` | No | `0.0.0.0`, `8000`, `1` | Listen address, port and worker count when started with `ai-gov-server`. The Docker image sets `WORKERS=4`. |
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
│   ├── audit/logger.py       # Hash-chained, signed audit logger
│   ├── audit/anchor.py       # Copies the log's state to another system
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

- **Regex-only detection.** The scanner will miss encoded, obfuscated, or context-dependent sensitive data. Record numbers, dates of birth, undashed SSNs and the CJIS identifiers are caught only when a label such as "MRN" or "FBI number" sits next to them. Names and addresses are not detected. See `scanning/patterns.py` for per-pattern false-positive/false-negative documentation. NER model integration (e.g., Presidio) is planned.
- **Cryptography is not FIPS validated by default.** TLS and audit signatures use the OpenSSL that Python is linked against. For CJIS or GovRAMP, run on a FIPS 140-3 validated OpenSSL or terminate TLS on a validated load balancer. See [docs/COMPLIANCE_MAPPING.md](docs/COMPLIANCE_MAPPING.md).
- **The audit log is only as safe as its key and its anchor.** Without the signing key nobody can alter or remove entries undetected. Someone who holds the key can, unless `AUDIT_ANCHOR_URL` points at a system they cannot change. Set it in production.
- **No log retention or rotation.** The proxy appends to one file. Archive and expire it to match your retention policy.
- **The `user_id` field in a request is not verified.** The audit log records the owner of the API key as `user_id` and stores the caller-supplied value separately as `client_user_id`.
- **Rate limits are per worker.** With four workers, a key can make up to four times `RATE_LIMIT` requests per minute. Use a shared store or your gateway's rate limiting if you need an exact limit.
- **Streaming is not supported.** A request with `stream: true` is refused, because a streamed reply would reach the caller before it could be scanned as a whole.
- **Images, audio and files are refused by default.** Pattern matching cannot read them, so a photo of an ID card would pass straight through. Set `allow_non_text_content: true` in the policy to allow them unscanned.
- **Single upstream provider format.** Currently supports OpenAI-compatible APIs. Azure OpenAI and other providers require URL/auth format changes.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

[MIT](LICENSE)

**Disclaimer:** This tool does not guarantee regulatory compliance. It is one layer in a defense-in-depth strategy. Consult your compliance team before deploying in regulated environments.
