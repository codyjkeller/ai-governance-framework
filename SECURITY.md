# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.x     | Yes (best effort)  |
| < 3.0   | No                 |

## Important Context

This is a **personal portfolio project** maintained by a single developer. It is not actively monitored or staffed for rapid incident response. Vulnerability reports are appreciated but will be addressed on a best-effort basis as time permits.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please open a **private security advisory** via GitHub's [Security Advisories](https://github.com/codyjkeller/ai-governance-framework/security/advisories) feature with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. The potential impact
4. Any suggested fixes (optional)

I will handle any reported issues when I can. There is no SLA or guaranteed response time.

## Security Considerations

This framework is a governance proxy that processes potentially sensitive data (PII, PHI, secrets). Deployers should be aware of the following:

- **Regex-based detection has known limitations.** It will miss encoded, obfuscated, or context-dependent sensitive data. See `src/ai_governance/scanning/patterns.py` for documented false-positive and false-negative notes per pattern.
- **Audit logs contain metadata but not the full prompt/response by default.** Matched values are partially masked in logs.
- **The proxy fails closed.** It will not start without API keys, TLS, an audit signing key, or a valid policy file, and it refuses requests it cannot audit. `ALLOW_INSECURE_DEV=true` turns the startup checks off and must never be set in a real deployment.
- **This tool does not guarantee regulatory compliance.** It is one layer in a defense-in-depth strategy. Consult your compliance team before deploying in HIPAA, CJIS, or other regulated environments.
- **HTTPS is required.** Give the proxy a certificate and key (`TLS_CERT_FILE`, `TLS_KEY_FILE`) and it serves TLS 1.2+ itself, or set `TLS_TERMINATED_UPSTREAM=true` when a load balancer provides it. You supply and renew the certificate. The cryptography is not FIPS validated unless the host's OpenSSL is.

## Dependency Security

This project uses:
- `pip-audit` for dependency vulnerability scanning
- `bandit` for Python SAST
- `trivy` for container image scanning
- `detect-secrets` as a pre-commit hook

These run automatically in the CI pipeline on every PR.
