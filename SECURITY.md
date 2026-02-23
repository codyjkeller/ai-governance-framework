# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.x     | Yes                |
| < 3.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email **[security contact - update this]** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. The potential impact
4. Any suggested fixes (optional)

You should receive an acknowledgment within **48 hours** and a detailed response within **5 business days** indicating the next steps.

## Security Considerations

This framework is a governance proxy that processes potentially sensitive data (PII, PHI, secrets). Deployers should be aware of the following:

- **Regex-based detection has known limitations.** It will miss encoded, obfuscated, or context-dependent sensitive data. See `src/ai_governance/scanning/patterns.py` for documented false-positive and false-negative notes per pattern.
- **Audit logs contain metadata but not the full prompt/response by default.** Matched values are partially masked in logs.
- **This tool does not guarantee regulatory compliance.** It is one layer in a defense-in-depth strategy. Consult your compliance team before deploying in HIPAA, CJIS, or other regulated environments.
- **TLS termination is your responsibility.** The proxy runs on plaintext HTTP. Deploy behind a reverse proxy (nginx, Traefin, Envoy) with TLS in production.

## Dependency Security

This project uses:
- `pip-audit` for dependency vulnerability scanning
- `bandit` for Python SAST
- `trivy` for container image scanning
- `detect-secrets` as a pre-commit hook

These run automatically in the CI pipeline on every PR.
