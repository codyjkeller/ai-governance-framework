# Control Mapping

How this proxy supports controls in **NIST SP 800-53 Rev. 5**, **SOC 2**, the **HIPAA Security Rule**, **CJIS Security Policy v6.1**, and **GovRAMP** (formerly StateRAMP).

> **Read this first.** A proxy cannot make an organization compliant. It supplies technical safeguards and evidence for some controls. Each row says what the proxy does and what remains your responsibility. Control references were compiled by the maintainers and have not been reviewed by an assessor. Confirm them against the source documents before using this in an audit package.

## How the frameworks relate

| Framework | What to know |
| :--- | :--- |
| **NIST SP 800-53 Rev. 5** | The control catalog the others build on. The IDs below (AC-4, AU-9, and so on) are from this catalog. |
| **GovRAMP** | Built on NIST SP 800-53 Rev. 5. Use the NIST column. Which controls apply depends on your impact level; check the GovRAMP baseline for yours. |
| **CJIS Security Policy v6.1** | Since v6.0 the policy uses NIST-style control IDs, so the NIST column applies. CJIS adds its own parameters, noted below where they matter. |
| **SOC 2** | References are to the Trust Services Criteria. A Type 2 report tests whether controls operated over a period, so the audit log and its verification are your evidence. |
| **HIPAA Security Rule** | References are to 45 CFR Part 164 as currently in force. The update proposed in January 2025 is not final; the published target is July 2027. |

## What the proxy does, control by control

| Proxy capability | NIST 800-53 r5 / GovRAMP / CJIS | SOC 2 | HIPAA | Still your job |
| :--- | :--- | :--- | :--- | :--- |
| **Every caller needs an API key; each key has a named owner** | AC-3, IA-9 | CC6.1 | 164.312(a)(1), 164.312(d) | Issue one key per application, rotate them, and store them in a secrets manager. The proxy does not sign in people: put your SSO and MFA (IA-2) in front of the applications that call it. |
| **Only approved model families can be called** | AC-3, CM-7 | CC6.1 | none | Decide which models are approved, and have the contracts that approval depends on (see "Contracts" below). |
| **The whole request is scanned (messages, tool calls, tool results); sensitive data is blocked or redacted before it leaves. Images, audio and files are refused** | AC-4, SC-7(10), SI-4 | CC6.7, C1.1 | 164.312(e)(1), 164.502(b) | Detection is pattern-based and will miss things. Treat it as one layer. Tune the policy to the data you hold. |
| **Model responses are scanned before they are returned** | SI-15, AC-4 | CC6.7 | 164.312(e)(1) | Same limits as above. |
| **Every decision is logged with time, key owner, outcome and policy version** | AU-2, AU-3, AU-8, AU-12 | CC7.2 | 164.312(b) | Keep the host clock synchronized. Review the logs (AU-6, 164.308(a)(1)(ii)(D)). |
| **Log entries are hash-chained and signed with a secret key** | AU-9, AU-9(3), AU-10 | CC7.2 | 164.312(c)(1), 164.312(c)(2) | Keep `AUDIT_HMAC_KEY` in a secrets manager, away from the log. Anyone holding the key can forge entries. |
| **The newest log state is copied to another system after every write** | AU-9(2) | CC7.2 | 164.312(c)(2) | Point `AUDIT_ANCHOR_URL` at a system the proxy host cannot modify. Ship the full log there too if you need the entries themselves preserved. |
| **A request that cannot be logged is refused** | AU-5 | CC7.2 | 164.312(b) | Alert on the 503 responses this produces. |
| **The proxy will not start when misconfigured** (no keys, no TLS, no signing key, invalid policy) | SC-24, CM-6 | CC8.1 | none | Do not set `ALLOW_INSECURE_DEV` outside a developer's machine. `/health` shows if it is on. |
| **HTTPS with TLS 1.2 or newer, AES-GCM suites only; the model provider is always called over HTTPS** | SC-8, SC-8(1), SC-13, SC-23 | CC6.7 | 164.312(e)(1), 164.312(e)(2)(ii) | Supply and renew the certificate. See "FIPS" below before relying on this for CJIS. |
| **Requests are rate limited per API key** | SC-5 | none | none | Limits are per worker. Use your gateway if you need an exact global limit. |
| **The policy is a versioned file; its version is stamped on every log entry** | CM-2, CM-3, CM-6 | CC8.1 | 164.316(b) | Review and approve policy changes through pull requests. |
| **Blocked requests can raise a Jira ticket; monitoring mode logs without enforcing** | SI-4(5), IR-5 | CC7.3 | 164.308(a)(6) | Own the incident process the ticket feeds. |

## What the proxy does not do

These are required by one or more of the frameworks and are outside this tool.

| Need | Why it matters | Where it applies |
| :--- | :--- | :--- |
| **Contracts with the model provider** | Blocking most sensitive data does not make a provider an approved destination for it. PHI needs a business associate agreement. Criminal justice information needs a provider that meets CJIS requirements, including the Security Addendum. | HIPAA 164.308(b), CJIS |
| **Log retention** | The proxy appends to a file. It does not rotate, archive or delete. Set retention to match your policy. | AU-11, CJIS, HIPAA 164.316(b)(2) |
| **Log review** | Someone has to look at the log and act on it. | AU-6, SOC 2 CC7.3, HIPAA 164.308(a)(1)(ii)(D) |
| **Encryption at rest** | The audit log and policy are plain files. Put them on an encrypted volume. | SC-28, HIPAA 164.312(a)(2)(iv) |
| **Signing in people** | API keys identify applications, not users. | IA-2, IA-2(1), IA-2(2), HIPAA 164.312(a)(2)(i) |
| **Vulnerability and patch management** | CI scans dependencies and the image, but you run and patch the deployment. | RA-5, SI-2 |

## FIPS-validated cryptography

CJIS v6.1 control SC-13 calls for FIPS 140-3 certified modules, or FIPS 197 (AES) with a 256-bit key, for criminal justice information in transit. FIPS 140-2 certificates stopped being accepted after September 21, 2026. GovRAMP and FedRAMP baselines also expect validated cryptography.

**Validation belongs to the cryptographic module, not to this code.** The proxy uses whatever OpenSSL the Python runtime is linked against, for TLS and for the audit signatures (HMAC-SHA-256). The stock Python container image is not FIPS validated. To meet the requirement, do one of these:

- Run the proxy on a host or base image whose OpenSSL is a FIPS 140-3 validated module in FIPS mode.
- Terminate TLS on a FIPS 140-3 validated load balancer and set `TLS_TERMINATED_UPSTREAM=true`.

The built-in TLS allows AES-128-GCM as well as AES-256-GCM on TLS 1.3. If you need 256-bit only, enforce that at a validated load balancer.

## Proving the audit log is intact

1. `GET /admin/audit/verify` checks every entry's chain hash and signature, and the signed head record.
2. To prove nothing was removed since a given moment, take any head record your anchor system stored and pass it back:
   `GET /admin/audit/verify?anchor_entries=<entries>&anchor_hash=<last_hash>`
   `"anchor_found": false` means the log no longer contains that state.

| An attacker who can... | Outcome |
| :--- | :--- |
| Edit or delete log entries | Detected. They cannot produce valid signatures without the key. |
| Edit entries and rewrite every hash and the head record | Detected, for the same reason. |
| Put back an older copy of the log and head record | Detected while the proxy keeps running, and detected afterwards by any stored anchor. |
| Do the above and also holds the signing key | Detected only by a stored anchor. This is why the anchor must live on a system the proxy host cannot change. |
| Controls the proxy host, the key, and the anchor system | Not detected. No single-system control can cover this; separate the duties. |
