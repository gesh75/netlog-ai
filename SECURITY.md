# Security Policy

netlog-ai is a sanitize-first log analysis platform: device configs and logs are
scrubbed before they reach any LLM, and the web/MCP/ITSM surfaces handle operator
credentials. We take reports against those guarantees seriously.

## Supported versions

Security fixes are made against the latest released minor version on PyPI
(currently the 2.x line) and `main`. Older releases are not patched; please upgrade.

| Version            | Supported |
| ------------------ | --------- |
| 2.x (latest minor) | Yes       |
| < 2.0              | No        |

## Reporting a vulnerability

**Please do not open a public GitHub Issue, pull request or discussion for a
suspected vulnerability.**

Report privately through GitHub Security Advisories:

1. Go to <https://github.com/gesh75/netlog-ai/security/advisories/new>
   (repository **Security** tab, then **Report a vulnerability**).
2. Describe the issue, the affected version or commit, and a minimal reproduction.
   **Use synthetic data only** (RFC 5737/3849 prefixes, private ASNs, fake
   hostnames). Never attach real device configs, tokens or customer logs.

You can expect an acknowledgement within 5 business days and a status update at
least every 14 days until the issue is resolved. Reporters are credited in the
advisory unless they prefer to stay anonymous.

## In scope

- **Sanitizer bypasses**: any input that leaves a secret, credential, community
  string, key, or other value that should be masked in text that is sent to an LLM
  provider, stored, exported or logged.
- **Credential handling**: leaks of API keys, ITSM/NetBox/device credentials or
  viewer/operator/admin tokens (logs, error messages, responses, files, process
  arguments); missing or bypassable authentication/authorization (RBAC).
- **SSRF** via configurable URLs (ITSM, NetBox, LLM endpoints, log sources, webhooks).
- **Injection**: command injection, path traversal, SQL injection, XSS, prompt-to-tool
  injection that reaches write actions, log/CRLF injection, unsafe deserialization.
- Denial of service from unauthenticated input with disproportionate resource use.

## Out of scope

- Findings that require an attacker who already holds admin tokens or shell access
  to the host.
- Vulnerabilities in third-party dependencies with no demonstrable impact on
  netlog-ai (report those upstream; we track them via Dependabot and `pip-audit`).
- Running the web server unauthenticated on an untrusted network; see
  [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md) for the authentication and binding settings.
- Quality of LLM analyses (hallucinations) that does not cross a security boundary.
