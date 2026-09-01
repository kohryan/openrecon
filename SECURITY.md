# Security Policy

## Supported Versions

We release patches for the latest minor version. Older versions are not supported.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1.0 | No        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to [rw.januardi@gmail.com](mailto:rw.januardi@gmail.com) 

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 90 days.

## Security Considerations

openrecon is a security testing tool. Please use it responsibly:

- **Authorized use only** — only scan systems you own or have explicit permission to test
- **Rate-limited by default** — the tool is designed to be gentle on targets
- **Scope-gated** — active scans require explicit authorization via `--active --i-own-this` or a scope file

## Dependencies

We keep dependencies minimal and audit them regularly. If you find a vulnerability in a dependency, please report it.

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the issue and determine its severity
2. Develop a fix and release a patch
3. Credit the reporter (unless they prefer to remain anonymous)
4. Publish a security advisory on GitHub
