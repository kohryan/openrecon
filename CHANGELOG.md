# Changelog

All notable changes to openrecon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-01

### Added
- Initial release
- Passive reconnaissance: WHOIS, DNS, subdomains, certificates, network, technologies
- Active reconnaissance: port scanning, HTTP fingerprinting, exposed path detection
- Attack-stage pipeline: katana crawl, nuclei scan, fuzzer (ffuf + dalfox), SQLi (sqlmap), SSRF (interactsh), auth-bypass, GraphQL verification
- Server-side vulnerability detection: SSTI, LFI, CMDI, JWT analysis, CORS misconfiguration
- Attack-surface graph with risk scoring
- Adversary simulation (shortest path, counterfactual analysis)
- AI analyst integration (Gemini, Groq, OpenRouter, Anthropic, Ollama)
- Report formats: HTML, PDF, console, JSON
- Scope gating with authorization files
- CDN/edge detection and asset attribution
