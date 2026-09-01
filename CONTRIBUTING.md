# Contributing to openrecon

Thank you for your interest in contributing! This document covers how to get started, our development workflow, and the standards we follow.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it.

## Getting Started

### Prerequisites

- Python 3.11+
- Go 1.21+ (for the OSS scanners openrecon drives)
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Setup

```bash
git clone https://github.com/kohryan/openrecon
cd openrecon
uv venv && uv pip install -e '.[dev]'
make tools  # install the Go scanners (optional for development)
```

### Running Tests

```bash
make test
```

The test suite is hermetic — no collector reaches the network. Tests use local listeners and mocked HTTP clients.

### Linting

```bash
make lint
```

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting.

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Open a new issue with:
   - openrecon version (`openrecon --version`)
   - Python version
   - Command that triggered the bug
   - Expected vs actual behavior
   - Full error output (with `--verbose` if available)

### Suggesting Features

Open an issue describing:
- What the feature does
- Why it's useful
- How it might be implemented (optional)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-collector`)
3. Make your changes
4. Add tests for new functionality
5. Run `make test` and `make lint`
6. Update CHANGELOG.md under "Unreleased"
7. Submit the PR with a clear description

## Project Structure

```
openrecon/
├── openrecon/
│   ├── collectors/        # Data-gathering modules
│   │   ├── base.py        # Collector contract & registry
│   │   ├── services.py    # Port scanning, exposed services
│   │   ├── attack.py      # Crawler, nuclei, fuzzer, SQLi, SSRF, auth
│   │   ├── cmdi.py        # OS command injection
│   │   ├── lfi.py         # Path traversal
│   │   └── ...
│   ├── core/
│   │   ├── graph.py       # Attack-surface graph
│   │   ├── models.py      # Node, Finding, Edge types
│   │   └── net.py         # HTTP client, DNS resolver
│   ├── adversary/         # Attack-path simulation
│   ├── risk/              # Risk scoring engine
│   ├── report/            # HTML, PDF, console output
│   ├── ai/                # AI analyst integration
│   └── cli.py             # Command-line interface
├── tests/                 # Test suite (mirrors openrecon/ structure)
├── docs/
└── pyproject.toml
```

## Collector Development

Every collector inherits from `Collector` and declares:

```python
@register
class MyCollector(Collector):
    name = "my_collector"
    stage = "attack"  # or "dns", "subdomains", "services", etc.
    mode = ScanMode.ACTIVE  # or ScanMode.PASSIVE
    description = "What this collector does"
    requires_keys = ()  # API keys needed
    requires_bins = ()  # External binaries needed

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        # Read the graph, return new nodes/edges/findings
        ...
```

### Key Principles

1. **Scope-gated**: Always filter targets through `self.targets_in_scope()`
2. **Graph-aware**: Return `CollectorResult` with nodes, edges, findings
3. **Non-mutating**: Never modify the input graph
4. **Graceful degradation**: One failing collector never aborts the scan
5. **Evidence-backed**: Every finding includes evidence and confidence

### Testing Collectors

```python
# tests/test_my_collector.py
def test_my_collector_finds_vulnerable_endpoint():
    http = _FakeHttp("vulnerable")
    ctx = CollectorContext(config=Config(active=True), http=http, ...)
    collector = MyCollector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    # Add test nodes...
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
```

## Release Process

See [RELEASE.md](RELEASE.md) for the full release workflow.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
