# Convenience targets. The only one most users need is `make tools`.
#
# `make tools` installs openrecon's free open-source dependencies in one shot:
#   - spiderfoot  (Python, via the [tools] extra)
#   - katana, nuclei, subfinder, naabu  (Go, via `go install`)
#
# Go tools require a Go toolchain on PATH; if it is missing the script skips
# them and tells you how to install it. API-key tools (securitytrails, hibp,
# shodan, virustotal) are never fetched - they need an account/key.

.PHONY: install tools dev test lint

install:
	uv pip install -e .

tools:
	./install-tools.sh

dev:
	uv pip install -e '.[dev,tools,pdf]'

test:
	pytest -q

lint:
	ruff check openrecon tests
