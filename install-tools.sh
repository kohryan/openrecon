#!/usr/bin/env bash
# Install every free open-source tool openrecon drives, in one command.
#
#   - Python tool (sqlmap) via the [tools] extra
#   - Go tools (katana, nuclei, subfinder, naabu, ...) via `go install`
#
# API-key tools (securitytrails, hibp, shodan, virustotal) are NEVER fetched -
# they need an account/key, which this script does not handle. SpiderFoot is not
# on PyPI as a usable release either, so it is not installed here; `openrecon
# collectors` prints how to fetch it from GitHub. Run `openrecon collectors`
# afterwards to see what is ready and what still needs a key.
#
# Go tools require a Go toolchain on PATH. If `go` is missing the script prints
# the install command and skips them instead of failing.
set -euo pipefail

echo "==> openrecon tool installer"

# --- Python tool (sqlmap) --------------------------------------------------
if command -v uv >/dev/null 2>&1; then
  echo "==> installing python tool (sqlmap) via uv"
  uv pip install '.[tools]' || pip install '.[tools]' || true
else
  echo "==> installing python tool (sqlmap) via pip"
  pip install '.[tools]' || true
fi

# --- Go tools --------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "!! go toolchain not found - skipping katana/nuclei/subfinder/naabu"
  echo "   install Go (https://go.dev/dl), then re-run this script or:"
  echo "     go install github.com/projectdiscovery/katana/cmd/katana@latest"
  echo "     go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  echo "     go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  echo "     go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  echo "==> done (partial: python tool only)"
  exit 0
fi

GO_TOOLS=(
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)

for pkg in "${GO_TOOLS[@]}"; do
  # strip the @version, then take the final path segment -> the binary name
  base="${pkg%@*}"          # github.com/projectdiscovery/katana/cmd/katana
  bin="$(basename "$base")"  # katana
  echo "==> go install $bin"
  go install "$pkg" || echo "   !! failed: $bin (continuing)"
done

# Where go put the binaries: $GOBIN, else $GOPATH/bin, else ~/go/bin.
GOBIN_DIR="$(go env GOBIN)"
[ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH)/bin"

# nuclei ships its template set separately. Call it by full path in case the
# go bin dir is not on PATH yet.
if [ -x "$GOBIN_DIR/nuclei" ]; then
  echo "==> updating nuclei templates"
  "$GOBIN_DIR/nuclei" -update-templates || true
fi

# The classic gotcha: `go install` succeeds but the go bin dir is not on PATH,
# so the tools look "missing". openrecon itself will still find them (it checks
# ~/go/bin directly), but add it to PATH so you can run the tools by hand too.
case ":$PATH:" in
  *":$GOBIN_DIR:"*) ;;
  *)
    echo
    echo "!! $GOBIN_DIR is not on your PATH."
    echo "   openrecon will still find these tools, but to run them directly add:"
    echo "     export PATH=\"\$PATH:$GOBIN_DIR\""
    echo "   to your ~/.zshrc (or ~/.bashrc), then restart your shell."
    ;;
esac

echo "==> done. Verify with: openrecon collectors"
