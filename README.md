<p align="center">
  <img src="openrecon-logo.png" alt="openrecon" width="320"/>
</p>

<p align="center">
  <strong>Attack-surface reconnaissance that beats a bare nuclei/ffuf run.</strong><br/>
  Maps a target's exposure as a <strong>graph</strong>, drives best-of-breed OSS scanners
  against the <em>exact</em> endpoints recon found, and turns findings into a risk-scored report.
</p>

<p align="center">
  <!-- License -->
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License"/></a>
  <!-- Python -->
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"/>
  <!-- Code style -->
  <img src="https://img.shields.io/badge/code%20style-ruff-000000?style=flat-square" alt="Ruff"/>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#pipeline">Pipeline</a> ·
  <a href="#scope--safety">Scope & Safety</a> ·
  <a href="#development">Development</a>
</p>

---

> ⚠️ **Authorized use only.** Every active scan requires `--active --i-own-this`
> (or a scope file). It is rate-limited and single-origin — think "authorized
> attack-surface census", not a DDoS.
> Unauthorized scanning may be illegal in your jurisdiction.
> The developers are not responsible for misuse of this tool.

---

## Install

### 1. Python + the package

Requires Python 3.11+.

```bash
git clone https://github.com/kohryan/openrecon
cd openrecon
uv venv && uv pip install -e .
```

That is enough for **passive scans** and every report format except PDF. The
optional extras add:

| Extra | Command | Adds |
|-------|---------|------|
| `tools` | `uv pip install -e '.[tools]'` | `sqlmap` (the pip scanner used by the active `sqli` stage) |
| `pdf` | `uv pip install -e '.[pdf]'` | `reportlab`, so `--pdf` works |
| `ai` | `uv pip install -e '.[ai]'` | the Anthropic SDK (only needed for `--ai anthropic`; gemini/groq/openrouter/ollama are plain HTTP) |

(`pip install -e '.[tools]'` works too if you don't use uv.) You don't need to
run the `[tools]` line by hand, step 3 (`make tools`) installs it for you.

### 2. The Go toolchain (needed for the active scanners)

The free scanners openrecon drives — katana, nuclei, subfinder, naabu, ffuf,
dalfox, interactsh-client — are **Go binaries**. `pip`/`uv` cannot build Go code,
so you must install the Go toolchain once:

```bash
# macOS (Homebrew)
brew install go

# Ubuntu/Debian
sudo apt-get install -y golang-go

# Or download from https://go.dev/dl and add $(go env GOPATH)/bin to PATH
```

Verify:

```bash
go version        # Go 1.21+ recommended
```

`go install` drops the binaries into the Go bin dir, `$GOBIN`, else
`$(go env GOPATH)/bin` (which defaults to `~/go/bin`). **openrecon finds them
there automatically**: on top of your `PATH` it also searches `$GOBIN`,
`$GOPATH/bin`, `~/go/bin`, and `~/.local/bin`, so `make tools` just works even
when that directory isn't on your `PATH`.

Adding it to `PATH` is still recommended so you can run the scanners by hand
(`make tools` prints this line for you when it's missing):

```bash
# add to ~/.zshrc or ~/.bashrc, then restart your shell
export PATH="$PATH:$(go env GOPATH)/bin"
```

### 3. Fetch the scanners (one command)

```bash
make tools          # or: ./install-tools.sh
```

This installs the auto-installable scanners openrecon drives:

- **Python OSS** (via `[tools]`): `sqlmap`
- **Go OSS** (via `go install`): `katana`, `nuclei`, `subfinder`, `naabu`,
  `ffuf`, `dalfox`, `interactsh-client`, and runs `nuclei -update-templates`

If `go` isn't installed, the script skips the Go tools and tells you how to
install Go (step 2). Re-run `make tools` afterwards.

> **SpiderFoot is not fetched by `make tools`.** It has no usable PyPI release
> (only a `0.0.1` placeholder), so it cannot ship in the `[tools]` extra. It is
> an *optional* OSINT collector; to enable it, install it from source and point
> config at the binary:
>
> ```bash
> git clone https://github.com/smicallef/spiderfoot
> pip install -r spiderfoot/requirements.txt
> ```
> ```yaml
> # config file passed with --config
> tool_paths:
>   spiderfoot: /path/to/spiderfoot/sf.py
> ```

The paid/keyed enrichment sources (SecurityTrails, HIBP, Shodan, VirusTotal,
Censys) are **never fetched or bundled** — they need your own API keys. Set
them as environment variables when you want that data.

Run `openrecon collectors` afterwards to see exactly what is ready and what
still needs a Go binary, an API key, or `--active`.

### Troubleshooting: "missing tool(s)" after `make tools`

If a scan's footer still lists a tool as missing right after you installed it,
work down this list:

- **The binary isn't on `PATH`.** The usual cause: `go install` wrote it to
  `~/go/bin`, which many shells don't add to `PATH`. openrecon searches `$GOBIN`,
  `$GOPATH/bin`, `~/go/bin`, and `~/.local/bin` directly, so this normally
  resolves itself. If it doesn't, the binary lives somewhere non-standard, pin
  it with `tool_paths.<name>` (below) or add its dir to `PATH` (step 2). Confirm
  where a tool is with `command -v nuclei` (or `ls "$(go env GOPATH)/bin"`).
- **`spiderfoot`** is *never* fetched by `make tools`, it's a manual install
  (see the note above), then pin it with `tool_paths.spiderfoot`.
- **`leaks` / `securitytrails`** need an **API key**, not a binary. Set the env
  var (see the API-key section below); the warning is expected until you do.
- **Pin any tool explicitly** when it's in a custom location:

  ```yaml
  # a config file passed with --config
  tool_paths:
    nuclei: /opt/pd/nuclei
    ffuf: /usr/local/bin/ffuf
  ```

---

## External tools openrecon drives

openrecon doesn't reinvent scanners — it orchestrates best-of-breed ones as
subprocesses and turns their output into graph nodes. Each tool is resolved in
this order: an explicit `tool_paths.<name>` in a config file → your `PATH` → the
common install dirs `$GOBIN`, `$GOPATH/bin`, `~/go/bin`, `~/.local/bin`. So a
`go install`ed scanner is found even when its dir isn't on `PATH`.

| Tool | Install kind | How to get it | Role |
|------|--------------|---------------|------|
| `katana` | `go install` | `make tools` | Crawl in-scope endpoints (the surface everything else attacks) |
| `nuclei` | `go install` | `make tools` | Template-based CVE / misconfig / exposed-panel scanning |
| `subfinder` | `go install` | `make tools` | Passive subdomain enumeration |
| `naabu` | `go install` | `make tools` | Fast port scanning (active) |
| `ffuf` | `go install` | `make tools` | Parameter / content fuzzing (needs a wordlist) |
| `dalfox` | `go install` | `make tools` | Context-aware XSS scanning |
| `interactsh-client` | `go install` | `make tools` | Out-of-band callback client for blind SSRF |
| `sqlmap` | `pip` (`[tools]`) | `make tools` / `uv pip install -e '.[tools]'` | SQL-injection confirmation (verify-only) |
| `spiderfoot` | **manual** | clone from GitHub, set `tool_paths.spiderfoot` | OSINT / footprinting (optional) |
| `securitytrails`, `shodan`, `virustotal`, `hibp` | **API key** | set the env var (see below) | Enrichment; never fetched, never bundled |

**What changed recently**

- **Tools are found in `~/go/bin` even when it's not on `PATH`.** `make tools`
  installs the Go scanners into the Go bin dir, which many shells don't put on
  `PATH`, so they used to show up as "missing" right after installing them.
  openrecon now also searches `$GOBIN`, `$GOPATH/bin`, `~/go/bin`, and
  `~/.local/bin`, so a freshly `make tools`'d machine works out of the box.
- `interactsh` → **`interactsh-client`**. The old `.../cmd/interactsh` package
  doesn't exist; the real callback client binary is `interactsh-client`. `make
  tools` and the SSRF collector now use that name.
- The `[tools]` extra pins **`sqlmap`** only. It previously listed
  `spiderfoot>=5.0`, which is unsatisfiable (PyPI has only a `0.0.1`
  placeholder), so `.[tools]` failed to install at all. SpiderFoot moved to a
  documented manual install.
- **PDF export is fully optional.** `reportlab` is imported lazily, so the CLI
  runs without the `[pdf]` extra; only `--pdf` needs it.

API-key tools are enabled by exporting their env var, for example:

```bash
export SHODAN_API_KEY=...          # free tier
export VIRUSTOTAL_API_KEY=...      # free tier
export SECURITYTRAILS_API_KEY=...  # paid
export HIBP_API_KEY=...            # paid
```

`openrecon collectors` shows a `key: <name>` status for any collector still
waiting on one.

---

## Quick start

```bash
# 1. Check which collectors are ready right now (no target touched)
openrecon collectors

# 2. Passive scan, safe, never sends a packet to the target
openrecon scan example.com
#    -> writes the graph JSON to out/example_com/<timestamp>.json
#       and an interactive report to out/example.com.html

# 3. Authorized, full active bug-bounty scan (AI analyst on by default)
openrecon scan example.com --active --i-own-this --ai gemini

# 4. Re-render a saved graph as a report (add --pdf; needs the [pdf] extra)
openrecon report out/example_com/<timestamp>.json --html out/example.com.html --pdf out/example.com.pdf
```

The AI analyst runs **during the scan** (`--ai <provider>`, default gemini; use
`--no-ai` to skip). `openrecon report` just re-renders whatever the scan already
produced, so it has no `--ai` flag. PDF export needs the `[pdf]` extra
(`uv pip install -e '.[pdf]'`), without it, `--pdf` prints a hint instead of
failing the run.

`--i-own-this` is a hard gate: without it (or a scope file), openrecon refuses
to send a single active packet.

---

## Commands

| Command | What it does |
|---------|--------------|
| `openrecon scan <domain>` | Run the pipeline (passive by default; add `--active --i-own-this` for bug finding). AI analyst via `--ai <provider>` / `--no-ai`; `--pdf <path>` for PDF. |
| `openrecon collectors` | List every collector, its stage, and whether it can run right now (with `--active` to preview the active set). |
| `openrecon ai` | Show which AI backends are configured and which would be used. |
| `openrecon report <graph.json>` | Re-render a saved graph; `--html <path>` and `--pdf <path>` write those formats. (No `--ai`, the analyst runs during `scan`.) |
| `openrecon diff <old.json> <new.json>` | Compare two scans (what changed on the attack surface). |
| `openrecon scope init <domain>` | Author an `in_scope`/`out_scope` scope file. |
| `openrecon scope check <file>` | Validate a scope file against a target. |
| `openrecon install-tools` | Install the free scanners individually (`--only katana --only nuclei`, `--yes` to skip prompts). |

---

## The bug-bounty pipeline (stage `attack`)

When you pass `--active --i-own-this`, openrecon runs these graph-scoped active
collectors in order. Each one only fires at **in-scope endpoints recon actually
discovered** — that's the part a plain `nuclei -u target` misses.

| Collector | Engine | Finds |
|-----------|--------|-------|
| `crawler` | katana | All in-scope URLs/endpoints (the surface everything else attacks) |
| `nuclei` | nuclei | CVEs, misconfigs, exposed panels (graph-scoped, not a blanket sweep) |
| `fuzzer` | ffuf + dalfox | Hidden parameters + reflected/stored **XSS** |
| `sqli` | sqlmap | **SQL injection** (verify-only, never exfiltrates) |
| `ssrf` | interactsh-client | **Blind SSRF** via out-of-band callbacks |
| `auth` | native HTTP | **IDOR / auth-bypass** (needs a session cookie) |
| `ssti` | native HTTP | **Server-Side Template Injection** via parameter probing |
| `lfi` | native HTTP | **LFI / Path Traversal** via parameter probing |
| `cmdi` | native HTTP | **OS Command Injection** (time-based blind + error-based) |
| `jwt` | native HTTP | **JWT misconfiguration** (none algorithm, weak secrets) |
| `cors` | native HTTP | **CORS misconfiguration** (origin reflection, wildcard+credentials) |

### Enabling the `auth` collector (IDOR / auth-bypass)

`auth` diffs the anonymous vs authenticated response for each crawled endpoint.
A `401/403` that flips to `200` with a valid cookie is broken access control —
the highest-value bug class. Put your program's authorized session cookie in
config (never committed):

```yaml
# scope.yaml or a config file passed with --config
auth_cookie: "session=eyJhbGciOi..."
```

Then run: `openrecon scan target.com --active --i-own-this --config scope.yaml`

### Deep attack: server-side vulnerability detection

The `ssti`, `lfi`, `cmdi`, `jwt`, and `cors` collectors are **native Python** —
they need no external Go binaries and run entirely from the `pip install`. They
take the endpoints the crawler found and probe them for critical server-side bugs:

| Collector | What it does | Read-only? |
|-----------|--------------|------------|
| `ssti` | Injects `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` into query params and checks if the server rendered the result ("49"). Covers Jinja2, Twig, Velocity, Freemarker, ERB. | Yes, arithmetic only |
| `lfi` | Injects `../../../etc/passwd` variants and looks for file contents in the response. Covers Unix passwd, Windows win.ini, `/etc/shadow`. | Yes, reads only |
| `cmdi` | Injects `;sleep 5`, `|id`, `` `id` `` and measures response time or looks for shell errors. Blind + error-based. | Yes, `sleep`/`id` only |
| `jwt` | Finds JWTs in cookies/headers/bodies, decodes them, checks for `alg:none` and weak HMAC secrets (dictionary of 50 common secrets). | Yes, decode only |
| `cors` | Sends crafted `Origin` headers and checks `Access-Control-Allow-Origin` for reflection, wildcard+credentials, null origin. | Yes, GET only |

### ffuf wordlist

`fuzzer` needs a wordlist. Default is
`/usr/share/seclists/Discovery/Web-Content/common.txt`. Point it elsewhere with:

```yaml
tool_paths:
  ffuf-wordlist: /path/to/your/wordlist.txt
```

---

## Scope & safety

- **In-scope only.** A target is in scope if it matches `*.example.com` (implicit)
  or your `scope.yaml`. Every active collector checks `ctx.in_scope()` before
  touching a host.
- **Rate-limited.** Concurrency and per-host rate limits live in `Config`
  (`concurrency`, `rate_limit_per_host`). Tune them down for fragile targets.
- **No data leaves your machine** except to the target you authorized and (if
  configured) your AI provider. Paid enrichment APIs are opt-in via keys.

---

## Development

```bash
make dev        # install dev extras (pytest, ruff, mypy)
make test       # run the test suite
make lint       # ruff
```

PRs welcome — keep collectors scope-gated and graph-aware.
