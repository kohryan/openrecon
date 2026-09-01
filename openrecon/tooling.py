"""Single source of truth for the external tools openrecon shells out to.

openrecon deliberately drives best-of-breed open-source scanners (ProjectDiscovery
suites, SpiderFoot, ...) as subprocesses rather than reinventing them. That keeps the
core small and lets operators swap tool versions freely. This module knows, for each
tool:

* whether it is a free OSS binary we can fetch, or a paid API we only document;
* the exact command to install it, and the env var its key lives in.

`install-tools` (cli) consumes this to set up a working environment in one command,
and `Collector.available()` uses it to turn a bare "missing tool" line into a concrete
fix instead of a dead end.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess

# kind: "go"     -> free OSS, installed via `go install` (falls back to manual line)
#       "pip"    -> free OSS, installed via the [tools] extra
#       "manual" -> free OSS, but not pip/go installable; we only print how to get it
#       "key"    -> paid/external API; we never fetch it, only explain how to enable it
TOOL_REGISTRY: dict[str, dict] = {
    # --- ProjectDiscovery Go binaries (free, OSS) ----------------------------
    "katana": {
        "kind": "go",
        "pkg": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "manual": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "note": "web crawler - feeds the attack stage its endpoints",
    },
    "nuclei": {
        "kind": "go",
        "pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "manual": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "post": "nuclei -update-templates",
        "note": "template-based vuln scanner",
    },
    "subfinder": {
        "kind": "go",
        "pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "manual": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "note": "passive subdomain enumeration",
    },
    "naabu": {
        "kind": "go",
        "pkg": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "manual": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "note": "fast port scanner",
    },
    "ffuf": {
        "kind": "go",
        "pkg": "github.com/ffuf/ffuf/v2@latest",
        "manual": "go install github.com/ffuf/ffuf/v2@latest",
        "note": "parameter/endpoint fuzzer (needs a wordlist)",
    },
    "dalfox": {
        "kind": "go",
        "pkg": "github.com/hahwul/dalfox/v2@latest",
        "manual": "go install github.com/hahwul/dalfox/v2@latest",
        "note": "context-aware XSS scanner",
    },
    "interactsh-client": {
        "kind": "go",
        "pkg": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "manual": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "note": "OOB callback client for blind SSRF",
    },
    "sqlmap": {
        "kind": "pip",
        "extra": "tools",
        "manual": "uv pip install '.[tools]'   # or: pip install sqlmap",
        "note": "SQL injection confirmation (verify-only)",
    },
    # --- Python OSS ----------------------------------------------------------
    # SpiderFoot has no usable PyPI release (only a 0.0.1 placeholder), so it
    # cannot go in the [tools] extra. Install it from source and point config
    # at it with `tool_paths.spiderfoot`.
    "spiderfoot": {
        "kind": "manual",
        "manual": (
            "git clone https://github.com/smicallef/spiderfoot "
            "&& pip install -r spiderfoot/requirements.txt"
        ),
        "note": "OSINT / footprinting framework (install from GitHub, not PyPI)",
    },
    # --- External APIs (paid or free-tier keys; never fetched) ---------------
    "securitytrails": {
        "kind": "key",
        "env": "SECURITYTRAILS_API_KEY",
        "signup": "https://securitytrails.com/corp/products/api-integration",
        "note": "paid API - historical DNS & subdomain intelligence",
    },
    "shodan": {
        "kind": "key",
        "env": "SHODAN_API_KEY",
        "signup": "https://account.shodan.io/register",
        "note": "free tier available - internet-wide host intelligence",
    },
    "virustotal": {
        "kind": "key",
        "env": "VIRUSTOTAL_API_KEY",
        "signup": "https://www.virustotal.com/gui/my-apikey",
        "note": "free tier available - file/URL reputation",
    },
    "hibp": {
        "kind": "key",
        "env": "HIBP_API_KEY",
        "signup": "https://haveibeenpwned.com/API/Key",
        "note": "paid API - breached credential lookup",
    },
}


def tool_names() -> list[str]:
    return sorted(TOOL_REGISTRY)


def install_hint(name: str) -> str:
    """A concrete one-line fix for a missing tool or key."""
    info = TOOL_REGISTRY.get(name)
    if info is None:
        return f"install {name} or set tool_paths.{name} in your config"
    if info["kind"] in ("go", "pip", "manual"):
        return info["manual"]
    # key
    return f"set {info['env']} (sign up: {info['signup']})"


def oss_tools() -> list[str]:
    """Names of free OSS tools we can try to install automatically."""
    return [n for n, i in TOOL_REGISTRY.items() if i["kind"] in ("go", "pip")]


def install_oss_tool(name: str) -> tuple[bool, str]:
    """Attempt to install one OSS tool. Returns (ok, message).

    Go tools need a `go` toolchain on PATH; without it we fall back to printing
    the manual command rather than failing the whole run.
    """
    info = TOOL_REGISTRY.get(name)
    if info is None:
        return False, f"{name} is not a known tool"
    if info["kind"] not in ("go", "pip"):
        # key / manual tools are not fetched here - point at the concrete fix.
        return False, f"{name} is not auto-installable; {install_hint(name)}"

    if info["kind"] == "pip":
        try:
            subprocess.run(
                ["uv", "pip", "install", ".[tools]"],
                check=True,
                capture_output=True,
                text=True,
            )
            return True, f"installed {name} via the [tools] extra"
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            return False, f"could not auto-install ({(str(exc)[:80])}); run: {info['manual']}"

    # go binary
    if shutil.which("go") is None:
        return False, f"go toolchain not found - run manually:\n    {info['manual']}"
    try:
        subprocess.run(
            ["go", "install", info["pkg"]],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return False, f"go install failed ({(str(exc)[:80])}); run manually:\n    {info['manual']}"

    post = info.get("post")
    if post:
        with contextlib.suppress(OSError):
            subprocess.run(post, shell=True, check=False, capture_output=True, text=True)
    return True, f"installed {name} (go install)"
