"""Runtime configuration: defaults, env vars, and an optional YAML file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from platformdirs import user_cache_dir, user_config_dir

APP_NAME = "openrecon"

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


_dotenv_loaded = False


def ensure_dotenv() -> None:
    """Load .env once per process, whichever entry point ran first.

    Config objects get built directly by library callers as well as by the CLI,
    and a key that works in one and not the other is a confusing bug to hit.
    """
    global _dotenv_loaded
    if not _dotenv_loaded:
        _dotenv_loaded = True
        load_dotenv()


def load_dotenv(path: Path | None = None) -> dict[str, str]:
    """Read a .env file into os.environ without clobbering real environment vars.

    A shell export always wins over the file, so `GEMINI_API_KEY=x openrecon ...`
    does what you expect even when .env says something else.
    """
    candidate = Path(path) if path else Path.cwd() / ".env"
    if not candidate.exists():
        return {}
    loaded: dict[str, str] = {}
    for line in candidate.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2).strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            raw = raw[1:-1]
        if not raw:
            continue
        loaded[key] = raw
        os.environ.setdefault(key, raw)
    return loaded

DEFAULT_CONFIG_PATH = Path(user_config_dir(APP_NAME)) / "config.yaml"
DEFAULT_CACHE_DIR = Path(user_cache_dir(APP_NAME))


def _extra_tool_dirs() -> list[Path]:
    """Bin dirs to search after PATH: where `go install` and pip put binaries.

    `go install` writes to $GOBIN, else $GOPATH/bin, else ~/go/bin; pip
    user-installs and `uv tool` land in ~/.local/bin. None of these are
    guaranteed to be on PATH, so we check them explicitly.
    """
    home = Path.home()
    dirs: list[Path] = []
    if gobin := os.environ.get("GOBIN"):
        dirs.append(Path(gobin))
    if gopath := os.environ.get("GOPATH"):
        dirs.extend(Path(part) / "bin" for part in gopath.split(os.pathsep) if part)
    dirs.append(home / "go" / "bin")
    dirs.append(home / ".local" / "bin")
    seen: set[Path] = set()
    return [d for d in dirs if not (d in seen or seen.add(d))]

# Providers we know how to use, mapped to the env var holding their key.
API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai_compatible": "OPENRECON_AI_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "censys_id": "CENSYS_API_ID",
    "censys_secret": "CENSYS_API_SECRET",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "certspotter": "CERTSPOTTER_TOKEN",
    "nvd": "NVD_API_KEY",
    "hibp": "HIBP_API_KEY",
    "github": "GITHUB_TOKEN",
}


@dataclass
class Config:
    # --- behaviour -----------------------------------------------------------
    active: bool = False
    """Allow collectors that send packets to target-owned infrastructure."""

    concurrency: int = 20
    timeout: float = 10.0
    http_timeout: float = 12.0
    dns_timeout: float = 5.0
    rate_limit_per_host: float = 3.0
    """Max requests per second against any single host.

    Deliberately conservative. Several active collectors target the same host in
    the same stage, and the aggregate is what trips edge protection - after
    which every later collector sees a 403 and the scan quietly reports less
    than it should.
    """

    refusal_threshold: int = 5
    """Consecutive 403/429 responses before a host is left alone for the rest of the scan."""

    max_subdomains: int = 2000
    """Hard cap so a wildcard-heavy target can't blow up the graph."""

    max_ports_per_host: int = 0
    """0 = use the built-in top-ports list."""

    user_agent: str = "openrecon/0.1 (+https://github.com/openrecon/openrecon)"

    # --- attack-stage auth (IDOR / auth-bypass) -----------------------------
    # An authorized session cookie for the target program. Lets AuthCollector
    # diff authed vs unauthed responses to surface broken access control. Never
    # sent anywhere but the in-scope target. Keep it out of version control.
    auth_cookie: str = ""

    # --- selection -----------------------------------------------------------
    enabled_collectors: set[str] = field(default_factory=set)
    disabled_collectors: set[str] = field(default_factory=set)

    # --- infra ---------------------------------------------------------------
    resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    cache_dir: Path = DEFAULT_CACHE_DIR
    cache_ttl: int = 3600
    use_cache: bool = True
    output_dir: Path = Path("out")

    # --- ai ------------------------------------------------------------------
    ai_enabled: bool = True
    ai_provider: str = ""
    """Backend name, or empty to auto-select (local Ollama first, then free tiers)."""
    ai_model: str = ""
    """Empty means the provider's default model."""
    ai_base_url: str = ""
    """Override the provider endpoint - a remote Ollama, vLLM, LM Studio, ...."""
    ai_effort: str = "high"

    # --- keys ----------------------------------------------------------------
    api_keys: dict[str, str] = field(default_factory=dict)

    # --- external tools ------------------------------------------------------
    # Open-source scanners (subfinder, nuclei, spiderfoot, ...) are invoked as
    # subprocesses rather than imported. Map a tool name to an explicit path to
    # override discovery on PATH; anything unset is resolved with shutil.which.
    tool_paths: dict[str, str] = field(default_factory=dict)

    @property
    def mode_label(self) -> str:
        return "active" if self.active else "passive"

    def key(self, provider: str) -> str | None:
        """Resolve a provider key from config file first, then environment."""
        ensure_dotenv()
        if provider in self.api_keys and self.api_keys[provider]:
            return self.api_keys[provider]
        env = API_KEY_ENV.get(provider)
        value = os.environ.get(env) if env else None
        return value or None

    def has_key(self, *providers: str) -> bool:
        return all(self.key(p) for p in providers)

    def collector_allowed(self, name: str) -> bool:
        if name in self.disabled_collectors:
            return False
        if self.enabled_collectors:
            return name in self.enabled_collectors
        return True

    def tool(self, name: str) -> str | None:
        """Resolve the path to an external binary.

        Resolution order: an explicit ``tool_paths`` override, then ``PATH``,
        then the well-known bin dirs that ``go install`` and pip user-installs
        drop binaries into (``$GOBIN``, ``$GOPATH/bin``, ``~/go/bin``,
        ``~/.local/bin``).

        That last step is what makes ``make tools`` actually work: ``go install``
        writes to ``~/go/bin``, which is very often *not* on a user's PATH, so
        without this fallback every freshly installed ProjectDiscovery tool
        (katana, nuclei, subfinder, naabu, ...) would be reported as missing
        even though it is sitting right there on disk.
        """
        ensure_dotenv()
        override = self.tool_paths.get(name)
        if override:
            return override
        import shutil

        found = shutil.which(name)
        if found:
            return found
        for directory in _extra_tool_dirs():
            candidate = directory / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(cls, path: str | Path | None = None, **overrides: Any) -> Config:
        ensure_dotenv()
        cfg = cls()
        candidate = Path(path) if path else DEFAULT_CONFIG_PATH
        if candidate.exists():
            raw = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            cfg = cls._from_dict(raw)
        for k, v in overrides.items():
            if v is None:
                continue
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        cfg.cache_dir = Path(cfg.cache_dir)
        cfg.output_dir = Path(cfg.output_dir)
        return cfg

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> Config:
        cfg = cls()
        for k, v in raw.items():
            if not hasattr(cfg, k):
                continue
            current = getattr(cfg, k)
            if isinstance(current, set):
                v = set(v or [])
            elif isinstance(current, Path):
                v = Path(v)
            setattr(cfg, k, v)
        return cfg

    def describe_keys(self) -> dict[str, bool]:
        return {p: bool(self.key(p)) for p in API_KEY_ENV}
