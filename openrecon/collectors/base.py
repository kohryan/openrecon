"""Collector contract and registry.

A collector is a small, single-purpose unit that reads the graph so far and
returns new nodes/edges/findings. It declares which pipeline stage it belongs
to and whether it is passive or active; the pipeline handles ordering,
concurrency, scope enforcement, and error isolation.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import CollectorResult, Provenance, ScanMode
from openrecon.core.net import DnsClient, HttpClient
from openrecon.scope import Scope


@dataclass
class CollectorContext:
    config: Config
    http: HttpClient
    dns: DnsClient
    scope: Scope | None = None
    progress: Callable[[str, str, dict[str, Any]], None] | None = None
    "Pipeline progress hook, so a chatty collector can show live sub-status."

    def in_scope(self, asset: str) -> bool:
        return self.scope is not None and self.scope.allows(asset)


# Pipeline stages, in execution order. This is the engine diagram in code form.
STAGES: list[str] = [
    "registration",   # WHOIS / RDAP - who owns this
    "dns",            # zone records
    "subdomains",     # CT logs, passive sources, resolution
    "certificates",   # TLS material
    "addresses",      # hostname -> IP
    "network",        # IP -> ASN / netblock / hosting
    "services",       # open ports and banners
    "fingerprint",    # what software is running
    "vulnerabilities",# CVE correlation
    "secrets",        # exposed secrets and leaked credentials
    "threat",         # reputation / threat intelligence
    "attack",         # app-layer crawling + active exploitation (bug bounty)
]

STAGE_INDEX = {name: i for i, name in enumerate(STAGES)}

class Collector(abc.ABC):
    """Base class every collector inherits."""

    name: ClassVar[str] = ""
    stage: ClassVar[str] = "dns"
    mode: ClassVar[ScanMode] = ScanMode.PASSIVE
    description: ClassVar[str] = ""
    requires_keys: ClassVar[tuple[str, ...]] = ()
    requires_bins: ClassVar[tuple[str, ...]] = ()
    "External binaries this collector shells out to (resolved via Config.tool)."

    def __init__(self, ctx: CollectorContext) -> None:
        self.ctx = ctx
        self.config = ctx.config
        self.http = ctx.http
        self.dns = ctx.dns

    # ------------------------------------------------------------------ hooks

    @abc.abstractmethod
    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        """Read the graph, return new intelligence. Must not mutate `graph`."""

    def available(self) -> tuple[bool, str]:
        """Whether this collector can run at all. Returns (ok, reason-if-not)."""
        if self.mode is ScanMode.ACTIVE and not self.config.active:
            return False, "active mode disabled (use --active with an authorization scope)"
        missing = [k for k in self.requires_keys if not self.config.key(k)]
        if missing:
            return False, f"missing API key(s): {', '.join(missing)}"
        missing_bins = [b for b in self.requires_bins if not self.config.tool(b)]
        if missing_bins:
            from openrecon.tooling import install_hint

            hints = "; ".join(f"{b} -> {install_hint(b)}" for b in missing_bins)
            return False, f"missing tool(s): {hints}"
        if not self.config.collector_allowed(self.name):
            return False, "disabled by configuration"
        return True, ""

    # ---------------------------------------------------------------- helpers

    def prov(self, source: str = "", confidence: float = 1.0) -> Provenance:
        return Provenance(collector=self.name, source=source, confidence=confidence)

    def progress(self, event: str, data: dict[str, Any] | None = None) -> None:
        """Emit a live sub-status (e.g. per-host progress) if a hook exists.

        Collectors that do one cheap batch (DNS, CT) never need this. Collectors
        that fire hundreds of requests - fingerprint probing N subdomains - use
        it so the UI shows progress instead of looking frozen for minutes.
        """
        if self.ctx.progress is not None:
            self.ctx.progress(event, self.name, data or {})

    def targets_in_scope(self, assets: list[str]) -> list[str]:
        """Filter an asset list through the authorization scope (active only)."""
        if self.mode is ScanMode.PASSIVE:
            return assets
        if self.ctx.scope is None:
            return []
        allowed, _ = self.ctx.scope.filter(assets)
        return allowed


# ------------------------------------------------------------------- registry

_REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a `name`")
    if cls.stage not in STAGE_INDEX:
        raise ValueError(f"{cls.__name__} has unknown stage {cls.stage!r}")
    _REGISTRY[cls.name] = cls
    return cls


def all_collectors() -> dict[str, type[Collector]]:
    return dict(_REGISTRY)


def collectors_for_stage(stage: str) -> list[type[Collector]]:
    return [c for c in _REGISTRY.values() if c.stage == stage]
