"""Authorization scope: the guard rail in front of every active collector.

openrecon is passive by default. Anything that sends traffic to infrastructure
owned by the target (port probes, TLS handshakes, HTTP fingerprinting, exposed
path checks) requires the operator to declare, in writing, that they are
authorized to test it. That declaration is a scope file.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SCOPE_TEMPLATE = """\
# openrecon authorization scope
#
# By committing this file you assert that you are authorized to perform active
# testing against the assets listed below. openrecon refuses to send any packet
# to a host that does not match `include` (or that matches `exclude`).

authorized_by: "your name / team"
engagement: "internal ASM monitoring"

include:
  - "{target}"
  - "*.{target}"

exclude:
  - "status.{target}"

# Networks you own. Active checks against an IP require it to be listed here or
# to be a resolved address of an in-scope hostname.
networks: []

# Set true only for internal ASM: allows RFC1918 and other reserved addresses.
allow_private: false
"""


class ScopeViolation(RuntimeError):
    """Raised when a collector tries to touch an out-of-scope asset."""


@dataclass
class Scope:
    """An allow-list of hostnames and networks for active collection."""

    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    authorized_by: str = ""
    engagement: str = ""
    allow_private: bool = False
    """Permit RFC1918 / reserved addresses. Only for internal ASM deployments."""
    # Hostnames confirmed in scope get their resolved IPs implicitly authorized.
    _derived_ips: set[str] = field(default_factory=set, repr=False)

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"scope file not found: {p}")
        raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not raw.get("include"):
            raise ValueError(f"scope file {p} has no `include` entries - nothing is authorized")
        return cls(
            include=[str(x).lower() for x in raw.get("include", [])],
            exclude=[str(x).lower() for x in raw.get("exclude", [])],
            networks=[str(x) for x in raw.get("networks", [])],
            authorized_by=str(raw.get("authorized_by", "")),
            engagement=str(raw.get("engagement", "")),
            allow_private=bool(raw.get("allow_private", False)),
        )

    @classmethod
    def implicit(cls, target: str) -> Scope:
        """The scope you get from `--active` without a scope file: apex + subdomains only."""
        t = target.lower().lstrip(".")
        return cls(include=[t, f"*.{t}"], authorized_by="(implicit --active)", engagement="ad-hoc")

    @classmethod
    def write_template(cls, path: str | Path, target: str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(SCOPE_TEMPLATE.format(target=target.lower()), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ checks

    def authorize_ip(self, ip: str) -> None:
        """Mark an IP as in-scope because an in-scope hostname resolves to it."""
        self._derived_ips.add(ip)

    def allows_host(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        if any(fnmatch.fnmatch(h, pat) for pat in self.exclude):
            return False
        return any(fnmatch.fnmatch(h, pat) for pat in self.include)

    def covered_by_network(self, ip: str) -> bool:
        """True only for an explicitly declared network - not for a derived address.

        Active checks against third-party infrastructure need a deliberate
        declaration, which is what `networks` is for.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self.networks:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def allows_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # Loopback, link-local and multicast are never scannable. Private and
        # reserved space (which in Python includes the RFC 5737 documentation
        # ranges) is opt-in, for teams running openrecon against internal estates.
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return False
        if not self.allow_private and (addr.is_private or addr.is_reserved):
            return False
        if ip in self._derived_ips:
            return True
        return self.covered_by_network(ip)

    def allows(self, asset: str) -> bool:
        try:
            ipaddress.ip_address(asset)
        except ValueError:
            return self.allows_host(asset)
        return self.allows_ip(asset)

    def require(self, asset: str) -> None:
        if not self.allows(asset):
            raise ScopeViolation(
                f"{asset!r} is not covered by the authorization scope "
                f"(authorized_by={self.authorized_by or 'unset'!r}). "
                "Add it to `include`/`networks`, or drop --active."
            )

    def filter(self, assets: list[str]) -> tuple[list[str], list[str]]:
        """Split assets into (allowed, refused)."""
        allowed, refused = [], []
        for a in assets:
            (allowed if self.allows(a) else refused).append(a)
        return allowed, refused

    def summary(self) -> str:
        private = " +private" if self.allow_private else ""
        return (
            f"include={len(self.include)} exclude={len(self.exclude)} "
            f"networks={len(self.networks)}{private} by={self.authorized_by or 'unset'}"
        )
