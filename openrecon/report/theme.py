"""Design tokens for every surface openrecon prints.

One place decides what "critical" looks like, what a checkmark is, and how a
risk score maps to a colour - so the live scan view, the results screen, and the
HTML report never drift apart.
"""

from __future__ import annotations

import os
import sys

from rich.text import Text

from openrecon.core.models import Severity

# --------------------------------------------------------------------- palette

ACCENT = "#22d3ee"
MUTED = "grey50"
FAINT = "grey35"

SEVERITY_COLOR: dict[str, str] = {
    "critical": "#ef4444",
    "high": "#fb7185",
    "medium": "#fbbf24",
    "low": "#38bdf8",
    "info": "#94a3b8",
}

SEVERITY_BADGE: dict[str, str] = {
    "critical": "bold white on #b91c1c",
    "high": "bold #fb7185",
    "medium": "bold #fbbf24",
    "low": "#38bdf8",
    "info": "grey50",
}

GRADE_COLOR: dict[str, str] = {
    "A": "#34d399",
    "B": "#a3e635",
    "C": "#fbbf24",
    "D": "#fb923c",
    "F": "#ef4444",
}

NODE_COLOR: dict[str, str] = {
    "domain": "#22d3ee",
    "subdomain": "#60a5fa",
    "ip": "#a78bfa",
    "netblock": "#818cf8",
    "asn": "#f472b6",
    "certificate": "#34d399",
    "service": "#fbbf24",
    "technology": "#fb923c",
    "vulnerability": "#ef4444",
    "secret": "#e11d48",
    "credential_leak": "#be123c",
    "api": "#f59e0b",
    "organization": "grey50",
    "nameserver": "grey50",
    "mailserver": "grey50",
    "cloud_resource": "#2dd4bf",
    "threat": "#dc2626",
}

# API "kind" palette: collectors that discover a specific API surface can tag a
# node with ``attrs.kind`` (e.g. "graphql", "graphql-introspectable", "openapi",
# "grpc") to claim a distinct colour + glyph in the graph. This is the general
# hook - it is not GraphQL-specific. Unknown kinds fall back to the ``api`` colour.
NODE_KIND_COLOR: dict[str, str] = {
    "graphql": "#f472b6",
    "graphql-introspectable": "#ef4444",
    "openapi": "#a3e635",
    "swagger": "#a3e635",
    "grpc": "#c084fc",
    "api-root": "#fb923c",
    "re-sourcemap": "#fb7185",
    "re-manifest": "#f59e0b",
    "re-spec": "#a3e635",
}

NODE_KIND_GLYPH: dict[str, str] = {
    "graphql": "⬡",
    "graphql-introspectable": "⬢",
    "openapi": "✦",
    "swagger": "✦",
    "grpc": "▣",
    "api-root": "⌘",
}


# ----------------------------------------------------------------------- glyphs


def _unicode_ok() -> bool:
    """Windows consoles and some CI logs mangle box glyphs - fall back to ASCII."""
    if os.environ.get("OPENRECON_ASCII"):
        return False
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in encoding


class Glyphs:
    def __init__(self, unicode: bool | None = None) -> None:
        rich = _unicode_ok() if unicode is None else unicode
        self.ok = "✔" if rich else "+"
        self.fail = "✘" if rich else "x"
        self.skip = "–" if rich else "-"
        self.pending = "·" if rich else "."
        self.arrow = "→" if rich else "->"
        self.bullet = "•" if rich else "*"
        self.warn = "!"
        self.bar_full = "█" if rich else "#"
        self.bar_half = "▌" if rich else "="
        self.bar_empty = "░" if rich else "."
        self.corner = "└" if rich else "`"
        self.tee = "├" if rich else "|"
        self.pipe = "│" if rich else "|"


GLYPHS = Glyphs()

# Compact type markers used in the attack surface tree.
NODE_MARK: dict[str, str] = {
    "domain": "@",
    "subdomain": "",
    "ip": "#",
    "netblock": "/",
    "asn": "AS",
    "certificate": "%",
    "service": ">",
    "technology": "*",
    "vulnerability": "!",
    "secret": "$",
    "credential_leak": "$",
    "api": "{}",
    "threat": "!!",
    "nameserver": "ns",
    "mailserver": "mx",
    "cloud_resource": "~",
    "organization": "org",
}


# ---------------------------------------------------------------------- helpers


def risk_style(score: float) -> str:
    if score >= 70:
        return SEVERITY_COLOR["critical"]
    if score >= 45:
        return SEVERITY_COLOR["high"]
    if score >= 25:
        return SEVERITY_COLOR["medium"]
    if score > 0:
        return SEVERITY_COLOR["low"]
    return "white"


def severity_badge(severity: str | Severity) -> Text:
    value = severity.value if isinstance(severity, Severity) else severity
    return Text(f" {value.upper():<8}", style=SEVERITY_BADGE.get(value, "grey50"))


def grade_badge(grade: str) -> Text:
    return Text(f" {grade} ", style=f"bold black on {GRADE_COLOR.get(grade, 'grey50')}")


def meter(value: float, total: float, width: int = 24, color: str = ACCENT) -> Text:
    """A proportional bar. Renders as text, so it survives being piped to a file."""
    if total <= 0:
        return Text(GLYPHS.bar_empty * width, style=FAINT)
    filled = max(0, min(width, round(width * value / total)))
    bar = Text()
    bar.append(GLYPHS.bar_full * filled, style=color)
    bar.append(GLYPHS.bar_empty * (width - filled), style=FAINT)
    return bar


def severity_distribution(counts: dict[str, int], width: int = 30) -> Text:
    """One stacked bar showing the shape of the finding set at a glance."""
    total = sum(counts.get(s.value, 0) for s in Severity)
    if not total:
        return Text(GLYPHS.bar_empty * width, style=FAINT)

    bar = Text()
    used = 0
    order = ["critical", "high", "medium", "low", "info"]
    for i, name in enumerate(order):
        n = counts.get(name, 0)
        if not n:
            continue
        # Give every present severity at least one cell, and let the last one
        # absorb the rounding remainder so the bar is always exactly `width`.
        remaining_names = [s for s in order[i + 1 :] if counts.get(s, 0)]
        size = width - used if not remaining_names else max(1, round(width * n / total))
        size = min(size, width - used - len(remaining_names))
        bar.append(GLYPHS.bar_full * max(size, 1), style=SEVERITY_COLOR[name])
        used += max(size, 1)
    if used < width:
        bar.append(GLYPHS.bar_empty * (width - used), style=FAINT)
    return bar


def humanize_duration(seconds: float) -> str:
    if seconds < 1:
        # Cached stages finish in milliseconds; "0.0s" reads like a bug.
        return f"{seconds:.2f}s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes}m{rest:02d}s"


def plural(n: int, singular: str, plural_form: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural_form or singular + 's')}"
