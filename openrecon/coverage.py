"""How much of the attack surface did this scan actually see?

Every attack surface tool presents its findings as if they were the surface.
None of them say what they missed - and a clean report from a scan that could
only see a third of the estate is worse than no report, because it manufactures
confidence that isn't there.

So openrecon measures itself. Two methods:

**Capture-recapture.** Borrowed from ecology, where you cannot count every fish
either. Tag a sample, return it, take a second sample, and the overlap tells you
the population size. Certificate transparency and DNS resolution are two
independent-ish nets over the same pond: if CT found 200 hostnames, brute force
found 60, and 40 appeared in both, there are roughly 200x60/40 = 300 out there
and you have seen two-thirds of them.

**Channel accounting.** For asset classes with only one possible source, coverage
is binary and honest about it: without an active scan or a Shodan key, your
visibility into exposed services is zero, and the right thing to print is zero -
not an empty list that reads like an all-clear.

The output qualifies the posture grade. An A earned over 30% of the surface is
not an A, and the report says so.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import NodeType

# Discovery channels per asset class: which collectors could contribute at all.
CHANNELS: dict[str, dict[str, str]] = {
    "subdomains": {
        "ct": "certificate transparency logs",
        "dnsbrute": "wordlist resolution",
        "axfr": "zone transfer",
        "securitytrails": "passive DNS",
    },
    "services": {
        "ports": "active TCP scan",
        "shodan": "internet-wide scan data",
    },
    "software": {
        "http": "HTTP fingerprinting",
        "ports": "service banners",
        "shodan": "internet-wide banner data",
    },
    "vulnerabilities": {
        "vulns": "CVE correlation from observed versions",
        "shodan": "vendor-attributed CVEs",
    },
    "dependencies": {
        "sbom": "client bundle and source map analysis",
        "github": "public lockfile audit",
    },
    "secrets": {
        "exposed_paths": "public path probing",
        "leaks": "breach corpora",
        "github": "public code search",
    },
    "reputation": {
        "urlhaus": "malware URL feed",
        "virustotal": "multi-engine reputation",
    },
}

# Weight of each class when combining into one confidence number. Subdomain
# discovery dominates: everything downstream is conditioned on it.
CLASS_WEIGHT: dict[str, float] = {
    "subdomains": 0.30,
    "services": 0.20,
    "dependencies": 0.15,
    "software": 0.12,
    "vulnerabilities": 0.10,
    "secrets": 0.08,
    "reputation": 0.05,
}

# Even a perfect bundle analysis only sees what ships to the browser. Build-time
# and server-side packages - where most reported CVEs live - never leave CI, so
# this class is capped well below 1.0 no matter how well the scan went.
DEPENDENCY_CEILING = 0.45

CONFIDENCE_LABELS = [
    (0.80, "high"),
    (0.55, "moderate"),
    (0.30, "low"),
    (0.0, "very low"),
]


@dataclass
class ClassCoverage:
    """What this scan could see of one class of asset."""

    name: str
    observed: int
    method: str
    coverage: float | None
    """0-1, or None when the class cannot be estimated at all."""
    estimated_total: int | None = None
    interval: tuple[int, int] | None = None
    channels_used: list[str] = field(default_factory=list)
    channels_missing: dict[str, str] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "observed": self.observed,
            "method": self.method,
            "coverage": None if self.coverage is None else round(self.coverage, 3),
            "estimated_total": self.estimated_total,
            "interval": list(self.interval) if self.interval else None,
            "channels_used": self.channels_used,
            "channels_missing": self.channels_missing,
            "note": self.note,
        }


@dataclass
class CoverageReport:
    classes: list[ClassCoverage] = field(default_factory=list)
    confidence: float = 0.0
    confidence_label: str = "very low"
    blind_spots: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    def qualified_grade(self, grade: str) -> str:
        """A grade is only as good as the coverage it was earned over."""
        if self.confidence >= 0.80:
            return grade
        return f"{grade}?"

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": round(self.confidence, 3),
            "confidence_label": self.confidence_label,
            "classes": [c.to_dict() for c in self.classes],
            "blind_spots": self.blind_spots,
            "caveats": self.caveats,
        }


# ------------------------------------------------------------- capture-recapture


def chapman_estimate(n1: int, n2: int, overlap: int) -> tuple[int, tuple[int, int]] | None:
    """Chapman's bias-corrected Lincoln-Petersen estimator with a 95% interval.

    Chapman rather than plain Lincoln-Petersen because the naive estimator is
    undefined when the samples do not overlap and badly biased when they barely
    do - which is exactly the regime a small estate lands in.
    """
    if n1 <= 0 or n2 <= 0:
        return None
    estimate = ((n1 + 1) * (n2 + 1) / (overlap + 1)) - 1
    variance = (
        (n1 + 1) * (n2 + 1) * (n1 - overlap) * (n2 - overlap)
        / ((overlap + 1) ** 2 * (overlap + 2))
    )
    spread = 1.96 * math.sqrt(max(variance, 0.0))
    low = max(int(round(estimate - spread)), max(n1, n2))
    high = int(round(estimate + spread))
    return int(round(estimate)), (low, max(high, low))


def _by_collector(graph: AttackSurfaceGraph, node_type: NodeType) -> dict[str, set[str]]:
    """Which collector saw which asset - the sample membership we need."""
    seen: dict[str, set[str]] = {}
    for node in graph.nodes_of(node_type):
        for provenance in node.provenance:
            seen.setdefault(provenance.collector, set()).add(node.id)
    return seen


# ------------------------------------------------------------------- assessment


def assess(graph: AttackSurfaceGraph) -> CoverageReport:
    report = CoverageReport()
    ran = set(graph.meta.collectors_run)
    skipped = graph.meta.collectors_skipped

    report.classes.append(_subdomain_coverage(graph, ran, skipped))
    report.classes.append(
        _channel_coverage(
            graph, "services", len(graph.nodes_of(NodeType.SERVICE)), ran, skipped,
            zero_note="no channel could see exposed services - the count above is not evidence "
            "that none exist",
        )
    )
    report.classes.append(
        _channel_coverage(
            graph, "software", len(graph.nodes_of(NodeType.TECHNOLOGY)), ran, skipped,
            zero_note="no software was fingerprinted, so no CVE correlation was possible",
        )
    )
    report.classes.append(_dependency_coverage(graph, ran, skipped))
    report.classes.append(_vulnerability_coverage(graph, ran, skipped))
    report.classes.append(
        _channel_coverage(
            graph, "secrets", len(graph.nodes_of(NodeType.SECRET, NodeType.CREDENTIAL_LEAK)),
            ran, skipped,
            zero_note="secret and credential exposure was never checked",
        )
    )
    report.classes.append(
        _channel_coverage(
            graph, "reputation", len(graph.nodes_of(NodeType.THREAT)), ran, skipped,
            zero_note="asset reputation was not checked",
        )
    )

    total_weight = sum(
        CLASS_WEIGHT[c.name] for c in report.classes if c.coverage is not None
    )
    if total_weight:
        report.confidence = sum(
            (c.coverage or 0) * CLASS_WEIGHT[c.name]
            for c in report.classes
            if c.coverage is not None
        ) / total_weight
    # Being refused by edge protection is not the same as finding nothing, and
    # the confidence figure has to carry that.
    blocked = sorted(
        {e.split(":")[1].strip().split()[0] for e in graph.meta.errors if e.startswith("blocked:")}
    )
    if blocked:
        report.confidence *= 0.7
        report.blind_spots.append(
            f"{len(blocked)} host(s) refused this scan (403/429): "
            + ", ".join(blocked[:5])
            + " - their results are absent because they were blocked, not because they are clean"
        )

    report.confidence_label = next(
        label for threshold, label in CONFIDENCE_LABELS if report.confidence >= threshold
    )

    for entry in report.classes:
        if entry.coverage is not None and entry.coverage < 0.5:
            missing = ", ".join(entry.channels_missing) or "no additional channel"
            report.blind_spots.append(
                f"{entry.name}: {int((entry.coverage) * 100)}% coverage"
                f" - {entry.note or 'limited by available channels'} ({missing})"
            )

    report.caveats = [
        "Coverage is an estimate of what this scan could observe, not a guarantee.",
        "A host behind a WAF or bot filter yields fewer findings, not fewer weaknesses. "
        "Where this scan was refused, coverage is reduced rather than the result reported "
        "as clean.",
        "Application dependency risk is largely invisible from outside. Even with bundle "
        "analysis this scan sees client-side packages only - never build-time or "
        "server-side ones. Pair it with a lockfile audit in CI; the two are complementary, "
        "not alternatives.",
        "Capture-recapture assumes the two sources sample independently. Certificate "
        "logs and wordlists both favour conventional names, so they overlap more than "
        "chance - which inflates the coverage figure. Read it as an optimistic bound.",
        "Channel accounting treats an unavailable source as zero visibility, never as "
        "an all-clear.",
    ]
    return report


def _subdomain_coverage(
    graph: AttackSurfaceGraph, ran: set[str], skipped: dict[str, str]
) -> ClassCoverage:
    observed = len(graph.nodes_of(NodeType.SUBDOMAIN))
    by_collector = _by_collector(graph, NodeType.SUBDOMAIN)
    channels = CHANNELS["subdomains"]
    used = [c for c in channels if c in ran]
    missing = {c: skipped.get(c, "not run") for c in channels if c not in ran}

    ct = by_collector.get("ct", set())
    brute = by_collector.get("dnsbrute", set())
    estimate = chapman_estimate(len(ct), len(brute), len(ct & brute)) if ct and brute else None

    if estimate and observed:
        total, interval = estimate
        total = max(total, observed)
        shared = len(ct & brute)
        note = f"CT saw {len(ct)}, resolution saw {len(brute)}, {shared} in both"
        if interval[1] > interval[0]:
            note += f"; population estimate {total} (95% CI {interval[0]}-{interval[1]})"
        if shared < 2:
            # With almost no overlap the estimator has very little to work with.
            note += " - the samples barely overlap, so this estimate is weak"
        return ClassCoverage(
            name="subdomains",
            observed=observed,
            method="capture-recapture",
            coverage=min(observed / max(total, 1), 1.0),
            estimated_total=total,
            interval=interval,
            channels_used=used,
            channels_missing=missing,
            note=note,
        )

    # Only one net was cast: the honest answer is that the population is unknown.
    coverage = 0.5 if len(used) >= 1 else 0.0
    return ClassCoverage(
        name="subdomains",
        observed=observed,
        method="channel-accounting",
        coverage=coverage,
        channels_used=used,
        channels_missing=missing,
        note=(
            "only one discovery channel produced results, so the true population "
            "cannot be estimated"
        ),
    )


def _channel_coverage(
    graph: AttackSurfaceGraph,
    name: str,
    observed: int,
    ran: set[str],
    skipped: dict[str, str],
    *,
    zero_note: str = "",
) -> ClassCoverage:
    channels = CHANNELS[name]
    used = [c for c in channels if c in ran]
    missing = {c: skipped.get(c, "not run") for c in channels if c not in ran}
    coverage = len(used) / len(channels) if channels else None
    return ClassCoverage(
        name=name,
        observed=observed,
        method="channel-accounting",
        coverage=coverage,
        channels_used=used,
        channels_missing=missing,
        note=zero_note if not used else f"{len(used)} of {len(channels)} channels contributed",
    )


def _dependency_coverage(
    graph: AttackSurfaceGraph, ran: set[str], skipped: dict[str, str]
) -> ClassCoverage:
    """Application dependencies: the class most likely to hold real CVEs.

    Reporting a clean bill of health here without saying what was inspected is
    how a scanner ends up contradicting the repository's own Dependabot alerts.
    """
    packages = [n for n in graph.nodes_of(NodeType.TECHNOLOGY) if n.attrs.get("ecosystem")]
    versioned = [n for n in packages if n.attrs.get("version")]
    channels = CHANNELS["dependencies"]
    used = [c for c in channels if c in ran]
    missing = {c: skipped.get(c, "not run") for c in channels if c not in ran}

    if not used:
        return ClassCoverage(
            name="dependencies",
            observed=0,
            method="channel-accounting",
            coverage=0.0,
            channels_used=used,
            channels_missing=missing,
            note=(
                "no dependency inspection ran - application packages are invisible to this "
                "scan. A clean result here means nothing was looked at, not that nothing is "
                "vulnerable. Run npm/pip audit or Dependabot in CI for this class"
            ),
        )

    versioned_ratio = len(versioned) / len(packages) if packages else 0.0
    return ClassCoverage(
        name="dependencies",
        observed=len(packages),
        method="client-bundle",
        coverage=round(DEPENDENCY_CEILING * versioned_ratio, 3),
        channels_used=used,
        channels_missing=missing,
        note=(
            f"{len(versioned)} of {len(packages)} client-side packages exposed a version. "
            "Only what ships to the browser is visible; build-time and server-side "
            "dependencies are out of reach of any external scan"
        ),
    )


def _vulnerability_coverage(
    graph: AttackSurfaceGraph, ran: set[str], skipped: dict[str, str]
) -> ClassCoverage:
    """CVE correlation is bounded by how much software carried a version string."""
    technologies = graph.nodes_of(NodeType.TECHNOLOGY)
    versioned = [n for n in technologies if n.attrs.get("version")]
    channels = CHANNELS["vulnerabilities"]
    used = [c for c in channels if c in ran]
    missing = {c: skipped.get(c, "not run") for c in channels if c not in ran}

    if not technologies:
        return ClassCoverage(
            name="vulnerabilities",
            observed=len(graph.nodes_of(NodeType.VULNERABILITY)),
            method="channel-accounting",
            coverage=0.0,
            channels_used=used,
            channels_missing=missing,
            note="no software was identified, so nothing could be correlated against CVE data",
        )

    ratio = len(versioned) / len(technologies)
    return ClassCoverage(
        name="vulnerabilities",
        observed=len(graph.nodes_of(NodeType.VULNERABILITY)),
        method="version-attribution",
        coverage=ratio * (1.0 if used else 0.0),
        channels_used=used,
        channels_missing=missing,
        note=(
            f"{len(versioned)} of {len(technologies)} identified components exposed a version; "
            "unversioned software cannot be matched to a CVE"
        ),
    )
