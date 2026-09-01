"""Systemic pattern mining: find the broken process, not the broken host.

A findings list says "nine hosts are missing HSTS" and hands you nine tickets.
But if all nine sit behind the same platform, or were all provisioned from the
same template, there is one defect and eight duplicates - and the fix is a
config change, not nine tickets.

This module groups assets along the dimensions that correspond to real process
boundaries (who hosts it, what runs on it, who issued its certificate, what the
name says it is) and looks for findings that track a cohort rather than an
asset. When one does, the finding is not really about the hosts; it is about
whatever produced them.

The inverse matters too: a finding that appears in *every* cohort is not a
platform defect, it is a missing organizational standard.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import EdgeType, Node, NodeType, Severity

# A cohort must be at least this large before "they all share it" means anything.
MIN_COHORT = 3
# Fraction of a cohort that must carry the finding for it to read as systemic.
SYSTEMIC_RATIO = 0.8
# A finding present in this fraction of all assets is an org-wide gap, not a
# cohort one. Not 1.0: the apex often has no web finding of its own, and one
# unaffected host should not stop a whole-estate pattern from being named.
UNIVERSAL_RATIO = 0.85

# A cohort has to account for most of the finding before it counts as the cause.
MIN_EXPLANATORY_SCORE = 0.4

# How to phrase the cause and the fix for each grouping dimension.
DIMENSION_FRAMING: dict[str, tuple[str, str]] = {
    "platform": (
        "every affected host is served by {cohort}",
        "This is one platform setting, not {n} host fixes. Change it once in the "
        "{cohort} project configuration.",
    ),
    "provider": (
        "every affected host is hosted on {cohort}",
        "Fix the {cohort} account baseline - a security group, load balancer policy, "
        "or image template - rather than each host.",
    ),
    "software": (
        "every affected host runs {cohort}",
        "The default configuration of {cohort} is the defect. Fix the shared "
        "config or base image and redeploy.",
    ),
    "issuer": (
        "every affected certificate was issued by {cohort}",
        "The certificate pipeline using {cohort} is producing these consistently. "
        "Fix the issuance automation.",
    ),
    "environment": (
        "every affected host is {cohort}",
        "Your {cohort} provisioning path omits this control. Fix the template or "
        "pipeline that creates {cohort} hosts.",
    ),
}


@dataclass
class SystemicPattern:
    """A finding that belongs to a cohort rather than to its assets."""

    id: str
    title: str
    category: str
    dimension: str
    cohort: str
    affected: list[str]
    cohort_size: int
    ratio: float
    severity: str
    inference: str
    remediation: str
    universal: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def duplicates_saved(self) -> int:
        """Tickets this collapses into one."""
        return max(len(self.affected) - 1, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "dimension": self.dimension,
            "cohort": self.cohort,
            "affected": self.affected,
            "cohort_size": self.cohort_size,
            "ratio": round(self.ratio, 3),
            "severity": self.severity,
            "inference": self.inference,
            "remediation": self.remediation,
            "universal": self.universal,
            "duplicates_saved": self.duplicates_saved,
            "evidence": self.evidence,
        }


def _cohorts(graph: AttackSurfaceGraph) -> dict[str, dict[str, set[str]]]:
    """Group host-like assets along each process dimension."""
    groups: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    hosts = graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)

    for host in hosts:
        # Managed platform, read off the addresses the host resolves to.
        for address in graph.neighbors(host.id, edge_types=[EdgeType.RESOLVES_TO]):
            platform = address.attrs.get("managed_by")
            if platform:
                groups["platform"][str(platform)].add(host.id)
            asn = address.attrs.get("asn")
            if asn:
                asn_node = graph.nodes.get(Node.make_id(NodeType.ASN, str(asn)))
                provider = (asn_node.attrs.get("provider") if asn_node else None) or (
                    asn_node.attrs.get("organization") if asn_node else None
                )
                if provider:
                    groups["provider"][str(provider)].add(host.id)

        for tech in graph.neighbors(host.id, edge_types=[EdgeType.RUNS]):
            product = tech.attrs.get("product")
            if product:
                groups["software"][str(product)].add(host.id)

        for cert in graph.neighbors(host.id, edge_types=[EdgeType.SECURED_BY]):
            issuer = cert.attrs.get("issuer")
            if issuer:
                groups["issuer"][_short_issuer(str(issuer))].add(host.id)

        for tag in ("non-production", "sensitive-service"):
            if tag in host.tags:
                groups["environment"][tag].add(host.id)

    return {dim: dict(values) for dim, values in groups.items()}


def _short_issuer(issuer: str) -> str:
    """RFC4514 issuer strings are unreadable; keep the organization.

    O identifies the CA ("Let's Encrypt"); CN is an intermediate label that
    rotates ("R10", "WR2") and means nothing to a reader.
    """
    fields: dict[str, str] = {}
    for part in issuer.split(","):
        key, _, value = part.strip().partition("=")
        if key and value:
            fields.setdefault(key.strip().upper(), value.strip())
    return fields.get("O") or fields.get("CN") or issuer[:40]


def mine(graph: AttackSurfaceGraph) -> list[SystemicPattern]:
    """Find findings that track a cohort rather than an asset."""
    hosts = {n.id for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)}
    if len(hosts) < MIN_COHORT:
        return []

    # category -> hosts carrying a finding of that category
    by_category: dict[str, set[str]] = defaultdict(set)
    representative: dict[str, Any] = {}
    for finding in graph.findings.values():
        touched = {n for n in finding.node_ids if n in hosts}
        if not touched:
            continue
        by_category[finding.category] |= touched
        representative.setdefault(finding.category, finding)

    cohorts = _cohorts(graph)
    patterns: list[SystemicPattern] = []
    claimed: set[tuple[str, str]] = set()

    for category, affected in sorted(by_category.items()):
        if len(affected) < MIN_COHORT:
            continue
        finding = representative[category]

        # Organization-wide first: if nearly every host has it, no cohort explains it.
        if len(affected) / len(hosts) >= UNIVERSAL_RATIO and len(hosts) >= MIN_COHORT:
            patterns.append(
                SystemicPattern(
                    id=f"universal:{category}",
                    title=f"{_phrase(category)} affects the whole estate",
                    category=category,
                    dimension="organization",
                    cohort="every host",
                    affected=sorted(graph.nodes[h].label for h in affected),
                    cohort_size=len(hosts),
                    ratio=len(affected) / len(hosts),
                    severity=finding.severity.value,
                    inference=(
                        f"{len(affected)} of {len(hosts)} hosts share this, across every "
                        "platform and provider. No single team or template explains it."
                    ),
                    remediation=(
                        "Treat this as a missing organizational standard rather than a set of "
                        "host defects: define it once, then enforce it in CI or at the edge."
                    ),
                    universal=True,
                    evidence={"affected": len(affected), "total_hosts": len(hosts)},
                )
            )
            continue

        # A finding can be "explained" by several overlapping cohorts - hosts on
        # AWS are also hosts running Vercel are also hosts with a Let's Encrypt
        # certificate. Emitting all of them is four tickets again. Keep the
        # single most explanatory cohort: the one that covers the most affected
        # hosts while leaving the fewest unexplained.
        best: tuple[float, str, str, set[str]] | None = None
        for dimension, values in cohorts.items():
            for cohort, members in values.items():
                if len(members) < MIN_COHORT:
                    continue
                hit = members & affected
                ratio = len(hit) / len(members)
                if ratio < SYSTEMIC_RATIO or len(hit) < MIN_COHORT:
                    continue
                outside = affected - members
                if len(outside) >= len(hit):
                    continue  # explains half or less: not a cause, a coincidence
                # Explanatory power: how much of the finding this cohort accounts
                # for, penalised by what it leaves outside.
                score = len(hit) / len(affected) - (len(outside) / max(len(affected), 1)) * 0.5
                if score < MIN_EXPLANATORY_SCORE:
                    continue
                if best is None or score > best[0]:
                    best = (score, dimension, cohort, hit)

        if best is not None:
            _score, dimension, cohort, hit = best
            members = cohorts[dimension][cohort]
            outside = affected - members
            claimed.add((category, cohort))
            cause, fix = DIMENSION_FRAMING.get(
                dimension,
                ("every affected host shares {cohort}", "Fix the shared cause once."),
            )
            patterns.append(
                SystemicPattern(
                    id=f"{dimension}:{cohort}:{category}",
                    title=f"{_phrase(category)} across all {cohort} hosts",
                    category=category,
                    dimension=dimension,
                    cohort=cohort,
                    affected=sorted(graph.nodes[h].label for h in hit),
                    cohort_size=len(members),
                    ratio=len(hit) / len(members),
                    severity=finding.severity.value,
                    inference=(
                        f"{len(hit)} of {len(members)} - "
                        + cause.format(cohort=cohort, n=len(hit))
                        + (
                            f", and only {len(outside)} host(s) elsewhere are affected."
                            if outside
                            else ", and no host outside the group is affected."
                        )
                    ),
                    remediation=fix.format(cohort=cohort, n=len(hit)),
                    evidence={
                        "cohort_size": len(members),
                        "affected_in_cohort": len(hit),
                        "affected_outside": len(outside),
                        "alternative_dimensions": sorted(
                            d for d in cohorts if d != dimension
                        ),
                    },
                )
            )

    patterns.sort(
        key=lambda p: (
            -Severity(p.severity).weight,
            -p.duplicates_saved,
        )
    )
    return patterns


def _phrase(category: str) -> str:
    return category.replace("-", " ").capitalize()
