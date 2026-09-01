"""A synthetic attack surface, so tests never touch the network."""

from __future__ import annotations

import pytest

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    Provenance,
    Severity,
)


def _prov(collector: str = "test") -> Provenance:
    return Provenance(collector=collector, source="fixture")


@pytest.fixture
def graph() -> AttackSurfaceGraph:
    """example.com -> dev.example.com -> 93.184.216.34 -> gitlab:14.2.1 -> CVE + secret."""
    g = AttackSurfaceGraph.seed("example.com", mode="active", version="test")
    apex = Node.make_id(NodeType.DOMAIN, "example.com")

    dev = g.add_node(
        Node.create(
            NodeType.SUBDOMAIN,
            "dev.example.com",
            provenance=_prov("ct"),
            tags={"non-production", "sensitive-service", "live"},
        )
    )
    api = g.add_node(Node.create(NodeType.SUBDOMAIN, "api.example.com", provenance=_prov("ct")))
    ip = g.add_node(Node.create(NodeType.IP, "93.184.216.34", provenance=_prov("resolve")))
    svc = g.add_node(
        Node.create(
            NodeType.SERVICE,
            "93.184.216.34:9200",
            label="elasticsearch/9200",
            attrs={"ip": "93.184.216.34", "port": 9200, "service": "elasticsearch"},
            provenance=_prov("ports"),
            tags={"exposed", "unauthenticated-risk"},
        )
    )
    tech = g.add_node(
        Node.create(
            NodeType.TECHNOLOGY,
            "gitlab:14.2.1",
            attrs={"product": "gitlab", "version": "14.2.1"},
            provenance=_prov("http"),
        )
    )
    vuln = g.add_node(
        Node.create(
            NodeType.VULNERABILITY,
            "CVE-2021-22205",
            attrs={"cve": "CVE-2021-22205", "cvss": 10.0, "kev": True, "epss": 0.94},
            provenance=_prov("vulns"),
            tags={"kev"},
        )
    )
    secret = g.add_node(
        Node.create(
            NodeType.SECRET,
            "dev.example.com/.env",
            provenance=_prov("exposed_paths"),
            tags={"exposed", "suspicious"},
        )
    )

    for src, dst, kind in [
        (apex, dev.id, EdgeType.HAS_SUBDOMAIN),
        (apex, api.id, EdgeType.HAS_SUBDOMAIN),
        (dev.id, ip.id, EdgeType.RESOLVES_TO),
        (api.id, ip.id, EdgeType.RESOLVES_TO),
        (ip.id, svc.id, EdgeType.EXPOSES),
        (dev.id, tech.id, EdgeType.RUNS),
        (tech.id, vuln.id, EdgeType.VULNERABLE_TO),
        (dev.id, secret.id, EdgeType.LEAKS),
    ]:
        g.add_edge(Edge(source=src, target=dst, type=kind, provenance=[_prov()]))

    g.add_finding(
        Finding(
            title="CVE-2021-22205 affects gitlab 14.2.1",
            severity=Severity.CRITICAL,
            category="known-vulnerability",
            node_ids=[vuln.id, tech.id],
            cve="CVE-2021-22205",
            cvss=10.0,
            epss=0.94,
            kev=True,
            collector="vulns",
        )
    )
    g.add_finding(
        Finding(
            title="elasticsearch exposed to the internet on 93.184.216.34:9200",
            severity=Severity.CRITICAL,
            category="exposed-service",
            node_ids=[svc.id, ip.id],
            collector="ports",
        )
    )
    g.add_finding(
        Finding(
            title="Exposed application environment file at dev.example.com/.env",
            severity=Severity.HIGH,
            category="secret-exposure",
            node_ids=[secret.id, dev.id],
            collector="exposed_paths",
        )
    )
    g.add_finding(
        Finding(
            title="No CAA record on example.com",
            severity=Severity.LOW,
            category="certificate-governance",
            node_ids=[apex],
            collector="dns",
        )
    )
    return g
