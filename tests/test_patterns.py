"""Systemic pattern mining: one cause behind many symptoms."""

from __future__ import annotations

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Edge, EdgeType, Finding, Node, NodeType, Severity
from openrecon.risk.patterns import _short_issuer, mine


def _estate(platform_hosts: int, other_hosts: int) -> AttackSurfaceGraph:
    g = AttackSurfaceGraph.seed("example.com")
    for i in range(platform_hosts):
        host = g.add_node(Node.create(NodeType.SUBDOMAIN, f"p{i}.example.com"))
        address = g.add_node(
            Node.create(NodeType.IP, f"76.76.21.{i}", attrs={"managed_by": "Vercel"})
        )
        g.add_edge(Edge(source=host.id, target=address.id, type=EdgeType.RESOLVES_TO))
    for i in range(other_hosts):
        host = g.add_node(Node.create(NodeType.SUBDOMAIN, f"o{i}.example.com"))
        address = g.add_node(Node.create(NodeType.IP, f"93.184.216.{i}"))
        g.add_edge(Edge(source=host.id, target=address.id, type=EdgeType.RESOLVES_TO))
    return g


def _add_finding(g: AttackSurfaceGraph, host: str, category: str = "web-hardening") -> None:
    g.add_finding(
        Finding(
            title=f"Missing security headers on {host}",
            severity=Severity.LOW,
            category=category,
            node_ids=[Node.make_id(NodeType.SUBDOMAIN, host)],
        )
    )


def test_a_finding_confined_to_one_platform_is_reported_as_a_platform_defect():
    g = _estate(platform_hosts=5, other_hosts=4)
    for i in range(5):
        _add_finding(g, f"p{i}.example.com")

    patterns = mine(g)
    assert patterns
    top = patterns[0]
    assert top.cohort == "Vercel"
    assert top.dimension == "platform"
    assert top.duplicates_saved == 4
    assert "one platform setting" in top.remediation


def test_one_explanation_per_finding_not_one_per_overlapping_cohort():
    """AWS, Vercel and the certificate issuer all "explain" the same hosts."""
    g = _estate(platform_hosts=5, other_hosts=3)
    for i in range(5):
        host_id = Node.make_id(NodeType.SUBDOMAIN, f"p{i}.example.com")
        tech = g.add_node(
            Node.create(NodeType.TECHNOLOGY, "vercel:1", attrs={"product": "vercel"})
        )
        g.add_edge(Edge(source=host_id, target=tech.id, type=EdgeType.RUNS))
        _add_finding(g, f"p{i}.example.com")

    categories = [p.category for p in mine(g)]
    assert len(categories) == len(set(categories)), "one pattern per category, not per cohort"


def test_a_finding_spread_across_every_host_is_an_organizational_gap():
    g = _estate(platform_hosts=4, other_hosts=4)
    for prefix in ("p", "o"):
        for i in range(4):
            _add_finding(g, f"{prefix}{i}.example.com")

    patterns = mine(g)
    assert patterns and patterns[0].universal
    assert patterns[0].dimension == "organization"
    assert "organizational standard" in patterns[0].remediation


def test_a_cohort_that_does_not_explain_the_finding_is_not_reported():
    """Most affected hosts sit outside the cohort, so the cohort is not the cause."""
    g = _estate(platform_hosts=3, other_hosts=6)
    for i in range(3):
        _add_finding(g, f"p{i}.example.com")
    for i in range(5):
        _add_finding(g, f"o{i}.example.com")

    assert all(p.cohort != "Vercel" for p in mine(g))


def test_scattered_findings_produce_no_pattern():
    g = _estate(platform_hosts=4, other_hosts=4)
    _add_finding(g, "p0.example.com")
    _add_finding(g, "o0.example.com")
    assert mine(g) == []


def test_a_tiny_estate_is_not_mined():
    g = _estate(platform_hosts=2, other_hosts=0)
    _add_finding(g, "p0.example.com")
    _add_finding(g, "p1.example.com")
    assert mine(g) == []


def test_issuer_names_use_the_organization_not_the_rotating_intermediate():
    assert _short_issuer("C=US, O=Let's Encrypt, CN=R10") == "Let's Encrypt"
    assert _short_issuer("CN=WR2, O=Google Trust Services, C=US") == "Google Trust Services"
    assert _short_issuer("CN=self-signed") == "self-signed"


def test_patterns_serialize_and_rank_by_severity_then_savings():
    g = _estate(platform_hosts=5, other_hosts=3)
    for i in range(5):
        _add_finding(g, f"p{i}.example.com", category="web-hardening")
        g.add_finding(
            Finding(
                title=f"Expired certificate on p{i}.example.com",
                severity=Severity.HIGH,
                category="tls",
                node_ids=[Node.make_id(NodeType.SUBDOMAIN, f"p{i}.example.com")],
            )
        )
    import json

    patterns = mine(g)
    json.dumps([p.to_dict() for p in patterns])
    assert patterns[0].severity == "high", "the worse pattern leads"
