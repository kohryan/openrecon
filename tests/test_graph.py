from __future__ import annotations

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Edge, EdgeType, Node, NodeType, Provenance


def test_seed_creates_apex_domain():
    g = AttackSurfaceGraph.seed("example.com")
    assert g.meta.target == "example.com"
    assert Node.make_id(NodeType.DOMAIN, "example.com") in g.nodes


def test_node_ids_are_case_insensitive():
    assert Node.make_id(NodeType.SUBDOMAIN, "API.Example.COM") == Node.make_id(
        NodeType.SUBDOMAIN, "api.example.com"
    )


def test_repeated_observations_merge_instead_of_duplicating(graph):
    before = len(graph.nodes)
    graph.add_node(
        Node.create(
            NodeType.SUBDOMAIN,
            "dev.example.com",
            attrs={"http_status": 200},
            provenance=Provenance(collector="http"),
            tags={"web"},
        )
    )
    node = graph.nodes[Node.make_id(NodeType.SUBDOMAIN, "dev.example.com")]
    assert len(graph.nodes) == before
    assert node.attrs["http_status"] == 200
    assert "web" in node.tags and "non-production" in node.tags
    assert {"ct", "http"} <= set(node.sources)


def test_merge_unions_list_attributes():
    a = Node.create(NodeType.IP, "1.2.3.4", attrs={"ports": [80]})
    a.merge(Node.create(NodeType.IP, "1.2.3.4", attrs={"ports": [443, 80]}))
    assert a.attrs["ports"] == [80, 443]


def test_absorb_drops_dangling_edges(graph):
    from openrecon.core.models import CollectorResult

    result = CollectorResult(
        edges=[
            Edge(
                source=Node.make_id(NodeType.DOMAIN, "example.com"),
                target="subdomain:ghost.example.com",
                type=EdgeType.HAS_SUBDOMAIN,
            )
        ]
    )
    before = len(graph.edges)
    graph.absorb(result)
    assert len(graph.edges) == before


def test_exposure_counts_match_the_fixture(graph):
    e = graph.exposure()
    assert e.domains == 1
    assert e.subdomains == 2
    assert e.exposed_services == 1
    assert e.known_vulnerabilities == 1
    assert e.secrets_detected == 1
    assert e.suspicious_assets == 1  # dev/.env is tagged suspicious


def test_roundtrip_serialization(graph, tmp_path):
    path = graph.save(tmp_path / "g.json")
    restored = AttackSurfaceGraph.load(path)
    assert restored.nodes.keys() == graph.nodes.keys()
    assert restored.findings.keys() == graph.findings.keys()
    assert restored.meta.target == graph.meta.target


def test_diff_reports_new_and_removed(graph):
    previous = AttackSurfaceGraph.seed("example.com")
    delta = graph.diff(previous)
    assert "dev.example.com" in delta["new_assets"]
    assert delta["removed_assets"] == []
    assert any("CVE-2021-22205" in t for t in delta["new_findings"])


def test_neighbors_respects_edge_type(graph):
    apex = Node.make_id(NodeType.DOMAIN, "example.com")
    subs = graph.neighbors(apex, edge_types=[EdgeType.HAS_SUBDOMAIN])
    assert {n.label for n in subs} == {"dev.example.com", "api.example.com"}


def test_findings_grouped_by_category(graph):
    groups = graph.findings_by_category()
    # Every finding lands in exactly one type bucket, nothing lost.
    assert sum(len(v) for v in groups.values()) == len(graph.findings)
    assert set(groups) == {f.category for f in graph.findings.values()}
    # Groups are ordered by their most severe finding first: the fixture has two
    # critical categories (known-vulnerability, exposed-service) before the
    # high (secret-exposure) and the low (certificate-governance).
    order = list(groups)
    assert order[-1] == "certificate-governance"
    assert order.index("secret-exposure") < order.index("certificate-governance")
    # Within a group, findings are ordered by risk score.
    for items in groups.values():
        scores = [f.risk_score for f in items]
        assert scores == sorted(scores, reverse=True)
