from __future__ import annotations

from openrecon.core.models import Finding, Node, NodeType, Severity
from openrecon.risk.engine import RiskEngine, attack_paths


def test_kev_outranks_a_plain_critical(graph):
    engine = RiskEngine()
    engine.score(graph)
    kev = next(f for f in graph.findings.values() if f.kev)
    caa = next(f for f in graph.findings.values() if f.category == "certificate-governance")
    assert kev.risk_score > caa.risk_score
    assert kev.risk_score >= 60


def test_asset_risk_aggregates_its_findings(graph):
    RiskEngine().score(graph)
    dev = graph.nodes[Node.make_id(NodeType.SUBDOMAIN, "dev.example.com")]
    api = graph.nodes[Node.make_id(NodeType.SUBDOMAIN, "api.example.com")]
    assert dev.risk_score > api.risk_score
    assert dev.risk_severity in (Severity.HIGH, Severity.CRITICAL)


def test_posture_summary_shape(graph):
    summary = RiskEngine().score(graph)
    assert 0 <= summary["posture_score"] <= 100
    assert summary["grade"] in list("ABCDF")
    assert summary["finding_counts"]["critical"] == 2
    assert summary["kev_findings"] == 1
    assert summary["top_findings"][0]["score"] >= summary["top_findings"][-1]["score"]


def test_clean_graph_scores_an_a():
    from openrecon.core.graph import AttackSurfaceGraph

    g = AttackSurfaceGraph.seed("clean.example")
    summary = RiskEngine().score(g)
    assert summary["grade"] == "A"
    assert summary["posture_score"] == 100.0


def test_severity_bands_have_diminishing_returns():
    from openrecon.core.graph import AttackSurfaceGraph

    g = AttackSurfaceGraph.seed("noisy.example")
    apex = Node.make_id(NodeType.DOMAIN, "noisy.example")
    for i in range(40):
        g.add_finding(
            Finding(title=f"low {i}", severity=Severity.LOW, category="web-hardening",
                    node_ids=[apex])
        )
    low_only = RiskEngine().score(g)["posture_score"]

    g2 = AttackSurfaceGraph.seed("bad.example")
    apex2 = Node.make_id(NodeType.DOMAIN, "bad.example")
    g2.add_finding(
        Finding(title="crit", severity=Severity.CRITICAL, category="known-vulnerability",
                node_ids=[apex2], kev=True)
    )
    one_critical = RiskEngine().score(g2)["posture_score"]
    assert one_critical < low_only, "one KEV critical must outweigh a tail of low findings"


def test_attack_paths_reach_terminal_nodes(graph):
    RiskEngine().score(graph)
    paths = attack_paths(graph)
    assert paths, "expected at least one apex -> ... -> vulnerability path"
    labels = [[n["label"] for n in p["nodes"]] for p in paths]
    assert any(
        chain[0] == "example.com" and chain[-1] in ("CVE-2021-22205", "dev.example.com/.env")
        for chain in labels
    )
    assert paths[0]["score"] >= paths[-1]["score"]


def test_blast_radius_raises_shared_infrastructure(graph):
    engine = RiskEngine()
    blast = engine._blast_radius(graph)
    ip = Node.make_id(NodeType.IP, "93.184.216.34")
    assert blast[ip] >= 2  # both subdomains resolve to it
