"""Adversary simulation: the cost model, the pathfinder, and the counterfactuals.

The point of these tests is the claim the feature makes - that ranking by
attacker cost gives different, better answers than ranking by severity - so
several of them assert exactly that divergence.
"""

from __future__ import annotations

import pytest

from openrecon.adversary import simulate
from openrecon.adversary.model import (
    Capability,
    ObjectiveKind,
    TechniqueCatalog,
    objectives_for,
)
from openrecon.adversary.simulator import UNREACHABLE
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    Severity,
)
from openrecon.risk.engine import RiskEngine

# ------------------------------------------------------------------ cost model


def test_kev_is_cheaper_than_a_higher_scoring_theoretical_cve():
    """The whole thesis: exploitability beats severity."""
    catalog = TechniqueCatalog()
    kev = catalog.for_finding(
        Finding(title="a", severity=Severity.HIGH, category="known-vulnerability",
                cve="CVE-1", cvss=7.5, kev=True)
    )
    theoretical = catalog.for_finding(
        Finding(title="b", severity=Severity.CRITICAL, category="known-vulnerability",
                cve="CVE-2", cvss=10.0, kev=False, epss=0.001)
    )
    assert kev.effective_hours < theoretical.effective_hours
    assert kev.capability < theoretical.capability


def test_very_high_epss_is_priced_like_a_kev_listing():
    """KEV is curated and lags; EPSS above 50% says the same thing sooner."""
    catalog = TechniqueCatalog()
    weaponised = catalog.for_finding(
        Finding(title="a", severity=Severity.CRITICAL, category="known-vulnerability",
                cve="CVE-1", epss=0.99)
    )
    emerging = catalog.for_finding(
        Finding(title="b", severity=Severity.CRITICAL, category="known-vulnerability",
                cve="CVE-2", epss=0.15)
    )
    assert weaponised.id == "known-vulnerability/weaponised"
    assert weaponised.effective_hours < emerging.effective_hours


def test_effective_hours_accounts_for_retries():
    catalog = TechniqueCatalog()
    technique = catalog.get("known-vulnerability/kev")
    assert technique.effective_hours == pytest.approx(technique.hours / technique.success)


def test_unauthenticated_datastore_is_the_cheapest_service_route():
    catalog = TechniqueCatalog()
    node = Node.create(NodeType.SERVICE, "1.2.3.4:27017", tags={"unauthenticated-risk"})
    finding = Finding(title="mongodb exposed", severity=Severity.CRITICAL,
                      category="exposed-service")
    technique = catalog.for_finding(finding, node)
    assert technique.id == "exposed-service/datastore"
    assert technique.capability is Capability.OPPORTUNIST


def test_findings_with_no_modelled_route_are_not_invented():
    """Missing headers are real, but they are not a way in on their own."""
    catalog = TechniqueCatalog()
    assert catalog.for_finding(
        Finding(title="Missing security headers", severity=Severity.LOW,
                category="web-hardening")
    ) is None


def test_cost_overrides_are_honoured():
    catalog = TechniqueCatalog(overrides={"known-vulnerability/kev": {"hours": 40.0}})
    assert catalog.get("known-vulnerability/kev").hours == 40.0
    assert catalog.get("known-vulnerability/kev").mitre == "T1190", "unpatched fields survive"


def test_objectives_are_derived_from_what_an_attacker_would_want():
    secret = Node.create(NodeType.SECRET, "host/.env", attrs={"credential_types": ["AWS key"]})
    found = objectives_for(secret, [])
    assert found and found[0].kind is ObjectiveKind.CREDENTIAL_ACCESS

    plain_host = Node.create(NodeType.SUBDOMAIN, "www.example.com")
    assert objectives_for(plain_host, []) == []


# ------------------------------------------------------------------ pathfinding


@pytest.fixture
def cheap_and_expensive() -> AttackSurfaceGraph:
    """One host with a critical CVE, and a cheaper open door to the same data."""
    g = AttackSurfaceGraph.seed("example.com", mode="active")
    host = g.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com"))
    ip = g.add_node(Node.create(NodeType.IP, "93.184.216.34"))
    service = g.add_node(
        Node.create(NodeType.SERVICE, "93.184.216.34:27017", label="mongodb/27017",
                    tags={"unauthenticated-risk"})
    )
    vuln = g.add_node(
        Node.create(NodeType.VULNERABILITY, "CVE-2099-1", attrs={"cvss": 10.0, "kev": False})
    )
    for src, dst, kind in [
        (host.id, ip.id, EdgeType.RESOLVES_TO),
        (ip.id, service.id, EdgeType.EXPOSES),
        (host.id, vuln.id, EdgeType.VULNERABLE_TO),
    ]:
        g.add_edge(Edge(source=src, target=dst, type=kind))

    g.add_finding(
        Finding(title="mongodb exposed on 93.184.216.34:27017", severity=Severity.CRITICAL,
                category="exposed-service", node_ids=[service.id])
    )
    g.add_finding(
        Finding(title="CVE-2099-1 affects app", severity=Severity.CRITICAL,
                category="known-vulnerability", node_ids=[vuln.id], cvss=10.0, epss=0.001)
    )
    RiskEngine().score(g)
    return g


def test_the_cheapest_route_is_found_not_the_scariest(cheap_and_expensive):
    result = simulate(cheap_and_expensive)
    assert result.reachable
    cheapest = min(result.campaigns, key=lambda c: c.hours)
    assert "mongodb" in cheapest.steps[0].technique.lower() or "datastore" in cheapest.steps[0].technique.lower()
    assert cheapest.hours < 1.0, "an open database is minutes of work"


def test_patching_the_critical_cve_does_not_help_while_a_cheaper_door_is_open(cheap_and_expensive):
    """This is the case severity ranking gets wrong."""
    result = simulate(cheap_and_expensive)
    fixes = {c.title: c for c in result.counterfactuals}
    assert "CVE-2099-1 affects app" not in fixes, (
        "patching a CVE behind a cheaper open door must not appear as a top fix"
    )
    assert any("mongodb" in title for title in fixes), "closing the open door must matter"


def test_counterfactual_reports_when_a_fix_closes_every_route():
    g = AttackSurfaceGraph.seed("example.com", mode="active")
    secret = g.add_node(Node.create(NodeType.SECRET, "app/.env",
                                    attrs={"credential_types": ["AWS key"]}))
    g.add_finding(
        Finding(title="Exposed .env", severity=Severity.CRITICAL, category="secret-exposure",
                node_ids=[secret.id], evidence={"credential_types": ["AWS key"]})
    )
    RiskEngine().score(g)
    result = simulate(g)

    assert result.reachable
    assert len(result.counterfactuals) == 1
    assert result.counterfactuals[0].closes_the_path
    assert result.counterfactuals[0].to_dict()["remediated_hours"] is None


def test_an_estate_with_no_priced_weakness_has_no_route():
    g = AttackSurfaceGraph.seed("clean.example")
    g.add_finding(
        Finding(title="Missing security headers", severity=Severity.LOW,
                category="web-hardening",
                node_ids=[Node.make_id(NodeType.DOMAIN, "clean.example")])
    )
    RiskEngine().score(g)
    result = simulate(g)
    assert not result.reachable
    assert result.time_to_compromise >= UNREACHABLE
    assert result.counterfactuals == []
    assert any("coverage" in a for a in result.assumptions)


def test_steps_carry_mitre_ids_for_detection_mapping(cheap_and_expensive):
    result = simulate(cheap_and_expensive)
    assert all(step.mitre for c in result.campaigns for step in c.steps)


def test_campaigns_rank_by_impact_per_hour(cheap_and_expensive):
    result = simulate(cheap_and_expensive)
    priorities = [c.priority for c in result.campaigns]
    assert priorities == sorted(priorities, reverse=True)


def test_detection_probability_compounds_across_steps():
    g = AttackSurfaceGraph.seed("example.com", mode="active")
    host = g.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com"))
    ip = g.add_node(Node.create(NodeType.IP, "93.184.216.34"))
    service = g.add_node(Node.create(NodeType.SERVICE, "93.184.216.34:9200",
                                     tags={"unauthenticated-risk"}))
    g.add_edge(Edge(source=host.id, target=ip.id, type=EdgeType.RESOLVES_TO))
    g.add_edge(Edge(source=ip.id, target=service.id, type=EdgeType.EXPOSES))
    g.add_finding(Finding(title="elastic exposed", severity=Severity.CRITICAL,
                          category="exposed-service", node_ids=[service.id]))
    RiskEngine().score(g)

    result = simulate(g)
    assert result.campaigns
    assert 0.0 <= result.campaigns[0].detection_probability <= 1.0


def test_simulation_serializes_cleanly(cheap_and_expensive):
    import json

    payload = simulate(cheap_and_expensive).to_dict()
    json.dumps(payload)
    assert payload["reachable"] is True
    assert payload["time_to_compromise_hours"] is not None
    assert payload["assumptions"], "the model must state what it assumes"
