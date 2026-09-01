"""Coverage assessment: the claim that this scan knows what it did not see."""

from __future__ import annotations

import pytest

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance
from openrecon.coverage import CONFIDENCE_LABELS, assess, chapman_estimate


def _seen_by(graph: AttackSurfaceGraph, collector: str, names: list[str]) -> None:
    for name in names:
        graph.add_node(
            Node.create(
                NodeType.SUBDOMAIN, name, provenance=Provenance(collector=collector)
            )
        )


# ------------------------------------------------------------ the estimator


def test_chapman_recovers_a_known_population():
    """200 tagged, 60 recaptured, 40 overlap -> about 300 fish in the pond."""
    estimate, (low, high) = chapman_estimate(200, 60, 40)
    assert 290 <= estimate <= 310
    assert low <= estimate <= high


def test_chapman_is_defined_when_samples_do_not_overlap():
    """Plain Lincoln-Petersen divides by zero here; Chapman is why we use it."""
    result = chapman_estimate(4, 1, 0)
    assert result is not None
    estimate, _interval = result
    assert estimate >= 4


def test_chapman_interval_never_falls_below_what_was_observed():
    _estimate, (low, _high) = chapman_estimate(50, 30, 5)
    assert low >= 50


def test_chapman_needs_two_samples():
    assert chapman_estimate(0, 10, 0) is None
    assert chapman_estimate(10, 0, 0) is None


def test_complete_overlap_implies_full_coverage():
    estimate, _ = chapman_estimate(30, 30, 30)
    assert estimate == 30


# ------------------------------------------------------------ the assessment


def test_two_sources_produce_a_population_estimate():
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = ["ct", "dnsbrute"]
    _seen_by(g, "ct", [f"a{i}.example.com" for i in range(20)])
    _seen_by(g, "dnsbrute", [f"a{i}.example.com" for i in range(5, 15)])

    subdomains = next(c for c in assess(g).classes if c.name == "subdomains")
    assert subdomains.method == "capture-recapture"
    assert subdomains.estimated_total >= subdomains.observed
    assert 0 < subdomains.coverage <= 1
    assert "in both" in subdomains.note


def test_one_source_refuses_to_guess_the_population():
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = ["ct"]
    _seen_by(g, "ct", [f"a{i}.example.com" for i in range(20)])

    subdomains = next(c for c in assess(g).classes if c.name == "subdomains")
    assert subdomains.method == "channel-accounting"
    assert subdomains.estimated_total is None
    assert "cannot be estimated" in subdomains.note


def test_barely_overlapping_samples_are_flagged_as_weak():
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = ["ct", "dnsbrute"]
    _seen_by(g, "ct", [f"a{i}.example.com" for i in range(6)])
    _seen_by(g, "dnsbrute", ["a0.example.com"])

    subdomains = next(c for c in assess(g).classes if c.name == "subdomains")
    assert "weak" in subdomains.note


def test_dependencies_report_zero_when_nothing_inspected_them():
    """The bug this class exists for: silence reading as an all-clear."""
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = ["dns", "resolve", "http"]

    dependencies = next(c for c in assess(g).classes if c.name == "dependencies")
    assert dependencies.coverage == 0.0
    assert "means nothing was looked at" in dependencies.note
    assert "npm" in dependencies.note or "audit" in dependencies.note


def test_dependency_coverage_is_capped_even_when_analysis_ran():
    """Bundle analysis sees runtime packages only, never the build tree."""
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = ["sbom"]
    for name, version in (("next", "12.1.6"), ("react-dom", "17.0.2")):
        g.add_node(
            Node.create(
                NodeType.TECHNOLOGY,
                f"npm:{name}:{version}",
                attrs={"product": name, "version": version, "ecosystem": "npm"},
            )
        )
    dependencies = next(c for c in assess(g).classes if c.name == "dependencies")
    assert 0 < dependencies.coverage <= 0.45
    assert "build-time and server-side" in dependencies.note


def test_being_blocked_reduces_confidence_rather_than_reading_as_clean():
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = ["ct", "dnsbrute", "http", "sbom"]
    _seen_by(g, "ct", [f"a{i}.example.com" for i in range(10)])
    _seen_by(g, "dnsbrute", [f"a{i}.example.com" for i in range(8)])
    clean = assess(g).confidence

    g.meta.errors.append("blocked: app.example.com answered 403 to bundle analysis")
    blocked = assess(g)
    assert blocked.confidence < clean
    assert any("refused this scan" in b for b in blocked.blind_spots)


def test_confidence_qualifies_the_grade():
    g = AttackSurfaceGraph.seed("example.com")
    report = assess(g)
    assert report.confidence < 0.8
    assert report.qualified_grade("A") == "A?"

    report.confidence = 0.95
    assert report.qualified_grade("A") == "A"


def test_confidence_labels_are_ordered_and_total():
    thresholds = [t for t, _ in CONFIDENCE_LABELS]
    assert thresholds == sorted(thresholds, reverse=True)
    assert thresholds[-1] == 0.0, "every confidence value must get a label"


def test_caveats_never_claim_completeness():
    report = assess(AttackSurfaceGraph.seed("example.com"))
    joined = " ".join(report.caveats).lower()
    assert "estimate" in joined
    assert "all-clear" in joined or "never as" in joined


def test_report_serializes(graph):
    import json

    payload = assess(graph).to_dict()
    json.dumps(payload)
    assert set(payload) >= {"confidence", "confidence_label", "classes", "caveats"}


@pytest.mark.parametrize("collector", ["ports", "shodan"])
def test_service_visibility_tracks_the_channel_that_ran(collector):
    g = AttackSurfaceGraph.seed("example.com")
    g.meta.collectors_run = [collector]
    services = next(c for c in assess(g).classes if c.name == "services")
    assert services.coverage == 0.5
    assert collector in services.channels_used
