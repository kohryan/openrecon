"""Pipeline orchestration, with collectors stubbed so nothing leaves the machine."""

from __future__ import annotations

import pytest

from openrecon.collectors.base import _REGISTRY, STAGES, Collector, register
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult,
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    ScanMode,
    Severity,
)
from openrecon.pipeline import Pipeline
from openrecon.scope import Scope


@pytest.fixture
def isolated_registry():
    """Swap the global registry so stub collectors don't leak into other tests."""
    saved = dict(_REGISTRY)
    _REGISTRY.clear()
    yield _REGISTRY
    _REGISTRY.clear()
    _REGISTRY.update(saved)


def _stub(name: str, stage: str, mode: ScanMode = ScanMode.PASSIVE, **kw):
    """Build and register a throwaway collector. Returns (class, calls-seen-list)."""
    calls: list[int] = []

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        calls.append(len(graph.nodes))
        if kw.get("raises"):
            raise RuntimeError("upstream exploded")
        return kw.get("result", CollectorResult())

    stub = type(
        f"Stub_{name}",
        (Collector,),
        {
            "name": name,
            "stage": stage,
            "mode": mode,
            "description": f"stub {name}",
            "requires_keys": kw.get("requires_keys", ()),
            "collect": collect,
        },
    )
    register(stub)
    return stub, calls


async def test_stages_run_in_dependency_order(isolated_registry):
    order: list[str] = []

    for stage in ("registration", "subdomains", "vulnerabilities"):
        stub, _ = _stub(f"s_{stage}", stage)
        original = stub.collect

        async def collect(self, graph, _stage=stage, _orig=original):
            order.append(_stage)
            return await _orig(self, graph)

        stub.collect = collect

    await Pipeline(Config()).run("example.com")
    assert order == ["registration", "subdomains", "vulnerabilities"]
    assert STAGES.index("registration") < STAGES.index("vulnerabilities")


async def test_later_stages_see_earlier_results(isolated_registry):
    _stub(
        "producer",
        "subdomains",
        result=CollectorResult(
            nodes=[Node.create(NodeType.SUBDOMAIN, "dev.example.com")],
            edges=[
                Edge(
                    source=Node.make_id(NodeType.DOMAIN, "example.com"),
                    target=Node.make_id(NodeType.SUBDOMAIN, "dev.example.com"),
                    type=EdgeType.HAS_SUBDOMAIN,
                )
            ],
        ),
    )
    _, consumer_saw = _stub("consumer", "vulnerabilities")

    graph = await Pipeline(Config()).run("example.com")
    assert Node.make_id(NodeType.SUBDOMAIN, "dev.example.com") in graph.nodes
    assert consumer_saw == [2], "consumer should see the seed domain plus the new subdomain"


async def test_a_failing_collector_does_not_abort_the_scan(isolated_registry):
    _stub("broken", "dns", raises=True)
    _stub(
        "healthy",
        "dns",
        result=CollectorResult(nodes=[Node.create(NodeType.SUBDOMAIN, "ok.example.com")]),
    )

    pipeline = Pipeline(Config())
    graph = await pipeline.run("example.com")

    assert Node.make_id(NodeType.SUBDOMAIN, "ok.example.com") in graph.nodes
    assert "healthy" in graph.meta.collectors_run
    assert "broken" not in graph.meta.collectors_run
    assert any("broken" in e for e in graph.meta.errors)


async def test_active_collectors_are_skipped_in_passive_mode(isolated_registry):
    _stub("aggressive", "services", mode=ScanMode.ACTIVE)
    graph = await Pipeline(Config(active=False)).run("example.com")
    assert "aggressive" in graph.meta.collectors_skipped
    assert "active mode disabled" in graph.meta.collectors_skipped["aggressive"]


async def test_active_collectors_need_a_scope_even_in_active_mode(isolated_registry):
    _stub("aggressive", "services", mode=ScanMode.ACTIVE)
    graph = await Pipeline(Config(active=True), scope=None).run("example.com")
    assert "no authorization scope" in graph.meta.collectors_skipped["aggressive"]

    graph2 = await Pipeline(
        Config(active=True), scope=Scope(include=["example.com"])
    ).run("example.com")
    assert "aggressive" in graph2.meta.collectors_run


async def test_risk_engine_runs_as_the_final_stage(isolated_registry):
    apex = Node.make_id(NodeType.DOMAIN, "example.com")
    _stub(
        "finder",
        "dns",
        result=CollectorResult(
            findings=[
                Finding(
                    title="critical thing",
                    severity=Severity.CRITICAL,
                    category="known-vulnerability",
                    node_ids=[apex],
                    kev=True,
                )
            ]
        ),
    )
    graph = await Pipeline(Config()).run("example.com")
    assert graph.risk["grade"] != "A"
    assert graph.nodes[apex].risk_score > 0
    assert graph.findings[next(iter(graph.findings))].risk_score > 0
    assert graph.meta.finished_at is not None


async def test_only_and_exclude_filters(isolated_registry):
    _stub("wanted", "dns")
    _stub("unwanted", "dns")

    graph = await Pipeline(Config(enabled_collectors={"wanted"})).run("example.com")
    assert graph.meta.collectors_run == ["wanted"]

    graph = await Pipeline(Config(disabled_collectors={"unwanted"})).run("example.com")
    assert graph.meta.collectors_run == ["wanted"]


def test_plan_reports_why_each_collector_is_unavailable(isolated_registry, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    _stub("needs_key", "services", requires_keys=("shodan",))
    _stub("needs_active", "services", mode=ScanMode.ACTIVE)
    _stub("ready", "dns")

    plan = Pipeline(Config()).plan()
    entries = {e["name"]: e for stage in plan.values() for e in stage}
    assert entries["ready"]["enabled"]
    assert not entries["needs_key"]["enabled"]
    assert entries["needs_key"]["missing_keys"] == ["shodan"]
    assert not entries["needs_active"]["enabled"]
