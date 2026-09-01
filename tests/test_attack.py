"""Tests for the `attack` stage collectors (katana crawler, nuclei)."""

from __future__ import annotations

import json

from openrecon.collectors import all_collectors, collectors_for_stage
from openrecon.collectors.attack import CrawlerCollector, NucleiCollector
from openrecon.collectors.base import STAGES
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import NodeType


def test_attack_stage_registered():
    assert "attack" in STAGES
    assert {"crawler", "nuclei"} <= set(all_collectors())
    assert {c.name for c in collectors_for_stage("attack")} == {
        "crawler", "nuclei", "fuzzer", "sqli", "ssrf", "auth",
        "api_surface", "graphql_verify", "reverse_engineering",
        "ssti", "lfi", "cmdi", "jwt", "cors", "security_txt",
    }


def test_crawler_is_active_and_scoped():
    assert CrawlerCollector.mode.value == "active"
    assert CrawlerCollector.requires_bins == ("katana",)


def test_crawler_unavailable_without_active_mode():
    cfg = Config()  # active=False, no katana on PATH
    collector = CrawlerCollector.__new__(CrawlerCollector)
    collector.ctx = None
    collector.config = cfg
    ok, reason = collector.available()
    assert ok is False
    assert "active" in reason.lower()


def test_crawler_parses_katana_json_lines_in_scope():
    """_parse_line keeps only endpoints on an in-scope host."""
    cfg = Config(active=True)
    collector = CrawlerCollector.__new__(CrawlerCollector)
    collector.ctx = None
    collector.config = cfg
    collector._in_scope = {"shop.example.com", "example.com"}

    good = json.dumps(
        {"host": "https://shop.example.com", "endpoint": "https://shop.example.com/cart", "source": "link"}
    ).encode()
    offscope = json.dumps(
        {"endpoint": "https://evil-ads.net/track", "source": "link"}
    ).encode()

    assert collector._parse_line(good) == ("https://shop.example.com/cart", "link")
    assert collector._parse_line(offscope) is None
    assert collector._parse_line(b"   ") is None


def test_crawler_builds_api_node_and_exposes_edge():
    cfg = Config(active=True)
    cfg.tool_paths = {}  # ensure resolution branch does not crash
    collector = CrawlerCollector.__new__(CrawlerCollector)
    collector.ctx = None
    collector.config = cfg

    node, edge = collector._endpoint_node(
        "shop.example.com", "https://shop.example.com/cart", "link"
    )
    assert node is not None and node.type is NodeType.API
    assert "endpoint" in node.tags and "crawled" in node.tags
    assert edge is not None and edge.type.value == "exposes"
    assert edge.source == "subdomain:shop.example.com"
    assert edge.target == node.id


def test_nuclei_is_active_and_scoped():
    assert NucleiCollector.mode.value == "active"
    assert NucleiCollector.requires_bins == ("nuclei",)


def test_nuclei_targets_prefer_crawled_endpoints():
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    from openrecon.core.models import Node, Provenance

    # a crawled endpoint (should be prioritised)
    graph.add_node(
        Node.create(
            NodeType.API,
            "https://shop.example.com/cart",
            attrs={"url": "https://shop.example.com/cart", "host": "shop.example.com"},
            provenance=Provenance(collector="crawler"),
            tags={"endpoint", "crawled"},
        )
    )
    # a known subdomain host
    graph.add_node(
        Node.create(
            NodeType.SUBDOMAIN, "blog.example.com", provenance=Provenance(collector="dns")
        )
    )

    collector = NucleiCollector.__new__(NucleiCollector)
    collector.ctx = type("_Ctx", (), {"in_scope": staticmethod(lambda a: True)})()
    collector.config = Config(active=True)
    targets = collector._targets(graph)
    assert "https://shop.example.com/cart" in targets
    # crawled endpoint comes before the generic host URLs
    assert targets.index("https://shop.example.com/cart") < targets.index("https://blog.example.com")


def test_nuclei_parses_finding_and_anchors_to_node():
    from openrecon.core.models import Node, Provenance

    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    api = Node.create(
        NodeType.API,
        "https://example.com/admin",
        attrs={"url": "https://example.com/admin", "host": "example.com"},
        provenance=Provenance(collector="crawler"),
        tags={"endpoint", "crawled"},
    )
    graph.add_node(api)

    collector = NucleiCollector.__new__(NucleiCollector)
    collector.config = Config(active=True)
    collector._nodes = graph.nodes

    line = json.dumps(
        {
            "host": "https://example.com",
            "matched-at": "https://example.com/admin",
            "template-id": "exposed-panels",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "medium",
                "description": "An admin panel is exposed.",
                "tags": ["exposure", "panel"],
                "reference": ["https://example.com/doc"],
            },
        }
    )
    finding = collector._parse_finding(line)
    assert finding is not None
    assert finding.severity.value == "medium"
    assert finding.category == "nuclei"
    assert api.id in finding.node_ids
    assert finding.references == ["https://example.com/doc"]


def test_nuclei_skips_unparsable_lines():
    collector = NucleiCollector.__new__(NucleiCollector)
    collector.config = Config(active=True)
    collector._nodes = {}
    assert collector._parse_finding("not json") is None
    assert collector._parse_finding(json.dumps({"info": {}})) is None  # no host/matched


def test_crawled_endpoints_helper_filters_scope():
    from openrecon.collectors.attack import _crawled_endpoints
    from openrecon.core.models import Node, Provenance

    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    in_scope = Node.create(
        NodeType.API, "https://app.example.com/x",
        attrs={"url": "https://app.example.com/x", "host": "app.example.com"},
        provenance=Provenance(collector="crawler"), tags={"endpoint", "crawled"},
    )
    off_scope = Node.create(
        NodeType.API, "https://evil.com/y",
        attrs={"url": "https://evil.com/y", "host": "evil.com"},
        provenance=Provenance(collector="crawler"), tags={"endpoint", "crawled"},
    )
    graph.add_node(in_scope)
    graph.add_node(off_scope)

    ctx = type("_Ctx", (), {"in_scope": staticmethod(lambda h: h.endswith("example.com"))})()
    eps = _crawled_endpoints(graph, ctx)
    assert in_scope in eps and off_scope not in eps


def test_fuzzer_sqli_ssrf_require_bins():
    from openrecon.collectors.attack import FuzzerCollector, SqliCollector, SsrfCollector

    for cls in (FuzzerCollector, SqliCollector, SsrfCollector):
        assert cls.mode.value == "active"
        assert cls.requires_bins


def test_auth_collector_requires_cookie():
    from openrecon.collectors.attack import AuthCollector

    cfg = Config(active=True)
    collector = AuthCollector.__new__(AuthCollector)
    collector.ctx = type("_Ctx", (), {"in_scope": staticmethod(lambda a: True)})()
    collector.config = cfg
    ok, reason = collector.available()
    assert ok is True
    import asyncio

    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    out = asyncio.run(collector.collect(graph))
    assert any("auth_cookie" in e for e in out.errors)


def test_auth_collector_detects_bypass():
    from openrecon.collectors.attack import AuthCollector

    cfg = Config(active=True, auth_cookie="session=valid")
    collector = AuthCollector.__new__(AuthCollector)

    class _Resp:
        def __init__(self, status, body=""):
            self.status = status
            self.body = body

    class _Http:
        async def request(self, *a, **k):
            return _Resp(200, "welcome") if k.get("headers", {}).get("Cookie") else _Resp(403, "no")

    collector.ctx = type("_Ctx", (), {"in_scope": staticmethod(lambda a: True)})()
    collector.http = _Http()
    collector.config = cfg

    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    from openrecon.core.models import Node, Provenance

    graph.add_node(
        Node.create(
            NodeType.API, "https://app.example.com/admin",
            attrs={"url": "https://app.example.com/admin", "host": "app.example.com"},
            provenance=Provenance(collector="crawler"), tags={"endpoint", "crawled"},
        )
    )
    import asyncio

    out = asyncio.run(collector.collect(graph))
    assert out.stats["auth_findings"] == 1
    assert out.findings[0].category == "broken-access-control"
