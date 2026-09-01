"""Tests for the API surface discovery + reverse-engineering collectors.

Both run with a mocked HTTP client (no network, no live target). We exercise the
pure helpers (classify_openapi / classify_rest / source-map counting) and the
collector end-to-end against a seeded graph.
"""

from __future__ import annotations

import asyncio
from typing import Any

from openrecon.collectors import all_collectors
from openrecon.collectors.api_exposure import (
    ApiSurfaceCollector,
    classify_openapi,
    classify_rest,
)
from openrecon.collectors.base import CollectorContext
from openrecon.collectors.reverse_engineering import (
    ReverseEngineeringCollector,
    count_sources,
)
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance, Severity
from openrecon.scope import Scope


# ------------------------------------------------------------- pure helpers

def test_classify_openapi_json_spec():
    body = '{"openapi":"3.0.0","info":{"title":"Acme"},"paths":{"/x":{},"/y":{}}}'
    ok, kind, snippet = classify_openapi(body, 200, "application/json")
    assert ok is True
    assert kind == "openapi"
    assert "Acme" in (snippet or "")


def test_classify_openapi_swagger_ui_shell():
    body = "<html><body>SwaggerUIBundle({ url: '/swagger.json' })</body></html>"
    ok, kind, _ = classify_openapi(body, 200, "text/html")
    assert ok is True
    assert kind == "swagger"


def test_classify_openapi_rejects_html_page():
    assert classify_openapi("<html><body>not found</body></html>", 404, "text/html")[0] is False


def test_classify_rest_json_envelope():
    assert classify_rest('{"data":[{"id":1}]}', 200, "application/json")[0] is True
    assert classify_rest('{"error":"unauthorized"}', 200, "application/json")[0] is True
    # A plain HTML page is not a REST api root.
    assert classify_rest("<html>home</html>", 200, "text/html")[0] is False


def test_count_sources_parses_map():
    map_text = '{"version":3,"sources":["a.js","b.js","c.js"],"mappings":"AAA"}'
    assert count_sources(map_text) == 3
    assert count_sources("not a map") == 0


# ------------------------------------------------------------------- fixtures

class _Resp:
    def __init__(self, text: str, status: int = 200, content_type: str = "application/json") -> None:
        self.text = text
        self.status_code = status
        self.headers = {"content-type": content_type}


class _FakeApiHttp:
    """Returns canned responses keyed by URL path."""

    def __init__(self, mode: str = "rich") -> None:
        self.mode = mode
        self.calls: list[dict[str, Any]] = []

    async def request(self, method, url, *, params=None, headers=None, retries=0, json=None, **kw):
        self.calls.append({"method": method, "url": url})
        path = url.split("example.com", 1)[-1]
        if self.mode == "rich":
            if path == "/graphql" and method == "POST":
                return _Resp('{"data":{"__typename":"Query"}}')
            if path == "/openapi.json":
                return _Resp('{"openapi":"3.0","info":{"title":"Acme API"},"paths":{"/users":{}}}')
            if path in ("/api", "/api/v1"):
                return _Resp('{"data":[],"total":0}')
            if path == "/main.js":
                return _Resp("console.log('app');//# sourceMappingURL=main.js.map")
            if path == "/main.js.map":
                return _Resp('{"version":3,"sources":["src/app.ts","src/util.ts"],"mappings":"AAA"}')
            if path == "/":
                return _Resp("<html>webpackJSONP([...])</html>", content_type="text/html")
            if path == "/swagger.yaml":
                return _Resp("openapi: 3.0.0\ninfo:\n  title: Acme\npaths: {}\n")
        if self.mode == "quiet":
            # Nothing exposed.
            return None
        return None


def _build(target: str = "example.com", active: bool = True):
    cfg = Config(active=active)
    scope = Scope.implicit(target)
    ctx = CollectorContext(
        config=cfg, http=None, dns=None, scope=scope, progress=lambda *a, **k: None
    )
    return ctx, scope


def _graph_with_host(target: str = "example.com", host: str = "app.example.com"):
    graph = AttackSurfaceGraph.seed(target, mode="active", version="t")
    graph.add_node(Node.create(
        NodeType.SUBDOMAIN, host,
        attrs={"http_status": 200, "resolves": True},
        provenance=Provenance(collector="http"), tags={"web"},
    ))
    return graph


# --------------------------------------------------------------- api_exposure

def test_api_exposure_registered_and_active():
    assert "api_surface" in all_collectors()
    assert all_collectors()["api_surface"] is ApiSurfaceCollector
    assert ApiSurfaceCollector.stage == "attack"
    assert ApiSurfaceCollector.mode.value == "active"


def test_api_exposure_discovers_graphql_openapi_rest():
    ctx, _ = _build()
    ctx.http = _FakeApiHttp("rich")
    collector = ApiSurfaceCollector(ctx)
    graph = _graph_with_host()
    out = asyncio.run(collector.collect(graph))

    kinds = {n.attrs.get("kind") for n in out.nodes}
    assert "graphql" in kinds
    assert "openapi" in kinds
    assert "rest" in kinds
    cats = {f.category for f in out.findings}
    assert "api-exposure" in cats
    # GraphQL is low; openapi/rest are medium by design.
    sev_by_cat = {f.category: f.severity for f in out.findings}
    assert sev_by_cat["api-exposure"] in (Severity.LOW, Severity.MEDIUM)


def test_api_exposure_quiet_host_no_findings():
    ctx, _ = _build()
    ctx.http = _FakeApiHttp("quiet")
    collector = ApiSurfaceCollector(ctx)
    graph = _graph_with_host()
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
    assert out.nodes == []


# -------------------------------------------------------- reverse_engineering

def test_reverse_engineering_registered_and_active():
    assert "reverse_engineering" in all_collectors()
    assert all_collectors()["reverse_engineering"] is ReverseEngineeringCollector
    assert ReverseEngineeringCollector.stage == "attack"
    assert ReverseEngineeringCollector.mode.value == "active"


def test_reverse_engineering_finds_sourcemap_manifest_spec():
    ctx, _ = _build()
    ctx.http = _FakeApiHttp("rich")
    collector = ReverseEngineeringCollector(ctx)
    graph = _graph_with_host()
    out = asyncio.run(collector.collect(graph))

    cats = {f.category for f in out.findings}
    assert "reverse-engineering" in cats
    leak_types = {n.attrs.get("leak_type") for n in out.nodes}
    # At least a source map and a build manifest (homepage carries webpackJSONP).
    assert "sourcemap" in leak_types
    assert "manifest" in leak_types
    # The source map is the high-severity reverse-engineering aid.
    sev = [f.severity for f in out.findings if f.category == "reverse-engineering"]
    assert Severity.HIGH in sev


def test_reverse_engineering_quiet_host_no_findings():
    ctx, _ = _build()
    ctx.http = _FakeApiHttp("quiet")
    collector = ReverseEngineeringCollector(ctx)
    graph = _graph_with_host()
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
    assert out.nodes == []
