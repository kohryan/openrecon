# tests/test_cors.py
import asyncio
from openrecon.collectors.cors import CorsDetector
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance, Severity
from openrecon.collectors.base import CollectorContext
from openrecon.config import Config
from openrecon.scope import Scope

class _Resp:
    def __init__(self, text, status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {"content-type": "text/html"}

class _FakeHttp:
    def __init__(self, mode="vulnerable"):
        self.mode = mode
        self.calls = []
    async def request(self, method, url, **kw):
        self.calls.append({"url": url, "headers": kw.get("headers", {})})
        if self.mode == "vulnerable":
            origin = kw.get("headers", {}).get("Origin", "")
            return _Resp("<html>OK</html>", headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
                "content-type": "text/html"
            })
        if self.mode == "wildcard":
            return _Resp("<html>OK</html>", headers={
                "access-control-allow-origin": "*",
                "content-type": "text/html"
            })
        return _Resp("<html>OK</html>")

def test_cors_detects_origin_reflection():
    http = _FakeHttp("vulnerable")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = CorsDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/api/data",
                               attrs={"host": "app.example.com", "path": "/api/data",
                                      "kind": "rest"},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity in (Severity.HIGH, Severity.MEDIUM)

def test_cors_wildcard_no_credentials():
    http = _FakeHttp("wildcard")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = CorsDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/api/data",
                               attrs={"host": "app.example.com", "path": "/api/data",
                                      "kind": "rest"},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) == 0 or out.findings[0].severity == Severity.LOW

def test_cors_clean_endpoint_no_finding():
    http = _FakeHttp("clean")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = CorsDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/api/data",
                               attrs={"host": "app.example.com", "path": "/api/data",
                                      "kind": "rest"},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
