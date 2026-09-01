# tests/test_ssti.py
import asyncio
from openrecon.collectors.ssti import SstiDetector, render_probe
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance, Severity
from openrecon.collectors.base import CollectorContext
from openrecon.config import Config
from openrecon.scope import Scope

class _Resp:
    def __init__(self, text, status=200, content_type="text/html"):
        self.text = text
        self.status_code = status
        self.headers = {"content-type": content_type}

class _FakeHttp:
    def __init__(self, mode="vulnerable"):
        self.mode = mode
        self.calls = []
    async def request(self, method, url, **kw):
        self.calls.append({"url": url, "params": kw.get("params", {})})
        if self.mode == "vulnerable":
            return _Resp("<html>Hello 49</html>")
        if self.mode == "clean":
            return _Resp("<html>Hello {{7*7}}</html>")
        return None

def test_render_probe_detects_ssti():
    # Rendered: payload consumed, expected value present
    assert render_probe("Hello 49", "{{7*7}}", "49") is True
    # Not rendered: payload still in response
    assert render_probe("Hello {{7*7}}", "{{7*7}}", "49") is False

def test_ssti_finds_vulnerable_endpoint():
    http = _FakeHttp("vulnerable")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = SstiDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/page",
                               attrs={"host": "app.example.com", "path": "/page",
                                      "kind": "rest", "query_params": ["id", "name"]},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

def test_ssti_clean_endpoint_no_finding():
    http = _FakeHttp("clean")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = SstiDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/page",
                               attrs={"host": "app.example.com", "path": "/page",
                                      "kind": "rest", "query_params": ["id"]},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
