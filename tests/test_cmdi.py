# tests/test_cmdi.py
import asyncio
from openrecon.collectors.cmdi import CmdiDetector
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance, Severity
from openrecon.collectors.base import CollectorContext
from openrecon.config import Config
from openrecon.scope import Scope

class _Resp:
    def __init__(self, text, status=200, elapsed=0.1):
        self.text = text
        self.status_code = status
        self.headers = {"content-type": "text/html"}
        self.elapsed = elapsed

class _FakeHttp:
    def __init__(self, mode="vulnerable"):
        self.mode = mode
        self.calls = []
    async def request(self, method, url, **kw):
        self.calls.append(url)
        if self.mode == "vulnerable":
            # Simulate time-based: sleep payload causes delay
            if "sleep" in url:
                # Initial sleep 5 -> 5.2s elapsed; verification sleep 10 -> 10.2s
                if "10" in url:
                    return _Resp("<html>OK</html>", elapsed=10.2)
                return _Resp("<html>OK</html>", elapsed=5.2)
            return _Resp("<html>OK</html>", elapsed=0.1)
        if self.mode == "error":
            return _Resp("sh: 1: command not found")
        return _Resp("<html>OK</html>", elapsed=0.1)

def test_cmdi_time_based_detection():
    http = _FakeHttp("vulnerable")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = CmdiDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/ping",
                               attrs={"host": "app.example.com", "path": "/ping",
                                      "kind": "rest", "query_params": ["host"]},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity == Severity.CRITICAL

def test_cmdi_clean_endpoint_no_finding():
    http = _FakeHttp("clean")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = CmdiDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/ping",
                               attrs={"host": "app.example.com", "path": "/ping",
                                      "kind": "rest", "query_params": ["host"]},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
