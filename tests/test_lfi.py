# tests/test_lfi.py
import asyncio
from openrecon.collectors.lfi import LfiDetector, contains_file_content
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
        self.calls.append(url)
        if self.mode == "vulnerable":
            return _Resp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        if self.mode == "clean":
            return _Resp("<html>Page content</html>")
        return None

def test_contains_file_content_detects_unix_passwd():
    found, file_type = contains_file_content("root:x:0:0:root:/root:/bin/bash")
    assert found is True
    assert file_type == "unix_passwd"
    found, file_type = contains_file_content("<html>Hello</html>")
    assert found is False

def test_lfi_finds_vulnerable_endpoint():
    http = _FakeHttp("vulnerable")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = LfiDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/download",
                               attrs={"host": "app.example.com", "path": "/download",
                                      "kind": "rest", "query_params": ["file"]},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity == Severity.HIGH

def test_lfi_clean_endpoint_no_finding():
    http = _FakeHttp("clean")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = LfiDetector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/download",
                               attrs={"host": "app.example.com", "path": "/download",
                                      "kind": "rest", "query_params": ["file"]},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
