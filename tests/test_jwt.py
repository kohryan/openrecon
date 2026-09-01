# tests/test_jwt.py
import asyncio
from openrecon.collectors.jwt import JwtAnalyzer, decode_jwt_header, is_weak_secret
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
        self.calls.append(url)
        if self.mode == "vulnerable":
            # JWT with "none" algorithm
            return _Resp("<html>OK</html>", headers={
                "set-cookie": "session=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
                "content-type": "text/html"
            })
        if self.mode == "clean":
            return _Resp("<html>OK</html>")
        return None

def test_decode_jwt_header():
    # JWT with alg=none
    header = decode_jwt_header("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.")
    assert header is not None
    header_dict, _ = header
    assert header_dict["alg"] == "none"

def test_is_weak_secret():
    assert is_weak_secret("secret") is True
    assert is_weak_secret("password") is True
    assert is_weak_secret("my-super-secret-key-123") is True
    assert is_weak_secret("aB3$kL9@mN2#pQ5") is False

def test_jwt_detects_none_algorithm():
    http = _FakeHttp("vulnerable")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = JwtAnalyzer(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/dashboard",
                               attrs={"host": "app.example.com", "path": "/dashboard",
                                      "kind": "rest"},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity in (Severity.HIGH, Severity.CRITICAL)

def test_jwt_clean_endpoint_no_finding():
    http = _FakeHttp("clean")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = JwtAnalyzer(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    graph.add_node(Node.create(NodeType.API, "https://app.example.com/dashboard",
                               attrs={"host": "app.example.com", "path": "/dashboard",
                                      "kind": "rest"},
                               provenance=Provenance(collector="crawler"),
                               tags={"api", "rest"}))
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
