"""Tests for security.txt collector."""
import asyncio
from openrecon.collectors.security_txt import SecurityTxtCollector
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance, Severity
from openrecon.collectors.base import CollectorContext
from openrecon.config import Config
from openrecon.scope import Scope


class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _FakeHttp:
    def __init__(self, mode="valid"):
        self.mode = mode
        self.calls = []

    async def request(self, method, url, **kw):
        self.calls.append(url)
        if self.mode == "valid":
            return _Resp(
                "Contact: security@example.com\n"
                "Expires: 2026-12-31T23:59:59Z\n"
                "Policy: https://example.com/security-policy\n"
            )
        if self.mode == "invalid":
            return _Resp("Contact: security@example.com\n")
        if self.mode == "missing":
            return _Resp("", status=404)
        return None


def _build_collector():
    http = _FakeHttp("valid")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    return SecurityTxtCollector(ctx)


def test_parse_fields():
    collector = _build_collector()
    text = (
        "Contact: security@example.com\n"
        "Expires: 2026-12-31T23:59:59Z\n"
        "Policy: https://example.com/security-policy\n"
    )
    fields = collector._parse_fields(text)
    assert "Contact" in fields
    assert "Expires" in fields
    assert "Policy" in fields
    assert fields["Contact"] == "security@example.com"


def test_security_txt_valid():
    http = _FakeHttp("valid")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = SecurityTxtCollector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity == Severity.LOW
    assert "valid" in out.findings[0].title.lower()


def test_security_txt_invalid():
    http = _FakeHttp("invalid")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = SecurityTxtCollector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    out = asyncio.run(collector.collect(graph))
    assert len(out.findings) >= 1
    assert out.findings[0].severity == Severity.INFO
    assert "invalid" in out.findings[0].title.lower()


def test_security_txt_missing():
    http = _FakeHttp("missing")
    ctx = CollectorContext(config=Config(active=True), http=http, dns=None,
                           scope=Scope.implicit("example.com"), progress=lambda *a, **k: None)
    collector = SecurityTxtCollector(ctx)
    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com",
                               attrs={"http_status": 200, "resolves": True},
                               provenance=Provenance(collector="http"), tags={"web"}))
    out = asyncio.run(collector.collect(graph))
    assert out.findings == []
