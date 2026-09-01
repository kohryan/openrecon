"""Active collectors, exercised against a local listener.

These never leave the machine: they bind 127.0.0.1 and talk to themselves. The
scope guard is tested separately - here we verify the probing logic itself.
"""

from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from openrecon.collectors.base import CollectorContext
from openrecon.collectors.fingerprint import HttpFingerprintCollector
from openrecon.collectors.secrets import ApiExposureCollector
from openrecon.collectors.services import PortScanCollector
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Severity

_DER = Encoding.DER


@pytest.fixture
def ctx() -> CollectorContext:
    return CollectorContext(config=Config(active=True, timeout=3.0), http=None, dns=None)  # type: ignore[arg-type]


async def test_port_probe_detects_an_open_port_and_reads_the_banner(ctx):
    async def handle(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        collector = PortScanCollector(ctx)
        outcome = await collector._probe(asyncio.Semaphore(1), "127.0.0.1", port)
    finally:
        server.close()
        await server.wait_closed()

    assert outcome is not None
    ip, found_port, banner = outcome
    assert (ip, found_port) == ("127.0.0.1", port)
    assert "OpenSSH_8.9p1" in banner


async def test_port_probe_returns_none_for_a_closed_port(ctx):
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    outcome = await PortScanCollector(ctx)._probe(asyncio.Semaphore(1), "127.0.0.1", port)
    assert outcome is None


def test_datastore_ports_produce_a_critical_finding(ctx):
    result = PortScanCollector(ctx)._service_findings(
        "93.184.216.34", 27017, "mongodb", Severity.CRITICAL, "", "service:93.184.216.34:27017"
    )
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.CRITICAL
    assert "mongodb" in result.findings[0].title


def test_banner_versions_become_technology_nodes(ctx):
    result = PortScanCollector(ctx)._service_findings(
        "93.184.216.34", 22, "ssh", Severity.INFO, "SSH-2.0-OpenSSH_8.9p1",
        "service:93.184.216.34:22",
    )
    tech = [n for n in result.nodes if n.type is NodeType.TECHNOLOGY]
    assert tech and tech[0].attrs["product"] == "openssh"
    assert tech[0].attrs["version"] == "8.9p1"


class _FakeResponse:
    def __init__(self, headers, body="", status=200, url="https://h/"):
        self.headers = headers
        self.text = body
        self.status_code = status
        self.url = url


class _FakeHttpClient:
    """Returns one canned response for every GET, regardless of URL."""

    def __init__(self, response):
        self._response = response

    async def request(self, *args, **kwargs):
        return self._response

    async def get_json(self, *args, **kwargs):
        import json as _json

        return _json.loads(self._response.text)


def _fake_http(response: _FakeResponse) -> _FakeHttpClient:
    return _FakeHttpClient(response)


def test_http_fingerprint_extracts_products_and_flags_disclosure(ctx, graph):
    resp = _FakeResponse(
        {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3", "content-type": "text/html"},
        "<html><title>GitLab</title><body>wp-content</body></html>",
    )
    result = HttpFingerprintCollector(ctx)._analyze(graph, "dev.example.com", "https", resp)
    products = {n.attrs["product"] for n in result.nodes if n.type is NodeType.TECHNOLOGY}
    assert {"nginx", "php", "gitlab", "wordpress"} <= products

    titles = [f.title for f in result.findings]
    assert any("version disclosed" in t for t in titles)
    assert any("Missing security headers" in t for t in titles)


def test_http_fingerprint_stays_quiet_on_a_hardened_host(ctx, graph):
    resp = _FakeResponse(
        {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-type": "text/html",
        },
        "<html><title>ok</title></html>",
    )
    result = HttpFingerprintCollector(ctx)._analyze(graph, "api.example.com", "https", resp)
    assert result.findings == []


async def test_active_collectors_refuse_targets_outside_the_scope(ctx):
    from openrecon.scope import Scope

    ctx.scope = Scope(include=["*.example.com"])
    collector = PortScanCollector(ctx)
    assert collector.targets_in_scope(["evil.net", "8.8.8.8"]) == []
    ctx.scope.authorize_ip("93.184.216.34")
    assert collector.targets_in_scope(["93.184.216.34"]) == ["93.184.216.34"]


async def test_active_collector_with_no_scope_gets_nothing(ctx):
    ctx.scope = None
    assert PortScanCollector(ctx).targets_in_scope(["example.com"]) == []


# ------------------------------------------------------------------ TLS keys


def _cert(key, *, days_valid: int = 90):
    """Mint a throwaway self-signed certificate for the key under test."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
    )
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


@pytest.mark.parametrize(
    "make_key,expect_weak,label",
    [
        (lambda: __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ec"])
         .generate_private_key(
             __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ec"]).SECP256R1()
         ), False, "P-256 is the modern default, not a weakness"),
        (lambda: __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["rsa"])
         .generate_private_key(public_exponent=65537, key_size=1024), True, "1024-bit RSA is weak"),
        (lambda: __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["rsa"])
         .generate_private_key(public_exponent=65537, key_size=2048), False, "2048-bit RSA is fine"),
        (lambda: __import__("cryptography.hazmat.primitives.asymmetric.ed25519",
                            fromlist=["ed25519"]).Ed25519PrivateKey.generate(),
         False, "Ed25519 has no bit-length to compare"),
    ],
)
def test_key_strength_is_judged_per_algorithm(ctx, graph, make_key, expect_weak, label):
    """Regression: comparing an EC key against an RSA threshold flagged every
    modern certificate as weak."""
    from openrecon.collectors.certificates import TlsHandshakeCollector

    cert = _cert(make_key())
    info = {"der": cert.public_bytes(_DER), "protocol": "TLSv1.3", "cipher": ("X", "TLSv1.3", 0)}
    result = TlsHandshakeCollector(ctx)._to_result(graph, "test.example.com", info)

    weak = [f for f in result.findings if "Weak public key" in f.title]
    assert bool(weak) is expect_weak, label


def test_key_algorithm_is_recorded_on_the_certificate_node(ctx, graph):
    from cryptography.hazmat.primitives.asymmetric import ec

    from openrecon.collectors.certificates import TlsHandshakeCollector

    cert = _cert(ec.generate_private_key(ec.SECP256R1()))
    info = {"der": cert.public_bytes(_DER), "protocol": "TLSv1.3", "cipher": ("X", "TLSv1.3", 0)}
    result = TlsHandshakeCollector(ctx)._to_result(graph, "test.example.com", info)

    cert_node = next(n for n in result.nodes if n.type is NodeType.CERTIFICATE)
    assert cert_node.attrs["key_algorithm"].startswith("ec/")
    assert cert_node.attrs["key_size"] == 256


# ------------------------------------------------------------------ API exposure


def _api_graph() -> AttackSurfaceGraph:
    g = AttackSurfaceGraph.seed("example.com", mode="active", version="test")
    g.add_node(
        Node.create(
            NodeType.SUBDOMAIN, "api.example.com",
            attrs={"http_status": 200}, tags={"web"},
        )
    )
    return g


def test_api_exposure_finds_swagger_spec(ctx):
    ctx.http = _fake_http(
        _FakeResponse(
            {"content-type": "application/json"},
            '{"swagger":"2.0","info":{"title":"X"},"paths":{"/user":{"get":{}}},"definitions":{}}',
        )
    )
    graph = _api_graph()
    result = asyncio.run(ApiExposureCollector(ctx)._probe(asyncio.Semaphore(1), graph, "api.example.com", "/swagger.json"))  # type: ignore[arg-type]
    assert result is not None
    api_nodes = [n for n in result.nodes if n.type is NodeType.API]
    assert api_nodes and api_nodes[0].attrs["kind"] == "Swagger/OpenAPI"
    assert result.findings[0].severity.value == "high"
    assert result.findings[0].category == "api-exposure"


def test_api_exposure_flags_graphql_introspection_as_critical(ctx):
    ctx.http = _fake_http(
        _FakeResponse(
            {"content-type": "application/json"},
            '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}',
        )
    )
    graph = _api_graph()
    result = asyncio.run(ApiExposureCollector(ctx)._probe(asyncio.Semaphore(1), graph, "api.example.com", "/graphql"))  # type: ignore[arg-type]
    assert result is not None
    api_nodes = [n for n in result.nodes if n.type is NodeType.API]
    assert api_nodes and api_nodes[0].attrs["introspectable"] is True
    assert result.findings[0].severity.value == "critical"


def test_api_exposure_skips_html_login_page(ctx):
    ctx.http = _fake_http(
        _FakeResponse(
            {"content-type": "text/html"},
            "<html><head><title>Login</title></head><body>sign in</body></html>",
        )
    )
    graph = _api_graph()
    result = asyncio.run(ApiExposureCollector(ctx)._probe(asyncio.Semaphore(1), graph, "api.example.com", "/swagger.json"))  # type: ignore[arg-type]
    assert result is None


def test_api_exposure_respects_scope(ctx):
    from openrecon.scope import Scope

    ctx.scope = Scope(include=["*.example.com"])
    collector = ApiExposureCollector(ctx)
    # out-of-scope host is dropped by targets_in_scope before any request
    assert collector.targets_in_scope(["evil.net"]) == []


# -------------------------------------------------------------- live progress


def test_fingerprint_emits_per_host_progress_events(ctx, graph):
    """Regression: a slow scan must report live progress, not freeze the cursor.

    The collector fires one request per host; for thousands of subdomains that
    is the fingerprint stage's bottleneck, so it must emit `probing` events the
    monitor can render as `123/2000 probed`.
    """
    events: list[tuple[str, str, dict]] = []
    ctx.progress = lambda event, name, data: events.append((event, name, data))

    from openrecon.scope import Scope

    ctx.scope = Scope(include=["*.example.com", "example.com"])
    collector = HttpFingerprintCollector(ctx)
    # Re-bind the fake http onto the collector's ctx and drive collect directly.
    from unittest.mock import AsyncMock

    fake = AsyncMock()
    fake.request = AsyncMock(return_value=_FakeResponse({"content-type": "text/html"},
                                                        "<html><title>ok</title></html>"))
    collector.http = fake
    asyncio.run(collector.collect(graph))

    probing = [e for e in events if e[0] == "probing"]
    assert probing, "expected per-host probing events"
    # start, one per host, done
    assert events[0][0] == "probing-start"
    assert events[-1][0] == "probing-done"
    assert events[-1][2]["done"] == events[-1][2]["total"]
    # every host was reported once
    assert len(probing) == len(graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN))


def test_scan_monitor_renders_probing_substatus():
    """The live view shows `123/2000 probed` during a long fingerprint run."""
    from rich.console import Console

    from openrecon.report.live import ScanMonitor

    console = Console()
    monitor = ScanMonitor(console, "shopify.com", "active",
                          ["dns", "subdomains", "fingerprint", "vulnerabilities"])
    monitor._on_stage_start("fingerprint", {"collectors": ["http"]})
    monitor._on_collector_start("http", {"stage": "fingerprint"})
    monitor._on_probing_start("http", {"stage": "fingerprint", "total": 2000, "done": 0})
    monitor._on_probing("http", {"stage": "fingerprint", "total": 2000, "done": 123})
    row = monitor._stage_row(monitor.stages["fingerprint"], final=False)
    detail = row[2]
    assert "123/2000" in detail.plain
    assert "probed" in detail.plain
