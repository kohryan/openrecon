"""Collector unit tests. Nothing here touches the network."""

from __future__ import annotations

import pytest

from openrecon.collectors import all_collectors
from openrecon.collectors._ct import names_from, valid_host
from openrecon.collectors.base import STAGE_INDEX, CollectorContext
from openrecon.collectors.dns_records import DnsRecordsCollector
from openrecon.collectors.resolve import _service_for
from openrecon.collectors.subdomains import _tags_for
from openrecon.collectors.vulnerabilities import _cpe_matches, _version_lt
from openrecon.config import Config
from openrecon.core.models import NodeType, ScanMode, Severity


def test_every_collector_declares_a_valid_stage_and_mode():
    for name, cls in all_collectors().items():
        assert cls.name == name
        assert cls.stage in STAGE_INDEX, f"{name} has an unknown stage"
        assert cls.mode in (ScanMode.PASSIVE, ScanMode.ACTIVE)
        assert cls.description, f"{name} needs a description"


def test_active_collectors_are_unavailable_without_active_mode():
    ctx = CollectorContext(config=Config(active=False), http=None, dns=None)  # type: ignore[arg-type]
    for cls in all_collectors().values():
        if cls.mode is not ScanMode.ACTIVE:
            continue
        ok, reason = cls(ctx).available()
        assert not ok and "active mode disabled" in reason


def test_keyed_collectors_skip_cleanly_without_a_key(monkeypatch):
    for env in ("SHODAN_API_KEY", "HIBP_API_KEY", "VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    ctx = CollectorContext(config=Config(active=True), http=None, dns=None)  # type: ignore[arg-type]
    for cls in all_collectors().values():
        if not cls.requires_keys:
            continue
        ok, reason = cls(ctx).available()
        assert not ok and "missing API key" in reason


@pytest.mark.parametrize(
    "name,apex,expected",
    [
        ("api.example.com", "example.com", True),
        ("example.com", "example.com", True),
        ("*.example.com", "example.com", False),
        ("api.example.com.evil.net", "example.com", False),
        ("notexample.com", "example.com", False),
        ("", "example.com", False),
    ],
)
def test_valid_host_rejects_lookalikes(name, apex, expected):
    assert valid_host(name, apex) is expected


def test_names_from_filters_out_of_scope_entries():
    records = [
        {"names": ["api.example.com", "*.example.com", "evil.net"], "serial": "1",
         "issuer": None, "common_name": None, "not_before": None, "not_after": None,
         "source": "test"}
    ]
    assert names_from(records, "example.com") == {"api.example.com"}


def test_hostname_tags_flag_non_production_and_sensitive():
    assert "non-production" in _tags_for("staging.example.com", "example.com")
    assert "sensitive-service" in _tags_for("jenkins.example.com", "example.com")
    assert _tags_for("www.example.com", "example.com") == set()


def test_takeover_service_recognition():
    assert _service_for("mybucket.s3.amazonaws.com") == "AWS S3"
    assert _service_for("app.herokuapp.com") == "Heroku"
    assert _service_for("host.example.com") is None


@pytest.mark.parametrize(
    "a,b,expected",
    [("1.2.3", "1.10.0", True), ("2.0", "1.99", False), ("1.18.0", "1.18.0", False)],
)
def test_version_comparison(a, b, expected):
    assert _version_lt(a, b) is expected


def test_cpe_range_matching():
    node = {
        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.16.0",
        "versionEndExcluding": "1.20.1",
    }
    assert _cpe_matches(node, "nginx", "1.18.0")
    assert not _cpe_matches(node, "nginx", "1.21.0")
    assert not _cpe_matches(node, "apache", "1.18.0")


def test_exact_cpe_version_match():
    node = {"criteria": "cpe:2.3:a:gitlab:gitlab:14.2.1:*:*:*:*:*:*:*"}
    assert _cpe_matches(node, "gitlab", "14.2.1")
    assert not _cpe_matches(node, "gitlab", "14.3.0")


def test_severity_from_cvss_bands():
    assert Severity.from_cvss(9.8) is Severity.CRITICAL
    assert Severity.from_cvss(7.5) is Severity.HIGH
    assert Severity.from_cvss(5.0) is Severity.MEDIUM
    assert Severity.from_cvss(2.0) is Severity.LOW
    assert Severity.from_cvss(None) is Severity.INFO


class _FakeCollector(DnsRecordsCollector):
    def __init__(self):
        pass  # bypass network wiring; we only exercise the pure check methods

    name = "dns"


def test_spf_all_wildcard_is_flagged_high():
    findings = _FakeCollector()._email_auth_findings(
        "example.com", "domain:example.com", ["v=spf1 include:x +all"], ["v=DMARC1; p=reject"], ["mx"]
    )
    assert any(f.severity is Severity.HIGH and "+all" in f.title for f in findings)


def test_missing_spf_and_dmarc_are_flagged_when_mail_is_configured():
    findings = _FakeCollector()._email_auth_findings(
        "example.com", "domain:example.com", [], [], ["10 mx.example.com"]
    )
    titles = " ".join(f.title for f in findings)
    assert "No SPF" in titles and "No DMARC" in titles
    assert all(f.severity is Severity.MEDIUM for f in findings)


def test_dmarc_p_none_is_only_low():
    findings = _FakeCollector()._email_auth_findings(
        "example.com", "domain:example.com", ["v=spf1 -all"], ["v=DMARC1; p=none"], ["mx"]
    )
    assert [f.severity for f in findings] == [Severity.LOW]


async def test_asn_names_are_paired_with_the_right_number():
    """Regression: gathering over a set and zipping against sorted() mismatched them."""
    from openrecon.collectors.asn import AsnCollector
    from openrecon.collectors.base import CollectorContext
    from openrecon.core.graph import AttackSurfaceGraph
    from openrecon.core.models import Node

    cymru = {
        "34.216.184.93.origin.asn.cymru.com": ["13335 | 104.16.0.0/12 | US | arin | 2011-10-14"],
        "1.1.1.1.origin.asn.cymru.com": ["54113 | 151.101.0.0/16 | US | arin | 2016-01-01"],
        "AS13335.asn.cymru.com": ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"],
        "AS54113.asn.cymru.com": ["54113 | US | arin | 2011-01-01 | FASTLY, US"],
    }

    class _Dns:
        async def query(self, name, rdtype):
            return cymru.get(name, [])

    graph = AttackSurfaceGraph.seed("example.com")
    graph.add_node(Node.create(NodeType.IP, "93.184.216.34"))
    graph.add_node(Node.create(NodeType.IP, "1.1.1.1"))

    ctx = CollectorContext(config=Config(), http=None, dns=_Dns())  # type: ignore[arg-type]
    result = await AsnCollector(ctx).collect(graph)

    by_asn = {n.attrs["asn"]: n.attrs["organization"] for n in result.nodes if n.type is NodeType.ASN}
    assert by_asn["13335"].startswith("CLOUDFLARENET")
    assert by_asn["54113"].startswith("FASTLY")


@pytest.mark.parametrize(
    "cname,platform",
    [
        ("cname.vercel-dns.com", "Vercel"),
        ("8944ed4788442d43.vercel-dns-017.com", "Vercel"),
        ("cname.short.io", "Short.io"),
        ("hacker0x01.github.io", "GitHub Pages"),
        ("d3rxkn2g2bbsjp.cloudfront.net", "AWS CloudFront"),
        ("app.internal.example.com", None),
        (None, None),
    ],
)
def test_managed_platform_detection(cname, platform):
    from openrecon.collectors.resolve import managed_platform

    assert managed_platform(cname) == platform


async def test_third_party_addresses_are_not_auto_authorized():
    """Owning example.com does not authorize port-scanning Vercel's edge."""
    from openrecon.collectors.base import CollectorContext
    from openrecon.collectors.resolve import ResolveCollector
    from openrecon.core.graph import AttackSurfaceGraph
    from openrecon.core.models import Node
    from openrecon.scope import Scope

    answers = {
        ("app.example.com", "CNAME"): ["cname.vercel-dns.com"],
        ("app.example.com", "A"): ["76.76.21.21"],
        ("self.example.com", "A"): ["93.184.216.34"],
        ("example.com", "A"): ["93.184.216.34"],
    }

    class _Dns:
        async def query(self, name, rdtype):
            return answers.get((name, rdtype), [])

        async def resolves(self, name):
            cnames = await self.query(name, "CNAME")
            ips = await self.query(name, "A")
            return bool(ips or cnames), ips, (cnames[0] if cnames else None)

    graph = AttackSurfaceGraph.seed("example.com")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "app.example.com"))
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "self.example.com"))

    scope = Scope(include=["example.com", "*.example.com"])
    ctx = CollectorContext(config=Config(active=True), http=None, dns=_Dns(), scope=scope)  # type: ignore[arg-type]
    result = await ResolveCollector(ctx).collect(graph)

    assert scope.allows_ip("93.184.216.34"), "an address we host ourselves is scannable"
    assert not scope.allows_ip("76.76.21.21"), "Vercel's address is not ours to scan"

    vercel = next(n for n in result.nodes if n.label == "76.76.21.21")
    assert "shared-infrastructure" in vercel.tags
    assert vercel.attrs["managed_by"] == "Vercel"
    assert any("third-party platforms" in f.title for f in result.findings)


async def test_port_scanner_skips_shared_infrastructure():
    from openrecon.collectors.base import CollectorContext
    from openrecon.collectors.services import PortScanCollector
    from openrecon.core.graph import AttackSurfaceGraph
    from openrecon.core.models import Node
    from openrecon.scope import Scope

    graph = AttackSurfaceGraph.seed("example.com")
    graph.add_node(
        Node.create(
            NodeType.IP, "76.76.21.21", attrs={"managed_by": "Vercel"},
            tags={"shared-infrastructure"},
        )
    )
    scope = Scope(include=["*.example.com"])
    ctx = CollectorContext(config=Config(active=True), http=None, dns=None, scope=scope)  # type: ignore[arg-type]

    result = await PortScanCollector(ctx).collect(graph)
    assert result.nodes == []
    assert any("Vercel" in e for e in result.errors)


def test_explicit_network_declaration_re_enables_a_shared_address():
    from openrecon.scope import Scope

    scope = Scope(include=["*.example.com"], networks=["76.76.21.0/24"])
    assert scope.covered_by_network("76.76.21.21")
    assert not scope.covered_by_network("93.184.216.34")

    derived = Scope(include=["*.example.com"])
    derived.authorize_ip("93.184.216.34")
    assert derived.allows_ip("93.184.216.34")
    assert not derived.covered_by_network("93.184.216.34"), "derived is not a declaration"
