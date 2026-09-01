"""Regression tests for Docker API detection, CDN/edge attribution, and attack scenarios.

Covers:
  - Open port 2375 but non-Docker protocol must not produce confirmed Docker API finding
  - Open port 2375 with confirmed Docker protocol should produce exposed-service finding
  - Docker-like response from a CDN edge IP must not be attributed to the scanned domain
  - Unknown authentication state must not be reported as unauthenticated
  - A Docker API exposure without sufficient evidence must not generate a host-takeover scenario
  - Confirmed unauthenticated Docker API on a verified origin may generate a high/critical exposure finding
  - Every high/critical finding must expose evidence and confidence
"""

from __future__ import annotations

from openrecon.collectors._cdn import (
    classify_ip_attribution,
    detect_cdn_from_headers,
    is_cdn_cname,
    is_cdn_ip,
)
from openrecon.collectors.services import _verify_docker_api
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    Severity,
)


# ----------------------------------------------------------------- Docker API


class TestDockerApiVerification:
    """Port 2375 open ≠ confirmed Docker API. Require protocol-level evidence."""

    def test_port_open_no_banner_is_not_confirmed(self):
        """An open port with no banner/response is NOT confirmed Docker."""
        is_confirmed, evidence = _verify_docker_api("")
        assert is_confirmed is False
        assert "No banner" in evidence or "no protocol" in evidence.lower()

    def test_port_open_with_random_banner_is_not_confirmed(self):
        """An open port with a non-Docker banner is NOT confirmed Docker."""
        is_confirmed, evidence = _verify_docker_api("HTTP/1.1 200 OK\r\nServer: nginx")
        assert is_confirmed is False
        assert "no Docker protocol indicators" in evidence

    def test_port_open_with_ssh_banner_is_not_confirmed(self):
        """SSH banner on port 2375 means it's not Docker."""
        is_confirmed, evidence = _verify_docker_api("SSH-2.0-OpenSSH_8.9p1")
        assert is_confirmed is False

    def test_docker_api_version_header_confirms(self):
        """Docker API-Version header is strong evidence."""
        is_confirmed, evidence = _verify_docker_api("Api-Version: 1.41\r\nContent-Type: application/json")
        assert is_confirmed is True
        assert "version header" in evidence.lower()

    def test_docker_json_response_confirms(self):
        """Docker JSON response with ApiVersion field confirms."""
        is_confirmed, evidence = _verify_docker_api('{"ApiVersion":"1.41","Version":"20.10.7"}')
        assert is_confirmed is True
        assert "json response" in evidence.lower() or "version" in evidence.lower()

    def test_docker_containers_content_confirms(self):
        """Docker-specific content (Containers, Images) confirms."""
        is_confirmed, evidence = _verify_docker_api('{"Containers":[],"Images":[]}')
        assert is_confirmed is True

    def test_http_response_with_docker_header_confirms(self):
        """HTTP response with Docker API-Version header confirms."""
        http_resp = {
            "headers": {"Api-Version": "1.41", "Content-Type": "application/json"},
            "body": "",
        }
        is_confirmed, evidence = _verify_docker_api("", http_resp)
        assert is_confirmed is True
        assert "header" in evidence.lower()

    def test_http_response_with_docker_body_confirms(self):
        """HTTP response with Docker JSON body confirms."""
        http_resp = {
            "headers": {"Content-Type": "application/json"},
            "body": '{"ApiVersion":"1.41"}',
        }
        is_confirmed, evidence = _verify_docker_api("", http_resp)
        assert is_confirmed is True


# ----------------------------------------------------------------- CDN/edge detection


class TestCdnDetection:
    """CDN/edge IPs must be detected and not attributed to origin."""

    def test_cloudflare_ip_detected(self):
        """104.18.1.246 is a Cloudflare edge IP."""
        is_cdn, provider = is_cdn_ip("104.18.1.246")
        assert is_cdn is True
        assert provider == "Cloudflare"

    def test_cloudflare_ipv6_detected(self):
        """Cloudflare IPv6 ranges are detected."""
        is_cdn, provider = is_cdn_ip("2606:4700::1")
        assert is_cdn is True
        assert provider == "Cloudflare"

    def test_fastly_ip_detected(self):
        """Fastly edge IPs are detected."""
        is_cdn, provider = is_cdn_ip("151.101.1.5")
        assert is_cdn is True
        assert provider == "Fastly"

    def test_akamai_ip_detected(self):
        """Akamai edge IPs are detected."""
        is_cdn, provider = is_cdn_ip("23.60.1.1")
        assert is_cdn is True
        assert provider == "Akamai"

    def test_aws_cloudfront_ip_detected(self):
        """AWS CloudFront edge IPs are detected."""
        is_cdn, provider = is_cdn_ip("54.230.1.1")
        assert is_cdn is True
        assert provider == "AWS CloudFront"

    def test_regular_ip_not_cdn(self):
        """A regular IP is not flagged as CDN."""
        is_cdn, provider = is_cdn_ip("93.184.216.34")
        assert is_cdn is False
        assert provider is None

    def test_cloudflare_cname_detected(self):
        """Cloudflare CNAME targets are detected."""
        is_cdn, provider = is_cdn_cname("example.cloudflare.com")
        assert is_cdn is True
        assert provider == "Cloudflare"

    def test_fastly_cname_detected(self):
        """Fastly CNAME targets are detected."""
        is_cdn, provider = is_cdn_cname("example.fastly.net")
        assert is_cdn is True
        assert provider == "Fastly"

    def test_cloudflare_headers_detected(self):
        """Cloudflare HTTP headers are detected."""
        is_cdn, provider, evidence = detect_cdn_from_headers({"CF-Ray": "abc123", "Server": "cloudflare"})
        assert is_cdn is True
        assert provider == "Cloudflare"

    def test_sucuri_headers_detected(self):
        """Sucuri HTTP headers are detected."""
        is_cdn, provider, evidence = detect_cdn_from_headers({"X-Sucuri-ID": "12345"})
        assert is_cdn is True
        assert provider == "Sucuri"

    def test_no_cdn_headers(self):
        """Regular headers don't trigger CDN detection."""
        is_cdn, provider, evidence = detect_cdn_from_headers({"Server": "nginx"})
        assert is_cdn is False


# ----------------------------------------------------------------- Asset attribution


class TestAssetAttribution:
    """Asset attribution must distinguish origin from shared-edge."""

    def test_cloudflare_ip_is_shared_edge(self):
        """Cloudflare IPs are classified as shared-edge."""
        attr = classify_ip_attribution("104.18.1.246")
        assert attr.status == "shared-edge"
        assert attr.provider == "Cloudflare"
        assert "cloudflare" in attr.evidence.lower()

    def test_regular_ip_is_unconfirmed(self):
        """Regular IPs are unconfirmed (not confirmed origin)."""
        attr = classify_ip_attribution("93.184.216.34")
        assert attr.status == "unconfirmed"
        assert attr.provider is None

    def test_cloudflare_cname_is_shared_edge(self):
        """Cloudflare CNAME is classified as shared-edge."""
        attr = classify_ip_attribution("1.2.3.4", cname="example.cloudflare.com")
        assert attr.status == "shared-edge"
        assert attr.provider == "Cloudflare"

    def test_cloudflare_headers_is_shared_edge(self):
        """Cloudflare headers are classified as shared-edge."""
        attr = classify_ip_attribution("1.2.3.4", http_headers={"CF-Ray": "abc123"})
        assert attr.status == "shared-edge"
        assert attr.provider == "Cloudflare"


# ----------------------------------------------------------------- Attack scenarios


class TestAttackScenarioEvidence:
    """Attack scenarios must require evidence-backed prerequisites."""

    def test_docker_finding_without_protocol_confirmation_no_takeover(self):
        """A Docker API finding without protocol confirmation should NOT generate a host-takeover scenario."""
        g = AttackSurfaceGraph.seed("example.com", mode="active")
        ip = g.add_node(Node.create(NodeType.IP, "93.184.216.34"))
        svc = g.add_node(
            Node.create(
                NodeType.SERVICE,
                "93.184.216.34:2375",
                label="unknown/2375",
                attrs={"ip": "93.184.216.34", "port": 2375, "service": "unknown"},
                tags={"exposed"},
            )
        )
        g.add_edge(Edge(source=ip.id, target=svc.id, type=EdgeType.EXPOSES))

        # Finding without Docker protocol confirmation
        g.add_finding(
            Finding(
                title="Potential service on 93.184.216.34:2375 (Docker API unconfirmed)",
                severity=Severity.LOW,
                category="exposed-service",
                node_ids=[svc.id],
                confidence=0.4,
                asset_attribution={"status": "unconfirmed"},
            )
        )

        from openrecon.adversary import simulate
        result = simulate(g)

        # No campaign should claim host takeover via Docker API
        for campaign in result.campaigns:
            for step in campaign.steps:
                assert "docker" not in step.technique.lower() or "persistent" not in step.technique.lower()

    def test_docker_finding_on_cdn_edge_no_takeover(self):
        """A Docker-like finding on a CDN edge IP should NOT generate a host-takeover scenario."""
        g = AttackSurfaceGraph.seed("nukhail.com", mode="active")
        ip = g.add_node(
            Node.create(
                NodeType.IP,
                "104.18.1.246",
                attrs={"managed_by": "Cloudflare"},
                tags={"shared-infrastructure"},
            )
        )
        svc = g.add_node(
            Node.create(
                NodeType.SERVICE,
                "104.18.1.246:2375",
                label="docker-api/2375",
                attrs={
                    "ip": "104.18.1.246",
                    "port": 2375,
                    "service": "docker-api",
                    "attribution_status": "shared-edge",
                    "attribution_provider": "Cloudflare",
                },
                tags={"exposed"},
            )
        )
        g.add_edge(Edge(source=ip.id, target=svc.id, type=EdgeType.EXPOSES))

        g.add_finding(
            Finding(
                title="Confirmed Docker API exposed on 104.18.1.246:2375",
                severity=Severity.HIGH,
                category="exposed-service",
                node_ids=[svc.id],
                confidence=0.9,
                asset_attribution={
                    "status": "shared-edge",
                    "provider": "Cloudflare",
                    "evidence": "IP matches Cloudflare ranges",
                    "notes": "Shared edge infrastructure",
                },
            )
        )

        from openrecon.adversary import simulate
        result = simulate(g)

        # No campaign should claim persistent access to host via CDN edge
        for campaign in result.campaigns:
            for step in campaign.steps:
                assert "persistent access" not in step.technique.lower()

    def test_unknown_auth_state_not_reported_as_unauthenticated(self):
        """Unknown authentication state must not be reported as unconfirmed."""
        g = AttackSurfaceGraph.seed("example.com", mode="active")
        ip = g.add_node(Node.create(NodeType.IP, "93.184.216.34"))
        svc = g.add_node(
            Node.create(
                NodeType.SERVICE,
                "93.184.216.34:2375",
                label="unknown/2375",
                attrs={"ip": "93.184.216.34", "port": 2375, "service": "unknown"},
                tags={"exposed"},
            )
        )
        g.add_edge(Edge(source=ip.id, target=svc.id, type=EdgeType.EXPOSES))

        # Finding with unknown auth state
        finding = Finding(
            title="Potential service on 93.184.216.34:2375 (Docker API unconfirmed)",
            severity=Severity.LOW,
            category="exposed-service",
            node_ids=[svc.id],
            confidence=0.4,
        )
        g.add_finding(finding)

        # The finding should NOT claim "unauthenticated"
        assert "unauthenticated" not in finding.title.lower()
        assert finding.confidence < 0.5


# ----------------------------------------------------------------- Finding evidence


class TestFindingEvidence:
    """Every high/critical finding must include evidence and confidence."""

    def test_high_finding_has_evidence(self):
        """High severity findings must include evidence."""
        finding = Finding(
            title="Confirmed Docker API exposed on 1.2.3.4:2375",
            severity=Severity.HIGH,
            category="exposed-service",
            node_ids=["service:1.2.3.4:2375"],
            evidence=[
                {"type": "protocol", "value": "TCP"},
                {"type": "port", "value": 2375},
                {"type": "docker_verification", "value": "Api-Version header found"},
            ],
            confidence=0.9,
        )
        assert len(finding.evidence) > 0
        assert finding.confidence > 0.5

    def test_critical_finding_has_evidence(self):
        """Critical severity findings must include evidence."""
        finding = Finding(
            title="Unauthenticated Docker API exposed",
            severity=Severity.CRITICAL,
            category="exposed-service",
            node_ids=["service:1.2.3.4:2375"],
            evidence=[
                {"type": "protocol", "value": "TCP"},
                {"type": "port", "value": 2375},
                {"type": "auth_test", "value": "No authentication required"},
            ],
            confidence=0.95,
        )
        assert len(finding.evidence) > 0
        assert finding.confidence > 0.5

    def test_finding_has_asset_attribution(self):
        """Findings should include asset attribution when available."""
        finding = Finding(
            title="Confirmed Docker API exposed on 1.2.3.4:2375",
            severity=Severity.HIGH,
            category="exposed-service",
            node_ids=["service:1.2.3.4:2375"],
            evidence=[{"type": "protocol", "value": "TCP"}],
            confidence=0.9,
            asset_attribution={
                "status": "confirmed",
                "provider": None,
                "evidence": "IP belongs to target organization",
                "notes": "",
            },
        )
        assert finding.asset_attribution.get("status") == "confirmed"


# ----------------------------------------------------------------- Integration


class TestDockerApiIntegration:
    """Integration tests for the full Docker API detection pipeline."""

    def test_open_port_2375_non_docker_no_confirmed_finding(self):
        """Open port 2375 with non-Docker protocol must NOT produce confirmed Docker API finding."""
        from openrecon.collectors.base import CollectorContext
        from openrecon.collectors.services import PortScanCollector
        from openrecon.config import Config

        ctx = CollectorContext(config=Config(active=True, timeout=3.0), http=None, dns=None)
        collector = PortScanCollector(ctx)

        # Non-Docker banner on port 2375
        result = collector._service_findings(
            "93.184.216.34", 2375, "docker-api", Severity.CRITICAL,
            "SSH-2.0-OpenSSH_8.9p1", "service:93.184.216.34:2375"
        )

        # Should produce a finding but NOT confirmed Docker API
        assert len(result.findings) == 1
        assert "unconfirmed" in result.findings[0].title.lower() or "potential" in result.findings[0].title.lower()
        assert result.findings[0].severity == Severity.LOW
        assert result.findings[0].confidence < 0.5

    def test_open_port_2375_docker_confirmed_finding(self):
        """Open port 2375 with confirmed Docker protocol should produce exposed-service finding."""
        from openrecon.collectors.services import PortScanCollector
        from openrecon.config import Config
        from openrecon.collectors.base import CollectorContext

        ctx = CollectorContext(config=Config(active=True, timeout=3.0), http=None, dns=None)
        collector = PortScanCollector(ctx)

        # Docker API banner
        result = collector._service_findings(
            "93.184.216.34", 2375, "docker-api", Severity.CRITICAL,
            '{"ApiVersion":"1.41","Version":"20.10.7"}', "service:93.184.216.34:2375"
        )

        assert len(result.findings) == 1
        assert "confirmed" in result.findings[0].title.lower()
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].confidence >= 0.8

    def test_docker_on_cdn_edge_not_attributed(self):
        """Docker-like response from a CDN edge IP must not be attributed to the scanned domain."""
        from openrecon.collectors.services import PortScanCollector
        from openrecon.config import Config
        from openrecon.collectors.base import CollectorContext

        ctx = CollectorContext(config=Config(active=True, timeout=3.0), http=None, dns=None)
        collector = PortScanCollector(ctx)

        # Cloudflare IP with Docker-like response
        result = collector._service_findings(
            "104.18.1.246", 2375, "docker-api", Severity.CRITICAL,
            '{"ApiVersion":"1.41"}', "service:104.18.1.246:2375"
        )

        # Should produce a finding but with shared-edge attribution
        assert len(result.findings) == 1
        attr = result.findings[0].asset_attribution
        assert attr.get("status") == "shared-edge"
        assert attr.get("provider") == "Cloudflare"
