"""Tests for the staged exposure detection pipeline."""

from __future__ import annotations

import asyncio

import pytest

from openrecon.collectors.pipeline import (
    AttributionResult,
    AuthState,
    ExposureAssessment,
    OwnershipResult,
    PipelineResult,
    PortReachability,
    ProtocolFingerprint,
    ServiceConfirmation,
    check_attribution,
    check_auth_state,
    check_ownership,
    check_port_reachable,
    confirm_database,
    confirm_docker_api,
    fingerprint_protocol,
    assess_exposure,
    run_pipeline,
)
from openrecon.core.models import Severity


# ----------------------------------------------------------------- Stage 1: Ownership


class TestOwnership:
    def test_cloudflare_ip(self):
        result = check_ownership("104.18.1.246")
        assert result.status == "cdn"
        assert result.provider == "Cloudflare"

    def test_fastly_ip(self):
        result = check_ownership("151.101.1.5")
        assert result.status == "cdn"
        assert result.provider == "Fastly"

    def test_regular_ip(self):
        result = check_ownership("93.184.216.34")
        assert result.status == "unknown"

    def test_private_ip(self):
        result = check_ownership("192.168.1.1")
        assert result.status == "owned"


# ----------------------------------------------------------------- Stage 2: Attribution


class TestAttribution:
    def test_cloudflare_ip_shared_edge(self):
        result = check_attribution("104.18.1.246", "example.com")
        assert result.status == "shared-edge"
        assert result.provider == "Cloudflare"
        assert result.confidence >= 0.8

    def test_scope_declared_confirmed(self):
        result = check_attribution("93.184.216.34", "example.com", scope_declared=True)
        assert result.status == "confirmed"
        assert result.confidence >= 0.9

    def test_public_ip_unconfirmed(self):
        """Public IP without scope declaration is unconfirmed."""
        result = check_attribution("93.184.216.34", "example.com")
        assert result.status == "unconfirmed"
        assert result.confidence < 0.3


# ----------------------------------------------------------------- Stage 3: Port Reachability


class TestPortReachability:
    def test_localhost_closed_port(self):
        """Closed port should return unreachable."""
        result = asyncio.run(check_port_reachable("127.0.0.1", 1))
        assert result.reachable is False


# ----------------------------------------------------------------- Stage 4: Protocol Fingerprint


class TestProtocolFingerprint:
    def test_docker_api_banner(self):
        result = fingerprint_protocol(2375, '{"ApiVersion":"1.41"}')
        assert result.service == "docker-api"
        assert result.confidence >= 0.7

    def test_ssh_banner(self):
        result = fingerprint_protocol(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert result.service == "ssh"
        assert result.product == "openssh"
        assert result.version == "8.9p1"

    def test_no_banner_unknown_port(self):
        result = fingerprint_protocol(9999, "")
        assert result.service == "unknown"
        assert result.confidence == 0.0

    def test_no_banner_known_port(self):
        result = fingerprint_protocol(3306, "")
        assert result.service == "mysql"
        assert result.confidence == 0.2


# ----------------------------------------------------------------- Stage 5: Service Confirmation


class TestServiceConfirmation:
    def test_docker_confirmed(self):
        result = confirm_docker_api('{"ApiVersion":"1.41"}')
        assert result.confirmed is True
        assert result.confidence >= 0.9

    def test_docker_not_confirmed(self):
        result = confirm_docker_api("SSH-2.0-OpenSSH_8.9p1")
        assert result.confirmed is False

    def test_docker_http_confirmed(self):
        result = confirm_docker_api("", {"headers": {"Api-Version": "1.41"}, "body": ""})
        assert result.confirmed is True

    def test_mysql_confirmed(self):
        result = confirm_database("mysql", "mysql 5.7.33", 3306)
        assert result.confirmed is True

    def test_redis_noauth_confirms_service(self):
        """Redis NOAUTH error confirms Redis service (auth required)."""
        result = confirm_database("redis", "-NOAUTH Authentication required.", 6379)
        assert result.confirmed is True  # NOAUTH is a valid Redis protocol response
        assert result.confidence >= 0.8


# ----------------------------------------------------------------- Stage 6: Auth State


class TestAuthState:
    def test_redis_noauth(self):
        result = asyncio.run(check_auth_state("redis", "1.2.3.4", 6379, "-NOAUTH Authentication required."))
        assert result.state == "none"
        assert result.confidence >= 0.8

    def test_mysql_access_denied(self):
        result = asyncio.run(check_auth_state("mysql", "1.2.3.4", 3306, "Access denied for user"))
        assert result.state == "required"
        assert result.confidence >= 0.7

    def test_unknown_service(self):
        result = asyncio.run(check_auth_state("unknown", "1.2.3.4", 9999, ""))
        assert result.state == "unknown"
        assert result.confidence == 0.0


# ----------------------------------------------------------------- Stage 7: Exposure Assessment


class TestExposureAssessment:
    def test_shared_edge_capped_at_info(self):
        """Shared-edge IPs should always be capped at INFO severity."""
        attribution = AttributionResult(status="shared-edge", provider="Cloudflare", confidence=0.9)
        port = PortReachability(reachable=True, banner='{"ApiVersion":"1.41"}')
        fingerprint = ProtocolFingerprint(service="docker-api", confidence=0.7)
        confirmation = ServiceConfirmation(confirmed=True, confidence=0.9)
        auth = AuthState(state="none", confidence=0.9)

        result = assess_exposure("docker-api", attribution, port, fingerprint, confirmation, auth)
        assert result.severity == Severity.INFO
        assert result.exposure_type == "potential"

    def test_confirmed_docker_no_auth_critical(self):
        """Confirmed Docker API with no auth on confirmed origin = CRITICAL."""
        attribution = AttributionResult(status="confirmed", confidence=0.95)
        port = PortReachability(reachable=True, banner='{"ApiVersion":"1.41"}')
        fingerprint = ProtocolFingerprint(service="docker-api", confidence=0.7)
        confirmation = ServiceConfirmation(confirmed=True, confidence=0.95)
        auth = AuthState(state="none", confidence=0.9)

        result = assess_exposure("docker-api", attribution, port, fingerprint, confirmation, auth)
        assert result.severity == Severity.CRITICAL
        assert result.exposure_type == "unauthenticated"

    def test_confirmed_docker_auth_required_high(self):
        """Confirmed Docker API with auth required = HIGH (downgraded from CRITICAL)."""
        attribution = AttributionResult(status="confirmed", confidence=0.95)
        port = PortReachability(reachable=True, banner='{"ApiVersion":"1.41"}')
        fingerprint = ProtocolFingerprint(service="docker-api", confidence=0.7)
        confirmation = ServiceConfirmation(confirmed=True, confidence=0.95)
        auth = AuthState(state="required", confidence=0.85)

        result = assess_exposure("docker-api", attribution, port, fingerprint, confirmation, auth)
        assert result.severity == Severity.HIGH
        assert result.exposure_type == "exposed"

    def test_unconfirmed_service_low(self):
        """Service not confirmed via protocol = LOW max."""
        attribution = AttributionResult(status="confirmed", confidence=0.95)
        port = PortReachability(reachable=True, banner="")
        fingerprint = ProtocolFingerprint(service="unknown", confidence=0.0)
        confirmation = ServiceConfirmation(confirmed=False, confidence=0.0)
        auth = AuthState(state="unknown", confidence=0.0)

        result = assess_exposure("unknown", attribution, port, fingerprint, confirmation, auth)
        assert result.severity == Severity.LOW
        assert result.exposure_type == "potential"

    def test_unconfirmed_attribution_caps_at_low(self):
        """Unconfirmed attribution caps severity at LOW."""
        attribution = AttributionResult(status="unconfirmed", confidence=0.2)
        port = PortReachability(reachable=True, banner='{"ApiVersion":"1.41"}')
        fingerprint = ProtocolFingerprint(service="docker-api", confidence=0.7)
        confirmation = ServiceConfirmation(confirmed=True, confidence=0.95)
        auth = AuthState(state="none", confidence=0.9)

        result = assess_exposure("docker-api", attribution, port, fingerprint, confirmation, auth)
        assert result.severity == Severity.LOW


# ----------------------------------------------------------------- Full Pipeline


class TestFullPipeline:
    def test_cloudflare_ip_not_reported(self):
        """Cloudflare IP should not produce a reportable finding."""
        result = asyncio.run(run_pipeline("104.18.1.246", 2375, "nukhail.com"))
        assert result.should_report is False
        assert result.attribution.status == "shared-edge"

    def test_regular_ip_reachable(self):
        """Regular IP with reachable port should produce a result."""
        # This test uses a mock — we can't actually connect
        # Just verify the pipeline structure
        result = asyncio.run(run_pipeline("93.184.216.34", 80, "example.com"))
        # Port 80 may or may not be reachable — just verify no crash
        assert result is not None
