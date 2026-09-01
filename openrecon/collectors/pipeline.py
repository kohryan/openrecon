"""Staged exposure detection pipeline.

Every confirmed exposure passes through the same evidence chain. Each stage
produces structured evidence; a finding's confidence and severity are bounded
by how far the chain was followed and what it proved.

Pipeline stages:
  1. IP ownership      — who operates this address?
  2. Target attribution — does it belong to the scanned organisation?
  3. Port reachable     — is the TCP port open?
  4. Protocol fingerprint — what does the banner/response say it is?
  5. Service confirmed  — does protocol-level verification agree?
  6. Authentication state — does it require credentials? (safe probes only)
  7. Exposure assessment — combine all evidence into severity + confidence.

A finding that stops at stage 3 ("port open, nothing more known") is reported
as potential/low. A finding that reaches stage 7 with strong evidence at
every step may be reported as confirmed/critical. No stage is ever skipped
to inflate severity.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from openrecon.collectors._cdn import classify_ip_attribution, is_cdn_ip
from openrecon.core.models import Severity


# ----------------------------------------------------------------- stage 1-2: ownership & attribution


@dataclass
class OwnershipResult:
    """Stage 1: who operates this IP?"""
    status: str  # "owned" | "shared" | "cdn" | "unknown"
    provider: str | None = None
    asn: str | None = None
    evidence: str = ""


@dataclass
class AttributionResult:
    """Stage 2: does this belong to the target organisation?"""
    status: str  # "confirmed" | "probable" | "unconfirmed" | "shared-edge"
    provider: str | None = None
    evidence: str = ""
    notes: str = ""
    confidence: float = 0.5  # 0-1, how confident is the attribution


def check_ownership(ip_str: str, cname: str | None = None) -> OwnershipResult:
    """Stage 1: determine who operates this IP."""
    # Check CDN/edge first
    is_cdn, provider = is_cdn_ip(ip_str)
    if is_cdn:
        return OwnershipResult(
            status="cdn",
            provider=provider,
            evidence=f"IP {ip_str} matches {provider} published edge ranges",
        )

    # Check CNAME for managed platform
    if cname:
        from openrecon.collectors._cdn import is_cdn_cname
        is_cdn_c, provider_c = is_cdn_cname(cname)
        if is_cdn_c:
            return OwnershipResult(
                status="cdn",
                provider=provider_c,
                evidence=f"CNAME {cname} matches {provider_c} infrastructure",
            )

    # Check if private
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private:
            return OwnershipResult(
                status="owned",
                evidence=f"IP {ip_str} is private (RFC1918) — internal infrastructure",
            )
    except ValueError:
        pass

    return OwnershipResult(
        status="unknown",
        evidence=f"IP {ip_str} ownership not determined from passive data",
    )


def check_attribution(
    ip_str: str,
    target: str,
    cname: str | None = None,
    scope_declared: bool = False,
) -> AttributionResult:
    """Stage 2: is this IP attributable to the target organisation?"""
    ownership = check_ownership(ip_str, cname)

    if ownership.status == "cdn":
        return AttributionResult(
            status="shared-edge",
            provider=ownership.provider,
            evidence=ownership.evidence,
            notes=(
                f"IP belongs to {ownership.provider} edge infrastructure. "
                "Services observed here cannot be attributed to the target origin "
                "without additional evidence (e.g., origin IP from passive DNS)."
            ),
            confidence=0.9,
        )

    if ownership.status == "shared":
        return AttributionResult(
            status="shared-edge",
            provider=ownership.provider,
            evidence=ownership.evidence,
            notes="IP belongs to a shared hosting platform, not the target.",
            confidence=0.8,
        )

    if scope_declared:
        return AttributionResult(
            status="confirmed",
            evidence=f"IP {ip_str} declared in scope for target {target}",
            confidence=0.95,
        )

    # Public IP, not CDN, not shared — probable but not confirmed
    if ownership.status == "owned":
        return AttributionResult(
            status="probable",
            evidence=f"IP {ip_str} is a public address, not known shared infrastructure",
            notes="Attribution is probable but not confirmed without scope declaration or ASN match.",
            confidence=0.6,
        )

    return AttributionResult(
        status="unconfirmed",
        evidence=f"Could not confirm {ip_str} belongs to {target}",
        confidence=0.2,
    )


# ----------------------------------------------------------------- stage 3: port reachable


@dataclass
class PortReachability:
    """Stage 3: is the port open and what did we see?"""
    reachable: bool = False
    banner: str = ""
    response_time_ms: float = 0.0
    error: str = ""


async def check_port_reachable(
    ip: str,
    port: int,
    timeout: float = 5.0,
) -> PortReachability:
    """Stage 3: TCP connect + banner grab."""
    import time

    result = PortReachability()
    start = time.monotonic()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        result.reachable = True
        result.response_time_ms = (time.monotonic() - start) * 1000

        # Try to read banner
        banner = ""
        try:
            with contextlib.suppress(asyncio.TimeoutError, OSError):
                data = await asyncio.wait_for(reader.read(512), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
        finally:
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)

        result.banner = banner
    except TimeoutError:
        result.error = "Connection timed out"
    except OSError as exc:
        result.error = str(exc)

    return result


# ----------------------------------------------------------------- stage 4: protocol fingerprint


@dataclass
class ProtocolFingerprint:
    """Stage 4: what does the banner/response identify?"""
    service: str = "unknown"
    product: str = ""
    version: str = ""
    confidence: float = 0.0
    evidence: str = ""
    hints: dict[str, Any] = field(default_factory=dict)


# Banner patterns that identify services with high confidence
# Pattern: (regex, service_name, product_group)
BANNER_PATTERNS: list[tuple[str, str, str]] = [
    # Docker API
    (r'"ApiVersion"\s*:\s*"[\d.]+"', "docker-api", "docker"),
    (r"Docker/", "docker-api", "docker"),
    # Databases
    (r"mysql", "mysql", "mysql"),
    (r"mariadb", "mariadb", "mariadb"),
    (r"postgresql", "postgresql", "postgresql"),
    (r"MongoDB", "mongodb", "mongodb"),
    (r"redis", "redis", "redis"),
    (r"elasticsearch", "elasticsearch", "elasticsearch"),
    # Remote access
    (r"SSH-2\.0-", "ssh", "ssh"),
    (r"RFB \d{3}\.\d{3}", "vnc", "vnc"),
    (r"220.*FTP", "ftp", "ftp"),
    # Web
    (r"HTTP/1\.[01]", "http", "http"),
    # Message queues
    (r"AMQP", "amqp", "rabbitmq"),
    (r"Kafka", "kafka", "kafka"),
]

# Port → expected service (weak evidence alone)
PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2375: "docker-api",
    2376: "docker-api-tls",
    3306: "mysql",
    3389: "rdp",
    4444: "http-alt",
    5000: "http-alt",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes-api",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8086: "influxdb",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
}


def fingerprint_protocol(
    port: int,
    banner: str,
    http_headers: dict[str, str] | None = None,
) -> ProtocolFingerprint:
    """Stage 4: identify service from banner/response."""
    result = ProtocolFingerprint()

    if not banner and not http_headers:
        # No data — fall back to port-based guess (weak)
        if port in PORT_SERVICE_MAP:
            result.service = PORT_SERVICE_MAP[port]
            result.confidence = 0.2
            result.evidence = f"No banner; service guessed from port {port} (weak evidence)"
        else:
            result.evidence = "No banner and unknown port"
        return result

    # Try banner patterns
    check_text = banner or ""
    if http_headers:
        check_text += " " + " ".join(f"{k}: {v}" for k, v in http_headers.items())

    for pattern, service, product in BANNER_PATTERNS:
        if re.search(pattern, check_text, re.IGNORECASE):
            result.service = service
            result.product = product
            result.confidence = 0.7
            result.evidence = f"Banner matches {service} pattern: /{pattern}/"
            break

    # Extract version from banner
    version_match = re.search(
        r"([A-Za-z][A-Za-z0-9\-+]{1,30})[/_ ]v?(\d+(?:\.\d+)+[\w.\-]*)",
        banner or "",
    )
    if version_match:
        result.product = version_match.group(1).lower()
        result.version = version_match.group(2)
        result.hints["version_source"] = "banner"

    # If no pattern matched but we have a banner, note the mismatch
    if not result.service != "unknown" and banner:
        # Check if banner contradicts port-based expectation
        expected = PORT_SERVICE_MAP.get(port)
        if expected and result.service != expected:
            result.hints["port_banner_mismatch"] = True
            result.hints["port_expected"] = expected
            result.hints["banner_identified"] = result.service

    # HTTP header-based detection
    if http_headers:
        server = http_headers.get("server", "")
        if server and not result.product:
            result.product = server.split("/")[0].lower()
            if not result.version:
                ver = re.search(r"/([\d.]+)", server)
                if ver:
                    result.version = ver.group(1)

    return result


# ----------------------------------------------------------------- stage 5: service confirmed


@dataclass
class ServiceConfirmation:
    """Stage 5: protocol-level service verification."""
    confirmed: bool = False
    confidence: float = 0.0
    evidence: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def confirm_docker_api(banner: str, http_response: dict | None = None) -> ServiceConfirmation:
    """Stage 5a: confirm Docker API with protocol-specific evidence."""
    result = ServiceConfirmation()

    if not banner and not http_response:
        result.evidence = "No data available for protocol verification"
        return result

    banner_bytes = (banner or "").encode("utf-8", errors="replace")

    # Strong: Docker API version in response
    if b"Api-Version" in banner_bytes or b'"ApiVersion"' in banner_bytes:
        result.confirmed = True
        result.confidence = 0.95
        result.evidence = "Docker API version identifier found in response"
        # Extract version
        ver = re.search(r'"ApiVersion"\s*:\s*"([\d.]+)"', banner)
        if ver:
            result.details["docker_version"] = ver.group(1)
        return result

    # Strong: Docker-specific JSON structure
    if b'"Containers"' in banner_bytes or b'"Images"' in banner_bytes:
        result.confirmed = True
        result.confidence = 0.9
        result.evidence = "Docker-specific JSON structure (Containers/Images) found"
        return result

    # Medium: Docker keyword + container-related content
    if b"docker" in banner_bytes.lower() and (b"Container" in banner_bytes or b"Image" in banner_bytes):
        result.confirmed = True
        result.confidence = 0.8
        result.evidence = "Docker keywords with container/image content found"
        return result

    # HTTP-based confirmation
    if http_response:
        headers = http_response.get("headers", {})
        body = http_response.get("body", "")

        if "Api-Version" in headers or any(k.lower() == "api-version" for k in headers):
            result.confirmed = True
            result.confidence = 0.95
            result.evidence = "Docker API-Version HTTP header present"
            return result

        if '"ApiVersion"' in body or '"Containers"' in body:
            result.confirmed = True
            result.confidence = 0.9
            result.evidence = "Docker API JSON structure in HTTP body"
            return result

    # Not confirmed
    result.evidence = "No Docker protocol indicators found"
    if banner:
        result.evidence += f"; banner: {banner[:100]}"
    return result


def confirm_database(
    service: str,
    banner: str,
    port: int,
) -> ServiceConfirmation:
    """Stage 5b: confirm database service with protocol-specific evidence."""
    result = ServiceConfirmation()
    banner_lower = (banner or "").lower()

    # Service-specific confirmation patterns
    DB_PATTERNS = {
        "mysql": [b"mysql", b"mariadb", b"5.7.", b"8.0.", b"10."],
        "postgresql": [b"postgresql", b"pg_", b"psql"],
        "mongodb": [b"mongodb", b"mongo"],
        "redis": [b"redis", b"+PONG", b"-NOAUTH"],
        "elasticsearch": [b"elasticsearch", b"cluster_name"],
        "mssql": [b"mssql", b"microsoft sql"],
        "oracle": [b"oracle", b"tns"],
    }

    patterns = DB_PATTERNS.get(service, [])
    banner_bytes = (banner or "").encode("utf-8", errors="replace")
    for pattern in patterns:
        if isinstance(pattern, str):
            if pattern.encode() in banner_bytes:
                result.confirmed = True
                result.confidence = 0.85
                result.evidence = f"Database protocol pattern matched: {pattern}"
                return result
        else:
            if pattern in banner_bytes:
                result.confirmed = True
                result.confidence = 0.85
                result.evidence = f"Database protocol pattern matched: {pattern}"
                return result

    # Port match + any banner = medium confidence
    if port in PORT_SERVICE_MAP and PORT_SERVICE_MAP[port] == service and banner:
        result.confirmed = True
        result.confidence = 0.5
        result.evidence = f"Port {port} matches expected {service} port, banner present but no protocol confirmation"

    result.evidence = f"No {service} protocol indicators found"
    return result


# ----------------------------------------------------------------- stage 6: authentication state


@dataclass
class AuthState:
    """Stage 6: what do we know about authentication requirements?"""
    state: str = "unknown"  # "required" | "none" | "unknown"
    confidence: float = 0.0
    evidence: str = ""
    safe_to_probe: bool = True  # whether we attempted a safe probe


async def check_auth_state(
    service: str,
    ip: str,
    port: int,
    banner: str,
) -> AuthState:
    """Stage 6: determine authentication state via SAFE probes only.

    We never brute-force, never exploit, never send malicious payloads.
    We only observe what the service voluntarily tells us.
    """
    result = AuthState()

    # Docker API: check /version endpoint (read-only, safe)
    if service == "docker-api":
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5.0,
            )
            # Send minimal HTTP GET /version
            request = f"GET /version HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            response = b""
            try:
                with contextlib.suppress(asyncio.TimeoutError, OSError):
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            finally:
                writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await writer.wait_closed()

            resp_str = response.decode("utf-8", errors="replace")

            # If we get 200 OK with Docker version, no auth required
            if "200 OK" in resp_str and "ApiVersion" in resp_str:
                result.state = "none"
                result.confidence = 0.9
                result.evidence = "Docker /version endpoint returned 200 OK with API version — no authentication required"
                return result

            # If we get 401/403, auth is required
            if "401" in resp_str or "403" in resp_str:
                result.state = "required"
                result.confidence = 0.85
                result.evidence = f"Docker API returned {resp_str[:50]} — authentication appears required"
                return result

            # Connection accepted but unexpected response
            result.state = "unknown"
            result.confidence = 0.3
            result.evidence = f"Docker API responded but auth state unclear: {resp_str[:100]}"
            return result

        except (TimeoutError, OSError) as exc:
            result.state = "unknown"
            result.confidence = 0.0
            result.evidence = f"Could not probe auth state: {exc}"
            return result

    # Redis: check for NOAUTH response
    if service == "redis":
        if "NOAUTH" in banner.upper():
            result.state = "none"
            result.confidence = 0.9
            result.evidence = "Redis banner contains NOAUTH — no authentication required"
            return result

    # MySQL: check for access denied in banner
    if service in ("mysql", "mariadb"):
        if "access denied" in banner.lower():
            result.state = "required"
            result.confidence = 0.8
            result.evidence = "MySQL returned access denied — authentication required"
            return result

    # MongoDB: check for unauthorized in banner
    if service == "mongodb":
        if "unauthorized" in banner.lower() or "authentication" in banner.lower():
            result.state = "required"
            result.confidence = 0.7
            result.evidence = "MongoDB response indicates authentication"
            return result

    # Default: unknown (we didn't probe)
    result.state = "unknown"
    result.confidence = 0.0
    result.evidence = f"No safe auth probe available for {service}"
    return result


# ----------------------------------------------------------------- stage 7: exposure assessment


@dataclass
class ExposureAssessment:
    """Stage 7: final exposure assessment combining all evidence."""
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    exposure_type: str = ""  # "potential" | "exposed" | "unauthenticated"
    evidence_chain: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""


def assess_exposure(
    service: str,
    attribution: AttributionResult,
    port: PortReachability,
    fingerprint: ProtocolFingerprint,
    confirmation: ServiceConfirmation,
    auth_state: AuthState,
) -> ExposureAssessment:
    """Stage 7: combine all evidence into final assessment."""
    result = ExposureAssessment()
    result.evidence_chain = [
        {"stage": "attribution", "status": attribution.status, "evidence": attribution.evidence},
        {"stage": "port", "reachable": port.reachable, "banner": port.banner[:100]},
        {"stage": "fingerprint", "service": fingerprint.service, "confidence": fingerprint.confidence},
        {"stage": "confirmation", "confirmed": confirmation.confirmed, "confidence": confirmation.confidence},
        {"stage": "auth", "state": auth_state.state, "confidence": auth_state.confidence},
    ]

    # If attribution is shared-edge, cap severity regardless of other evidence
    if attribution.status == "shared-edge":
        result.severity = Severity.INFO
        result.confidence = 0.2
        result.exposure_type = "potential"
        result.notes = (
            f"IP attributed to {attribution.provider} edge infrastructure. "
            "Service cannot be confirmed as belonging to target origin. "
            "Downgraded to informational."
        )
        return result

    # If attribution is unconfirmed, cap at LOW
    if attribution.status == "unconfirmed":
        max_severity = Severity.LOW
    elif attribution.status == "probable":
        max_severity = Severity.MEDIUM
    else:  # confirmed
        max_severity = Severity.CRITICAL

    # If service not confirmed, cap at LOW
    if not confirmation.confirmed:
        result.severity = Severity.LOW
        result.confidence = min(0.4, fingerprint.confidence * 0.5)
        result.exposure_type = "potential"
        result.notes = f"Service {service} not confirmed via protocol verification"
        return result

    # Service confirmed — assess exposure severity
    # Base severity by service type
    CRITICAL_SERVICES = {"docker-api", "redis", "mysql", "postgresql", "mongodb", "elasticsearch"}
    HIGH_SERVICES = {"kubernetes-api", "kubelet", "kibana", "rabbitmq-mgmt", "couchdb", "influxdb"}
    MEDIUM_SERVICES = {"telnet", "ftp", "vnc", "rdp", "smb", "msrpc", "netbios"}

    if service in CRITICAL_SERVICES:
        base_severity = Severity.CRITICAL
    elif service in HIGH_SERVICES:
        base_severity = Severity.HIGH
    elif service in MEDIUM_SERVICES:
        base_severity = Severity.MEDIUM
    else:
        base_severity = Severity.LOW

    # Adjust for auth state
    if auth_state.state == "none":
        # Unauthenticated — full severity
        result.exposure_type = "unauthenticated"
        result.severity = base_severity
    elif auth_state.state == "required":
        # Auth required — downgrade one level
        result.exposure_type = "exposed"
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        idx = severity_order.index(base_severity)
        result.severity = severity_order[max(0, idx - 1)]
    else:
        # Unknown auth — assume worst case but note uncertainty
        result.exposure_type = "exposed"
        result.severity = base_severity

    # Cap by attribution (compare by severity weight, not string value)
    severity_weights = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    if severity_weights[result.severity] > severity_weights[max_severity]:
        result.severity = max_severity

    # Confidence = product of all stage confidences
    result.confidence = min(
        attribution.confidence,
        fingerprint.confidence,
        confirmation.confidence,
        max(auth_state.confidence, 0.3),  # auth unknown shouldn't zero out everything
    )

    result.notes = (
        f"Service {service} confirmed on {attribution.status} infrastructure. "
        f"Auth state: {auth_state.state}. "
        f"Exposure type: {result.exposure_type}."
    )
    return result


# ----------------------------------------------------------------- full pipeline


@dataclass
class PipelineResult:
    """Full pipeline result for one IP:port."""
    ip: str
    port: int
    ownership: OwnershipResult | None = None
    attribution: AttributionResult | None = None
    port_reachability: PortReachability | None = None
    fingerprint: ProtocolFingerprint | None = None
    confirmation: ServiceConfirmation | None = None
    auth_state: AuthState | None = None
    assessment: ExposureAssessment | None = None

    @property
    def should_report(self) -> bool:
        """Whether this result should produce a finding."""
        if not self.port_reachability or not self.port_reachability.reachable:
            return False
        if not self.assessment:
            return False
        # Don't report shared-edge as findings
        if self.attribution and self.attribution.status == "shared-edge":
            return False
        return True


async def run_pipeline(
    ip: str,
    port: int,
    target: str,
    cname: str | None = None,
    scope_declared: bool = False,
) -> PipelineResult:
    """Run the full exposure detection pipeline for one IP:port."""
    result = PipelineResult(ip=ip, port=port)

    # Stage 1: IP ownership
    result.ownership = check_ownership(ip, cname)

    # Stage 2: Target attribution
    result.attribution = check_attribution(ip, target, cname, scope_declared)

    # Stage 3: Port reachable
    result.port_reachability = await check_port_reachable(ip, port)

    if not result.port_reachability.reachable:
        return result

    # Stage 4: Protocol fingerprint
    result.fingerprint = fingerprint_protocol(port, result.port_reachability.banner)

    # Stage 5: Service confirmed
    service = result.fingerprint.service
    if service == "docker-api":
        result.confirmation = confirm_docker_api(result.port_reachability.banner)
    elif service in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch", "mssql", "oracle"):
        result.confirmation = confirm_database(service, result.port_reachability.banner, port)
    else:
        result.confirmation = ServiceConfirmation(
            confirmed=result.fingerprint.confidence >= 0.5,
            confidence=result.fingerprint.confidence,
            evidence=result.fingerprint.evidence,
        )

    # Stage 6: Authentication state
    result.auth_state = await check_auth_state(service, ip, port, result.port_reachability.banner)

    # Stage 7: Exposure assessment
    result.assessment = assess_exposure(
        service=service,
        attribution=result.attribution,
        port=result.port_reachability,
        fingerprint=result.fingerprint,
        confirmation=result.confirmation,
        auth_state=result.auth_state,
    )

    return result
