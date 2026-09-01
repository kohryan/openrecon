"""Exposed services.

`ports` (active) opens TCP connections to in-scope hosts and grabs banners.
`shodan` (passive) asks Shodan what it already knows, so you can inventory
exposure without touching the target at all.

Service detection is protocol-aware: an open TCP port alone does NOT confirm
a service type. We distinguish between:
  - port reachable (potential service)
  - protocol fingerprint match (probable service)
  - confirmed service (protocol-verified with evidence)
"""

from __future__ import annotations

import asyncio
import contextlib
import re

from openrecon.collectors._cdn import classify_ip_attribution, is_cdn_ip
from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult,
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    ScanMode,
    Severity,
)

# port -> (service name, severity if reachable from the internet)
PORT_CATALOG: dict[int, tuple[str, Severity]] = {
    21: ("ftp", Severity.MEDIUM),
    22: ("ssh", Severity.INFO),
    23: ("telnet", Severity.HIGH),
    25: ("smtp", Severity.INFO),
    53: ("dns", Severity.INFO),
    80: ("http", Severity.INFO),
    110: ("pop3", Severity.LOW),
    135: ("msrpc", Severity.HIGH),
    139: ("netbios", Severity.HIGH),
    143: ("imap", Severity.LOW),
    443: ("https", Severity.INFO),
    445: ("smb", Severity.CRITICAL),
    993: ("imaps", Severity.INFO),
    995: ("pop3s", Severity.INFO),
    1433: ("mssql", Severity.CRITICAL),
    1521: ("oracle", Severity.CRITICAL),
    2375: ("docker-api", Severity.CRITICAL),
    2376: ("docker-api-tls", Severity.HIGH),
    3000: ("http-alt", Severity.LOW),
    3306: ("mysql", Severity.CRITICAL),
    3389: ("rdp", Severity.CRITICAL),
    4444: ("http-alt", Severity.MEDIUM),
    5000: ("http-alt", Severity.LOW),
    5432: ("postgresql", Severity.CRITICAL),
    5601: ("kibana", Severity.HIGH),
    5900: ("vnc", Severity.CRITICAL),
    5984: ("couchdb", Severity.HIGH),
    6379: ("redis", Severity.CRITICAL),
    6443: ("kubernetes-api", Severity.HIGH),
    7001: ("weblogic", Severity.HIGH),
    8000: ("http-alt", Severity.LOW),
    8080: ("http-proxy", Severity.LOW),
    8086: ("influxdb", Severity.HIGH),
    8443: ("https-alt", Severity.INFO),
    8888: ("http-alt", Severity.LOW),
    9000: ("http-alt", Severity.LOW),
    9092: ("kafka", Severity.HIGH),
    9200: ("elasticsearch", Severity.CRITICAL),
    9300: ("elasticsearch-transport", Severity.HIGH),
    10250: ("kubelet", Severity.CRITICAL),
    11211: ("memcached", Severity.CRITICAL),
    15672: ("rabbitmq-mgmt", Severity.HIGH),
    27017: ("mongodb", Severity.CRITICAL),
}

TOP_PORTS = sorted(PORT_CATALOG)

# Services that should essentially never face the internet unauthenticated.
NEVER_PUBLIC = {
    445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 10250, 11211, 27017, 5984, 9092,
}

# Real banners separate product from version with '/', '_' or a space:
#   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"   -> openssh 8.9p1
#   "220 ProFTPD 1.3.5 Server"         -> proftpd 1.3.5
#   "nginx/1.18.0"                     -> nginx 1.18.0
# The product may not contain a dot, so a protocol version like "SSH-2.0"
# cannot be swallowed into the product name.
BANNER_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9\-+]{1,30})[/_ ]v?(\d+(?:\.\d+)+[\w.\-]*)")

# Docker API protocol fingerprints - evidence that the service is actually Docker
DOCKER_API_INDICATORS = [
    b"Docker",
    b"docker",
    b"Api-Version",
    b"Content-Type: application/json",
    b'"ApiVersion"',
    b'"Version"',
    b"Containers",
    b"Images",
]


def _product_from_banner(banner: str) -> tuple[str, str] | None:
    """Take the last match: protocol preambles come first, software after."""
    matches = BANNER_VERSION_RE.findall(banner)
    if not matches:
        return None
    product, version = matches[-1]
    return product.lower(), version


def _verify_docker_api(banner: str, http_response: dict | None = None) -> tuple[bool, str]:
    """Verify if a service on port 2375 is actually Docker API.
    
    Returns (is_confirmed, evidence).
    
    An open TCP port 2375 alone is NOT sufficient evidence.
    We require protocol-level confirmation.
    """
    if not banner and not http_response:
        return False, "No banner or response data available"
    
    # Check banner for Docker-specific indicators
    banner_bytes = banner.encode("utf-8", errors="replace") if banner else b""
    
    # Strong evidence: Docker-specific API response
    if b"Api-Version" in banner_bytes or b'"ApiVersion"' in banner_bytes:
        return True, f"Docker API version header found in response: {banner[:100]}"
    
    if b"docker" in banner_bytes.lower() and (b"Container" in banner_bytes or b"Image" in banner_bytes):
        return True, f"Docker-specific content found in response: {banner[:100]}"
    
    # Check for Docker-specific JSON keys
    if b'"Containers"' in banner_bytes or b'"Images"' in banner_bytes or b'"ApiVersion"' in banner_bytes:
        return True, f"Docker API JSON structure detected: {banner[:100]}"
    
    # Check HTTP response if available
    if http_response:
        body = http_response.get("body", "")
        headers = http_response.get("headers", {})
        
        if "Api-Version" in headers or "api-version" in {k.lower() for k in headers}:
            return True, f"Docker API-Version HTTP header present: {headers}"
        
        if '"ApiVersion"' in body or '"Version"' in body:
            return True, f"Docker API JSON response detected: {body[:100]}"
    
    # Weak evidence: port 2375 is open but no Docker protocol confirmation
    if banner:
        return False, f"Port open but no Docker protocol indicators in banner: {banner[:100]}"
    
    return False, "Port open but no protocol evidence available"


@register
class PortScanCollector(Collector):
    name = "ports"
    stage = "services"
    mode = ScanMode.ACTIVE
    description = "TCP connect scan of common ports against in-scope hosts, with banner grab"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()

        # Scan in-scope hostnames directly (not just IPs). This catches services
        # on resolved addresses the scope authorized, and on hostnames that
        # resolve to IPs the scope did not explicitly derive.
        hostnames = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if n.attrs.get("resolves") is not False
        ]
        allowed_hosts = self.targets_in_scope(hostnames)

        # Also scan non-private, non-CDN, non-shared IPs that are in scope.
        candidates = [n for n in graph.nodes_of(NodeType.IP) if not n.attrs.get("private")]
        shared = {
            n.label: n.attrs.get("managed_by") or "a third-party platform"
            for n in candidates
            if "shared-infrastructure" in n.tags
            and not (self.ctx.scope and self.ctx.scope.covered_by_network(n.label))
        }
        cdn_ips = {}
        for n in candidates:
            if n.label in shared:
                continue
            is_cdn, provider = is_cdn_ip(n.label)
            if is_cdn:
                cdn_ips[n.label] = provider
        ips = [n.label for n in candidates if n.label not in shared and n.label not in cdn_ips]
        allowed_ips = self.targets_in_scope(ips)

        # Deduplicate: prefer hostname scanning, add IPs not covered by a hostname.
        ip_set = set(allowed_ips)
        targets: list[tuple[str, str]] = []
        for h in allowed_hosts:
            targets.append((h, "host"))
        for ip in allowed_ips:
            targets.append((ip, "ip"))

        refused = len(ips) - len(allowed_ips)
        if refused:
            result.errors.append(f"ports: skipped {refused} out-of-scope address(es)")
        if shared:
            platforms = ", ".join(sorted(set(shared.values())))
            result.errors.append(
                f"ports: skipped {len(shared)} address(es) operated by {platforms} - "
                "add the network to your scope file if you are authorized to test it"
            )
        if cdn_ips:
            providers = ", ".join(sorted(set(cdn_ips.values())))
            result.errors.append(
                f"ports: skipped {len(cdn_ips)} address(es) on {providers} edge/CDN infrastructure - "
                "services on shared edge IPs cannot be attributed to the target origin"
            )
        if not targets:
            return result

        ports = TOP_PORTS if not self.config.max_ports_per_host else TOP_PORTS[: self.config.max_ports_per_host]
        sem = asyncio.Semaphore(self.config.concurrency * 5)
        tasks = [self._probe(sem, target, port) for target, _kind in targets for port in ports]

        prov = self.prov("tcp-connect")
        open_count = 0
        for outcome in await asyncio.gather(*tasks):
            if outcome is None:
                continue
            target, port, banner = outcome
            open_count += 1
            service_name, base_sev = PORT_CATALOG.get(port, ("unknown", Severity.LOW))
            
            # Determine asset attribution for this target
            attribution = classify_ip_attribution(target)
            
            # For Docker API, verify protocol-level evidence
            is_docker_confirmed = False
            docker_evidence = ""
            if port == 2375:
                is_docker_confirmed, docker_evidence = _verify_docker_api(banner)
                if not is_docker_confirmed:
                    # Downgrade: port 2375 open but not confirmed Docker
                    service_name = "unknown"
                    base_sev = Severity.LOW
            
            svc = Node.create(
                NodeType.SERVICE,
                f"{target}:{port}",
                label=f"{service_name}/{port}",
                attrs={
                    "ip": target,
                    "port": port,
                    "service": service_name,
                    "banner": banner,
                    "transport": "tcp",
                    "attribution_status": attribution.status,
                    "attribution_provider": attribution.provider,
                },
                provenance=prov,
                tags={"exposed"} | ({"unauthenticated-risk"} if port in NEVER_PUBLIC and is_docker_confirmed else set()),
            )
            result.nodes.append(svc)
            result.edges.append(
                Edge(
                    source=Node.make_id(NodeType.IP, target),
                    target=svc.id,
                    type=EdgeType.EXPOSES,
                    provenance=[prov],
                )
            )
            result.extend(self._service_findings(target, port, service_name, base_sev, banner, svc.id, attribution, is_docker_confirmed, docker_evidence))

        result.stats["open_services"] = open_count
        result.stats["hosts_scanned"] = len(targets)
        return result

    async def _probe(
        self, sem: asyncio.Semaphore, ip: str, port: int
    ) -> tuple[str, int, str] | None:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.config.timeout / 2
                )
            except (TimeoutError, OSError):
                return None
            banner = ""
            try:
                with contextlib.suppress(asyncio.TimeoutError, OSError):
                    data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                    banner = data.decode("utf-8", errors="replace").strip()
            finally:
                writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            return ip, port, banner

    def _service_findings(
        self,
        ip: str,
        port: int,
        service_name: str,
        base_sev: Severity,
        banner: str,
        service_id: str,
        attribution=None,
        is_docker_confirmed: bool = False,
        docker_evidence: str = "",
    ) -> CollectorResult:
        out = CollectorResult()
        
        # Build asset attribution dict
        if attribution is None:
            attribution = classify_ip_attribution(ip)
        attr_dict = {
            "status": attribution.status,
            "provider": attribution.provider,
            "evidence": attribution.evidence,
            "notes": attribution.notes,
        }
        
        # Handle Docker API on port 2375
        if port == 2375:
            # Auto-verify Docker protocol if not already done
            if not is_docker_confirmed and not docker_evidence:
                is_docker_confirmed, docker_evidence = _verify_docker_api(banner)
            
            if is_docker_confirmed:
                # Confirmed Docker API - high severity
                out.findings.append(
                    Finding(
                        title=f"Confirmed Docker API exposed on {ip}:{port}",
                        severity=Severity.HIGH,
                        category="exposed-service",
                        type="exposure",
                        node_ids=[service_id, Node.make_id(NodeType.IP, ip)],
                        description=(
                            f"Docker API protocol confirmed on {ip}:{port}. "
                            "An exposed Docker API allows container manipulation and potential host compromise."
                        ),
                        evidence=[
                            {"type": "protocol", "value": "TCP"},
                            {"type": "port", "value": port},
                            {"type": "banner", "value": banner[:200]},
                            {"type": "docker_verification", "value": docker_evidence},
                            {"type": "attribution", "value": attr_dict},
                        ],
                        remediation=(
                            "Enable TLS authentication for Docker API (port 2376), "
                            "restrict access with firewall rules, or bind to localhost only."
                        ),
                        collector=self.name,
                        confidence=0.9,
                        detection_method="TCP_connect+Docker_protocol_verification",
                        source="tcp-connect",
                        asset_attribution=attr_dict,
                    )
                )
            else:
                # Port 2375 open but Docker NOT confirmed
                out.findings.append(
                    Finding(
                        title=f"Potential service on {ip}:{port} (Docker API unconfirmed)",
                        severity=Severity.LOW,
                        category="exposed-service",
                        type="exposure",
                        node_ids=[service_id, Node.make_id(NodeType.IP, ip)],
                        description=(
                            f"Port {port} is open on {ip}, traditionally associated with Docker API. "
                            f"Docker API protocol was NOT confirmed. {docker_evidence}"
                        ),
                        evidence=[
                            {"type": "protocol", "value": "TCP"},
                            {"type": "port", "value": port},
                            {"type": "banner", "value": banner[:200]},
                            {"type": "docker_verification", "value": docker_evidence},
                            {"type": "attribution", "value": attr_dict},
                        ],
                        remediation=(
                            "Verify what service is running on this port. "
                            "If Docker API, enable authentication and restrict access."
                        ),
                        collector=self.name,
                        confidence=0.4,
                        detection_method="TCP_connect+insufficient_Docker_evidence",
                        source="tcp-connect",
                        asset_attribution=attr_dict,
                    )
                )
            return out
        
        # Handle other NEVER_PUBLIC ports
        if port in NEVER_PUBLIC:
            out.findings.append(
                Finding(
                    title=f"{service_name} exposed to the internet on {ip}:{port}",
                    severity=base_sev,
                    category="exposed-service",
                    type="exposure",
                    node_ids=[service_id, Node.make_id(NodeType.IP, ip)],
                    description=(
                        f"{service_name} is a datastore or administrative service that should sit "
                        "behind a private network, VPN, or bastion - not on a public address."
                    ),
                    evidence=[
                        {"type": "protocol", "value": "TCP"},
                        {"type": "port", "value": port},
                        {"type": "banner", "value": banner[:200]},
                        {"type": "reachability", "value": "public"},
                        {"type": "attribution", "value": attr_dict},
                    ],
                    remediation=(
                        "Bind the service to a private interface, restrict with a security group "
                        "or firewall, and require authentication."
                    ),
                    collector=self.name,
                    confidence=0.9 if attr_dict.get("status") == "confirmed" else 0.6,
                    detection_method="TCP_connect+banner_grab",
                    source="tcp-connect",
                    asset_attribution=attr_dict,
                )
            )
        elif base_sev in (Severity.HIGH, Severity.MEDIUM):
            out.findings.append(
                Finding(
                    title=f"{service_name} reachable on {ip}:{port}",
                    severity=base_sev,
                    category="exposed-service",
                    type="exposure",
                    node_ids=[service_id],
                    evidence=[
                        {"type": "protocol", "value": "TCP"},
                        {"type": "port", "value": port},
                        {"type": "banner", "value": banner[:200]},
                        {"type": "attribution", "value": attr_dict},
                    ],
                    remediation="Confirm this exposure is intentional and access-controlled.",
                    collector=self.name,
                    confidence=0.85 if attr_dict.get("status") == "confirmed" else 0.5,
                    detection_method="TCP_connect+banner_grab",
                    source="tcp-connect",
                    asset_attribution=attr_dict,
                )
            )

        parsed = _product_from_banner(banner)
        if parsed:
            product, version = parsed
            tech = Node.create(
                NodeType.TECHNOLOGY,
                f"{product}:{version}",
                label=f"{product} {version}",
                attrs={"product": product, "version": version, "source": "banner"},
                provenance=self.prov("banner"),
            )
            out.nodes.append(tech)
            out.edges.append(
                Edge(
                    source=service_id,
                    target=tech.id,
                    type=EdgeType.RUNS,
                    provenance=[self.prov("banner")],
                )
            )
        return out


@register
class ShodanCollector(Collector):
    name = "shodan"
    stage = "services"
    mode = ScanMode.PASSIVE
    description = "Read known open ports and banners from Shodan without touching the target"
    requires_keys = ("shodan",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        key = self.config.key("shodan")
        ips = [n.label for n in graph.nodes_of(NodeType.IP) if not n.attrs.get("private")][:100]
        sem = asyncio.Semaphore(4)

        async def lookup(ip: str) -> tuple[str, dict | None]:
            async with sem:
                data = await self.http.get_json(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": key, "minify": "false"},
                    retries=1,
                )
            return ip, data

        prov = self.prov("shodan")
        for ip, data in await asyncio.gather(*(lookup(ip) for ip in ips)):
            if not data:
                continue
            result.nodes.append(
                Node.create(
                    NodeType.IP,
                    ip,
                    attrs={
                        "organization": data.get("org"),
                        "os": data.get("os"),
                        "hostnames": data.get("hostnames"),
                        "shodan_ports": data.get("ports"),
                        "shodan_tags": data.get("tags"),
                    },
                    provenance=prov,
                )
            )
            for item in data.get("data", [])[:50]:
                port = item.get("port")
                if port is None:
                    continue
                product = (item.get("product") or "").strip()
                version = (item.get("version") or "").strip()
                service_name = item.get("_shodan", {}).get("module") or PORT_CATALOG.get(
                    port, ("unknown", Severity.LOW)
                )[0]
                svc = Node.create(
                    NodeType.SERVICE,
                    f"{ip}:{port}",
                    label=f"{service_name}/{port}",
                    attrs={
                        "ip": ip,
                        "port": port,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "banner": (item.get("data") or "")[:300],
                        "transport": item.get("transport", "tcp"),
                    },
                    provenance=prov,
                    tags={"exposed", "shodan"}
                    | ({"unauthenticated-risk"} if port in NEVER_PUBLIC else set()),
                )
                result.nodes.append(svc)
                result.edges.append(
                    Edge(
                        source=Node.make_id(NodeType.IP, ip),
                        target=svc.id,
                        type=EdgeType.EXPOSES,
                        provenance=[prov],
                    )
                )
                if product:
                    tech = Node.create(
                        NodeType.TECHNOLOGY,
                        f"{product.lower()}:{version or 'unknown'}",
                        label=f"{product} {version}".strip(),
                        attrs={"product": product.lower(), "version": version, "source": "shodan"},
                        provenance=prov,
                    )
                    result.nodes.append(tech)
                    result.edges.append(
                        Edge(source=svc.id, target=tech.id, type=EdgeType.RUNS, provenance=[prov])
                    )
                for cve in (item.get("vulns") or {}):
                    svc.attrs.setdefault("shodan_cves", []).append(cve)
        return result
