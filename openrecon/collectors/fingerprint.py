"""HTTP fingerprinting: what software answers, and how it is configured."""

from __future__ import annotations

import asyncio
import re

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

VERSION_RE = re.compile(r"^([A-Za-z][\w\-\.]{1,40})(?:/(\d[\w\.\-]*))?")

# Response fingerprints -> product. Deliberately small and high-signal.
BODY_SIGNATURES: list[tuple[str, str]] = [
    ("gitlab", "GitLab"),
    ("jenkins", "Jenkins"),
    ("phpmyadmin", "phpMyAdmin"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
    ("wp-content", "WordPress"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("django", "Django"),
    ("laravel", "Laravel"),
    ("jira", "Jira"),
    ("confluence", "Confluence"),
    ("sonarqube", "SonarQube"),
    ("rabbitmq", "RabbitMQ"),
    ("prometheus", "Prometheus"),
    ("keycloak", "Keycloak"),
    ("harbor", "Harbor"),
    ("minio", "MinIO"),
]

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", Severity.LOW),
    "content-security-policy": ("Content-Security-Policy", Severity.LOW),
    "x-content-type-options": ("X-Content-Type-Options", Severity.INFO),
    "x-frame-options": ("clickjacking protection", Severity.LOW),
}

INFO_LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")


@register
class HttpFingerprintCollector(Collector):
    name = "http"
    stage = "fingerprint"
    mode = ScanMode.ACTIVE
    description = "Fetch each in-scope host over HTTP(S) to identify software and headers"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if n.attrs.get("resolves") is not False
        ]
        hosts = self.targets_in_scope(hosts)[: self.config.max_subdomains]
        if not hosts:
            return result

        self.progress("probing-start", {"stage": self.stage, "total": len(hosts), "done": 0})
        sem = asyncio.Semaphore(self.config.concurrency)
        done = 0

        async def fetch(host: str) -> None:
            nonlocal done
            async with sem:
                for scheme in ("https", "http"):
                    resp = await self.http.request(
                        "GET", f"{scheme}://{host}/", retries=0
                    )
                    if resp is None:
                        continue
                    if resp.status_code in (403, 429):
                        result.errors.append(
                            f"blocked: {host} answered {resp.status_code} - edge protection "
                            "is filtering this scan, so fingerprinting is incomplete"
                        )
                    result.extend(self._analyze(graph, host, scheme, resp))
                    break
            done += 1
            self.progress("probing", {"stage": self.stage, "total": len(hosts), "done": done, "host": host})

        await asyncio.gather(*(fetch(h) for h in hosts))
        result.stats["http_probed"] = len(hosts)
        self.progress("probing-done", {"stage": self.stage, "total": len(hosts), "done": len(hosts)})
        if self.http.cooled_off:
            result.errors.append(
                "blocked: stopped requesting "
                + ", ".join(sorted(self.http.cooled_off)[:5])
                + " after repeated refusals - lower --concurrency or rate_limit_per_host, "
                "and re-run once the block expires"
            )
        return result

    def _analyze(self, graph: AttackSurfaceGraph, host: str, scheme: str, resp) -> CollectorResult:
        out = CollectorResult()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:200_000].lower() if resp.headers.get("content-type", "").startswith("text") else ""
        node_type = NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN
        host_id = Node.make_id(node_type, host)
        prov = self.prov(f"{scheme}://{host}/")

        title = ""
        if body:
            match = re.search(r"<title[^>]*>(.*?)</title>", body, re.S)
            if match:
                title = match.group(1).strip()[:120]

        out.nodes.append(
            Node.create(
                node_type,
                host,
                attrs={
                    "http_status": resp.status_code,
                    "http_scheme": scheme,
                    "http_title": title,
                    "http_server": headers.get("server"),
                    "http_powered_by": headers.get("x-powered-by"),
                    "final_url": str(resp.url),
                },
                provenance=prov,
                tags={"web"},
            )
        )

        products: list[tuple[str, str]] = []
        for header in ("server", "x-powered-by", "x-generator"):
            value = headers.get(header)
            if not value:
                continue
            match = VERSION_RE.match(value.strip())
            if match:
                products.append((match.group(1).lower(), match.group(2) or ""))
        for needle, product in BODY_SIGNATURES:
            if needle in body or needle in (headers.get("set-cookie", "").lower()):
                products.append((product.lower(), ""))

        for product, version in {(p, v) for p, v in products}:
            tech = Node.create(
                NodeType.TECHNOLOGY,
                f"{product}:{version or 'unknown'}",
                label=f"{product} {version}".strip(),
                attrs={"product": product, "version": version, "source": "http"},
                provenance=prov,
            )
            out.nodes.append(tech)
            out.edges.append(
                Edge(source=host_id, target=tech.id, type=EdgeType.RUNS, provenance=[prov])
            )

        out.findings.extend(self._header_findings(host, host_id, scheme, headers))
        return out

    def _header_findings(
        self, host: str, host_id: str, scheme: str, headers: dict[str, str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        missing = [
            label
            for header, (label, _) in SECURITY_HEADERS.items()
            if header not in headers
        ]
        if missing and scheme == "https":
            findings.append(
                Finding(
                    title=f"Missing security headers on {host}",
                    severity=Severity.LOW,
                    category="web-hardening",
                    node_ids=[host_id],
                    description="Defence-in-depth headers absent: " + ", ".join(missing),
                    evidence={"missing": missing},
                    remediation="Add HSTS, CSP, X-Content-Type-Options, and X-Frame-Options at the edge.",
                    collector=self.name,
                )
            )

        disclosed = {h: headers[h] for h in INFO_LEAK_HEADERS if h in headers and headers[h]}
        versioned = {k: v for k, v in disclosed.items() if re.search(r"\d+\.\d+", v)}
        if versioned:
            findings.append(
                Finding(
                    title=f"Software version disclosed in HTTP headers on {host}",
                    severity=Severity.LOW,
                    category="information-disclosure",
                    node_ids=[host_id],
                    description=(
                        "Exact versions let an attacker match your stack to public exploits "
                        "without probing you first."
                    ),
                    evidence=versioned,
                    remediation="Suppress version tokens (e.g. nginx `server_tokens off`).",
                    collector=self.name,
                )
            )
        return findings
