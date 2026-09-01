"""Secrets and credential exposure.

`exposed_paths` (active) checks a short list of paths that leak configuration
when a deploy goes wrong. `leaks` (passive) queries Have I Been Pwned for
breaches affecting the domain's mailboxes.
"""

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

# path -> (what it leaks, severity, a substring that confirms a real hit)
SENSITIVE_PATHS: dict[str, tuple[str, Severity, tuple[str, ...]]] = {
    "/.env": ("application environment file", Severity.CRITICAL, ("APP_KEY", "DB_", "SECRET", "API_KEY", "PASSWORD")),
    "/.git/config": ("git repository metadata", Severity.HIGH, ("[core]", "[remote", "url =")),
    "/.git/HEAD": ("exposed git directory", Severity.HIGH, ("ref: refs/",)),
    "/.aws/credentials": ("AWS credentials", Severity.CRITICAL, ("aws_access_key_id",)),
    "/config.json": ("application configuration", Severity.MEDIUM, ("password", "secret", "token")),
    "/.npmrc": ("npm registry token", Severity.HIGH, ("_authToken",)),
    "/.dockercfg": ("docker registry credentials", Severity.HIGH, ("auth",)),
    "/docker-compose.yml": ("compose file with service credentials", Severity.MEDIUM, ("services:",)),
    "/actuator/env": ("Spring Boot environment", Severity.CRITICAL, ("propertySources", "systemEnvironment")),
    "/actuator/heapdump": ("Spring Boot heap dump", Severity.CRITICAL, ("JAVA PROFILE",)),
    "/server-status": ("Apache mod_status", Severity.MEDIUM, ("Apache Server Status",)),
    "/debug/pprof/": ("Go pprof debug endpoint", Severity.HIGH, ("Types of profiles",)),
    "/phpinfo.php": ("phpinfo output", Severity.HIGH, ("phpinfo()", "PHP Version")),
    "/.svn/entries": ("Subversion metadata", Severity.MEDIUM, ("dir",)),
    "/wp-config.php.bak": ("WordPress config backup", Severity.CRITICAL, ("DB_PASSWORD",)),
    "/.well-known/security.txt": ("security contact (informational)", Severity.INFO, ("Contact:",)),
    # backups and dumps - common deploy leftovers that leak full datasets
    "/backup.zip": ("application backup archive", Severity.CRITICAL, ("PK\x03\x04",)),
    "/backup.tar.gz": ("application backup archive", Severity.CRITICAL, ("\x1f\x8b",)),
    "/db.sql": ("database dump", Severity.CRITICAL, ("CREATE TABLE", "INSERT INTO")),
    "/dump.sql": ("database dump", Severity.CRITICAL, ("CREATE TABLE", "INSERT INTO")),
    "/database.yml": ("database connection config", Severity.HIGH, ("adapter:", "password:", "username:")),
    "/.env.backup": ("environment file backup", Severity.CRITICAL, ("APP_KEY", "DB_", "SECRET", "API_KEY")),
    "/.env.local": ("local environment file", Severity.CRITICAL, ("APP_KEY", "DB_", "SECRET", "API_KEY")),
    "/.env.prod": ("production environment file", Severity.CRITICAL, ("APP_KEY", "DB_", "SECRET", "API_KEY")),
    "/storage/.env": ("environment file in storage dir", Severity.CRITICAL, ("APP_KEY", "DB_", "SECRET", "API_KEY")),
}

# High-confidence credential shapes, for when a page does leak something.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), Severity.CRITICAL),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), Severity.MEDIUM),
]


@register
class ExposedPathCollector(Collector):
    name = "exposed_paths"
    stage = "secrets"
    mode = ScanMode.ACTIVE
    description = "Request a short list of paths that leak configuration and credentials"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if "web" in n.tags or n.attrs.get("http_status")
        ]
        if not hosts:
            hosts = [
                n.label
                for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
                if n.attrs.get("resolves")
            ]
        hosts = self.targets_in_scope(hosts)[:100]
        if not hosts:
            return result

        sem = asyncio.Semaphore(self.config.concurrency)
        tasks = [self._check(sem, graph, host, path) for host in hosts for path in SENSITIVE_PATHS]
        for outcome in await asyncio.gather(*tasks):
            if outcome:
                result.extend(outcome)
        result.stats["paths_checked"] = len(tasks)
        return result

    async def _check(
        self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph, host: str, path: str
    ) -> CollectorResult | None:
        label, severity, confirmations = SENSITIVE_PATHS[path]
        scheme = "https"
        async with sem:
            resp = await self.http.request("GET", f"{scheme}://{host}{path}", retries=0)
        if resp is None or resp.status_code != 200:
            return None
        body = resp.text[:100_000]
        if not any(c.lower() in body.lower() for c in confirmations):
            return None
        if "<html" in body[:200].lower() and path != "/server-status":
            return None  # soft-404 page, not the real file

        out = CollectorResult()
        node_type = NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN
        host_id = Node.make_id(node_type, host)
        prov = self.prov(f"{scheme}://{host}{path}")

        secret_node = Node.create(
            NodeType.SECRET,
            f"{host}{path}",
            label=f"{path} on {host}",
            attrs={"host": host, "path": path, "leaks": label, "status": resp.status_code},
            provenance=prov,
            tags={"exposed", "suspicious"},
        )
        out.nodes.append(secret_node)
        out.edges.append(
            Edge(source=host_id, target=secret_node.id, type=EdgeType.LEAKS, provenance=[prov])
        )

        hits = [
            name
            for name, pattern, _ in SECRET_PATTERNS
            if pattern.search(body)
        ]
        if hits:
            severity = Severity.CRITICAL
            secret_node.attrs["credential_types"] = hits

        out.findings.append(
            Finding(
                title=f"Exposed {label} at {host}{path}",
                severity=severity,
                category="secret-exposure",
                node_ids=[secret_node.id, host_id],
                description=(
                    f"{host}{path} returned 200 with content matching a real {label}."
                    + (f" Credential material detected: {', '.join(hits)}." if hits else "")
                ),
                evidence={
                    "url": f"{scheme}://{host}{path}",
                    "status": resp.status_code,
                    "bytes": len(body),
                    "credential_types": hits,
                },
                remediation=(
                    "Remove the file from the web root, rotate every credential it contained, "
                    "and block the path at the edge."
                ),
                collector=self.name,
            )
        )
        return out


@register
class BreachCollector(Collector):
    name = "leaks"
    stage = "secrets"
    mode = ScanMode.PASSIVE
    description = "Breached-account exposure for the domain via Have I Been Pwned"
    requires_keys = ("hibp",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        domain_id = Node.make_id(NodeType.DOMAIN, apex)
        data = await self.http.get_json(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{apex}",
            headers={"hibp-api-key": self.config.key("hibp") or ""},
            retries=1,
        )
        if not data:
            return result

        # HIBP returns {alias: [breach names]} for domains you have verified.
        total = 0
        breaches: dict[str, int] = {}
        for _alias, names in (data or {}).items():
            total += 1
            for name in names or []:
                breaches[name] = breaches.get(name, 0) + 1

        prov = self.prov("haveibeenpwned")
        node = Node.create(
            NodeType.CREDENTIAL_LEAK,
            f"hibp:{apex}",
            label=f"{total} breached accounts @{apex}",
            attrs={"count": total, "breaches": breaches, "domain": apex},
            provenance=prov,
            tags={"credential-exposure"},
        )
        result.nodes.append(node)
        result.edges.append(
            Edge(source=domain_id, target=node.id, type=EdgeType.LEAKS, provenance=[prov])
        )
        if total:
            result.findings.append(
                Finding(
                    title=f"{total} corporate accounts appear in public breach data",
                    severity=Severity.HIGH if total > 25 else Severity.MEDIUM,
                    category="credential-exposure",
                    node_ids=[node.id, domain_id],
                    description=(
                        "Reused passwords from these breaches are the most common initial access "
                        "vector. Every exposed mailbox is a credential-stuffing target."
                    ),
                    evidence={"accounts": total, "breaches": dict(sorted(breaches.items(), key=lambda x: -x[1])[:10])},
                    remediation=(
                        "Force a reset for affected accounts, enforce phishing-resistant MFA, "
                        "and screen new passwords against a breach corpus."
                    ),
                    collector=self.name,
                )
            )
        return result


# Exposed API surface: Swagger/OpenAPI specs and GraphQL endpoints are a map of
# the entire backend. They are probed here (active) because a reachable spec or an
# introspectable GraphQL endpoint hands an attacker the full method/parameter list
# for free - the single highest-value thing to find on a web host after credentials.
API_DOC_PATHS: dict[str, tuple[str, tuple[str, ...]]] = {
    "/swagger.json": ("Swagger/OpenAPI", ("swagger", "openapi", "paths", "definitions")),
    "/swagger/v1/swagger.json": ("Swagger/OpenAPI", ("swagger", "openapi", "paths")),
    "/swagger-ui.html": ("Swagger UI", ("swagger-ui", "SwaggerUIBundle", "url:")),
    "/api-docs": ("Swagger/OpenAPI", ("swagger", "openapi", "paths")),
    "/openapi.json": ("OpenAPI", ("openapi", "paths", "components")),
    "/v2/api-docs": ("Swagger/OpenAPI", ("swagger", "openapi", "paths")),
    "/v3/api-docs": ("Springfox OpenAPI", ("openapi", "paths", "components")),
    "/.well-known/openapi.json": ("OpenAPI", ("openapi", "paths", "components")),
    "/graphql": ("GraphQL", ("\"data\"", "\"__schema\"", "\"queryType\"", "graphql")),
    "/api": ("API root", ("\"swagger\"", "\"openapi\"", "\"paths\"", "\"_links\"", "\"endpoints\"")),
    "/api/v1": ("API root", ("\"swagger\"", "\"openapi\"", "\"paths\"", "\"_links\"", "\"endpoints\"")),
}


def _classify_api(path: str, body: str) -> tuple[str, Severity, bool]:
    """Return (kind, severity, introspectable) for a detected API doc."""
    lowered = body[:200_000].lower()
    if "graphql" in path or "__schema" in lowered or "querytype" in lowered:
        # A reachable GraphQL endpoint answering introspection = full schema
        # disclosure - the dangerous case. Any 200 on /graphql carrying schema
        # data is treated as introspection-enabled.
        introspectable = "__schema" in lowered or "querytype" in lowered
        return "GraphQL", Severity.CRITICAL if introspectable else Severity.HIGH, introspectable
    return "Swagger/OpenAPI", Severity.HIGH, False


@register
class ApiExposureCollector(Collector):
    name = "api_exposure"
    stage = "secrets"
    mode = ScanMode.ACTIVE
    description = "Probe for exposed API specifications (Swagger/OpenAPI) and GraphQL endpoints"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if "web" in n.tags or n.attrs.get("http_status")
        ]
        if not hosts:
            hosts = [
                n.label
                for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
                if n.attrs.get("resolves")
            ]
        hosts = self.targets_in_scope(hosts)[:100]
        if not hosts:
            return result

        sem = asyncio.Semaphore(self.config.concurrency)
        tasks = [self._probe(sem, graph, host, path) for host in hosts for path in API_DOC_PATHS]
        for outcome in await asyncio.gather(*tasks):
            if outcome:
                result.extend(outcome)
        result.stats["api_paths_checked"] = len(tasks)
        return result

    async def _probe(
        self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph, host: str, path: str
    ) -> CollectorResult | None:
        confirm = API_DOC_PATHS[path][1]
        scheme = "https"
        async with sem:
            resp = await self.http.request("GET", f"{scheme}://{host}{path}", retries=0)
        if resp is None or resp.status_code != 200:
            return None
        body = resp.text[:200_000]
        if not any(c.lower() in body.lower() for c in confirm):
            return None
        # A 200 with an HTML login/redirect page is not a real spec.
        if "<html" in body[:200].lower() and path != "/graphql":
            return None

        kind, severity, introspectable = _classify_api(path, body)
        out = CollectorResult()
        node_type = NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN
        host_id = Node.make_id(node_type, host)
        prov = self.prov(f"{scheme}://{host}{path}")

        api_node = Node.create(
            NodeType.API,
            f"{host}{path}",
            label=f"{kind} at {host}{path}",
            attrs={
                "host": host,
                "path": path,
                "kind": kind,
                "introspectable": introspectable,
                "status": resp.status_code,
            },
            provenance=prov,
            tags={"exposed", "api"},
        )
        out.nodes.append(api_node)
        out.edges.append(
            Edge(source=host_id, target=api_node.id, type=EdgeType.EXPOSES, provenance=[prov])
        )
        out.findings.append(
            Finding(
                title=f"Exposed {kind} at {host}{path}",
                severity=severity,
                category="api-exposure",
                node_ids=[api_node.id, host_id],
                description=(
                    f"{host}{path} returns {kind} documentation. "
                    + (
                        "GraphQL introspection is enabled, disclosing the entire schema."
                        if introspectable
                        else "The spec enumerates every endpoint, parameter, and often the auth scheme."
                    )
                ),
                evidence={
                    "url": f"{scheme}://{host}{path}",
                    "status": resp.status_code,
                    "kind": kind,
                    "introspectable": introspectable,
                },
                remediation=(
                    "Restrict the spec to authenticated users or disable it in production, "
                    "and turn off GraphQL introspection. An exposed schema is a roadmap for attackers."
                ),
                collector=self.name,
            )
        )
        return out
