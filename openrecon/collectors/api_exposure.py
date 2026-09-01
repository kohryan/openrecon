"""API surface discovery + classification.

Sits at the front of the ``attack`` stage, before the crawler's deep crawl,
because the endpoints it finds are exactly what the later collectors want to
aim at:

  * the ``GraphQLVerifier`` only verifies endpoints it is *told* about
    (either by this collector, or by the crawler). Discovering GraphQL here
    means introspection verification runs even when katana is not installed
    or misses the path.
  * the ``ReverseEngineeringCollector`` feeds on the spec/doc nodes this one
    produces (an open OpenAPI document is itself a reverse-engineering aid).

Three families of endpoint are probed per in-scope web host, each over the
schemes the host answers on:

  graphql   POST a trivial ``{__typename}`` query to common paths
            (/graphql, /api/graphql, /gql, ...) and let the existing
            ``classify_body`` helper decide if it is really GraphQL. The node
            is tagged ``kind=graphql`` so ``graphql_verify`` picks it up.
  openapi   GET the well-known spec locations (/openapi.json, /swagger.json,
            /v2/api-docs, ...) and recognise both the JSON document and the
            Swagger-UI HTML shell.
  rest      GET the obvious API roots (/api, /api/v1, ...) and recognise a
            JSON API response (a machine-readable body, as opposed to a HTML
            page).

Everything is read-only and non-destructive. A discovered endpoint becomes an
``api`` node tagged with its ``kind``; where the spec is small enough we fold
a snippet into the node so downstream analysis can quote it without re-fetching.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any

from openrecon.collectors.base import Collector, register
from openrecon.collectors.graphql import classify_body
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

# Common GraphQL entry points. We deliberately cover the popular frameworks
# (Apollo, relay, graphene, Hasura, Saleor, ...); missing one is fine - the
# crawler catches the rest, this just guarantees coverage without katana.
GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/api",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/graphql/console",
    "/query",
    "/api/query",
]

# OpenAPI / Swagger spec + UI locations.
OPENAPI_PATHS = [
    "/openapi.json",
    "/api/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/swagger.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/docs/openapi.json",
]

# Bare Swagger-UI shells - the HTML page that loads a spec we may then fetch.
SWAGGER_UI_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/swagger/index.html",
    "/api/swagger-ui.html",
]

# Obvious unversioned / versioned REST roots.
REST_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/api",
    "/api/rest",
    "/v1",
    "/v2",
    "/webapi",
    "/services",
]


@dataclass
class ApiHit:
    url: str
    host: str
    path: str
    kind: str  # graphql | openapi | swagger | rest | api-root
    scheme: str
    snippet: str | None = None
    title: str | None = None
    details: dict[str, Any] | None = None


# A JSON body that is clearly an OpenAPI/Swagger document.
_OPENAPI_MARKERS = ("openapi", "swagger", "paths", "info", "definitions", "components")
_SWAGGER_UI_MARKERS = ("swagger-ui", "swaggerui", "swaggeruibundle", "swagger-config")


def classify_openapi(text: str, status: int, content_type: str | None) -> tuple[bool, str | None, str | None]:
    """Return (is_spec, kind, snippet) for a possible OpenAPI/Swagger response."""
    if not text:
        return False, None, None
    lowered = text[:200_000].lower()
    ctype = (content_type or "").lower()
    is_json = ctype.startswith("application/json") or lowered.lstrip().startswith("{")
    if is_json:
        try:
            obj = json.loads(text[:400_000])
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            if "openapi" in obj or "swagger" in obj:
                version = obj.get("openapi") or obj.get("swagger")
                kind = "openapi" if "openapi" in obj else "swagger"
                title = (obj.get("info") or {}).get("title") if isinstance(obj.get("info"), dict) else None
                snippet = json.dumps(
                    {"openapi": version, "title": title, "paths": list((obj.get("paths") or {}).keys())[:40]},
                    ensure_ascii=False,
                )[:4000]
                return True, kind, snippet
            # A bare api-docs doc from older Spring/ASP.NET stacks.
            if {"paths", "definitions"} <= set(obj) or (
                "paths" in obj and isinstance(obj.get("paths"), dict) and len(obj["paths"]) >= 1
            ):
                return True, "openapi", json.dumps(
                    {"title": "undocumented-api-docs", "paths": list((obj.get("paths") or {}).keys())[:40]},
                    ensure_ascii=False,
                )[:4000]
    # A Swagger-UI HTML shell is also an exposure: it points at a spec a
    # determined reader can fetch, and leaks the UI/framework choice.
    if status < 400 and any(m in lowered for m in _SWAGGER_UI_MARKERS):
        return True, "swagger", None
    return False, None, None


def classify_rest(text: str, status: int, content_type: str | None) -> tuple[bool, str | None]:
    """Recognise a machine-readable REST API root (JSON, not a HTML page)."""
    if status >= 400 or not text:
        return False, None
    ctype = (content_type or "").lower()
    lowered = text[:200_000].lower()
    if "<html" in lowered[:500] and "application/json" not in ctype:
        return False, None
    if ctype.startswith("application/json") or lowered.lstrip().startswith(("{", "[")):
        try:
            obj = json.loads(text[:400_000])
        except ValueError:
            return False, None
        # A real API body: an object with data, or a list, or error envelope.
        if isinstance(obj, list) and len(obj) >= 1:
            return True, "rest"
        if isinstance(obj, dict) and (
            {"data"} & obj.keys()
            or "error" in obj
            or any(k in obj for k in ("results", "items", "total", "count", "message"))
        ):
            return True, "rest"
    return False, None


def is_auth_locked_rest(snippet: str) -> bool:
    """Detect whether a REST JSON snippet indicates an auth-locked endpoint.

    Returns True when the response is a JSON error envelope indicating the
    request requires authentication (e.g. {"error": "unauthorized"}).
    """
    if not snippet:
        return False
    lowered = snippet.lower()
    return any(
        kw in lowered
        for kw in ("unauthorized", "authentication required", "forbidden",
                   "must be authenticated", "login required", "access denied",
                   "jwt", "bearer", "token expired", "invalid token")
    )


@register
class ApiSurfaceCollector(Collector):
    """Discover and classify exposed API surfaces across in-scope web hosts.

    Produces ``api`` nodes tagged with ``kind`` (graphql/openapi/swagger/rest)
    so downstream collectors (graphql_verify, reverse_engineering) and the risk
    engine can reason about the API attack surface without a full crawl.
    """

    name = "api_surface"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Probe in-scope web hosts for exposed GraphQL, OpenAPI/Swagger, and REST API surfaces"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()

        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if n.attrs.get("resolves") is not False and (n.attrs.get("http_status") or "web" in n.tags)
        ]
        hosts = self.targets_in_scope(hosts)[: self.config.max_subdomains]
        if not hosts:
            result.errors.append(
                "api_exposure: no in-scope web hosts to probe "
                "(run fingerprint/http first, or this is a non-web target)"
            )
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        total = len(hosts)
        done = 0
        self.progress("api-exposure-start", {"total": total})

        async def probe(host: str) -> None:
            nonlocal done
            async with sem:
                hits = await self._probe_host(host)
                for hit in hits:
                    self._record(result, graph, hit)
            done += 1
            self.progress("api-exposure", {"done": done, "total": total, "host": host})

        await asyncio.gather(*(probe(h) for h in hosts))
        result.stats["api_hosts_probed"] = total
        result.stats["api_endpoints_found"] = sum(
            1 for n in result.nodes if n.type is NodeType.API
        )
        self.progress("api-exposure-done", {"found": result.stats["api_endpoints_found"]})
        return result

    # ----------------------------------------------------------------- probing

    async def _probe_host(self, host: str) -> list[ApiHit]:
        hits: list[ApiHit] = []
        # 1) GraphQL - POST a trivial query to each candidate path.
        for path in GRAPHQL_PATHS:
            url = f"https://{host}{path}"
            resp = await self.http.request(
                "POST", url,
                json={"query": "{__typename}"},
                headers={"Content-Type": "application/json"},
                retries=0,
            )
            if resp is None:
                # Fall back to http if https was refused/closed.
                resp = await self.http.request(
                    "POST", f"http://{host}{path}",
                    json={"query": "{__typename}"},
                    headers={"Content-Type": "application/json"},
                    retries=0,
                )
                if resp is not None:
                    url = f"http://{host}{path}"
            if resp is None:
                continue
            is_gql, _, _ = classify_body(resp.text, resp.status_code)
            if is_gql:
                hits.append(ApiHit(url, host, path, "graphql", "https" if url.startswith("https") else "http"))
                break  # one GraphQL endpoint per host is enough to verify

        # 2) OpenAPI / Swagger specs + UI shells.
        for path in OPENAPI_PATHS + SWAGGER_UI_PATHS:
            url = f"https://{host}{path}"
            resp = await self.http.request("GET", url, retries=0)
            if resp is None or resp.status_code >= 400:
                resp = await self.http.request("GET", f"http://{host}{path}", retries=0)
                if resp is not None and resp.status_code < 400:
                    url = f"http://{host}{path}"
            if resp is None or resp.status_code >= 400:
                continue
            ok, kind, snippet = classify_openapi(
                resp.text, resp.status_code, resp.headers.get("content-type")
            )
            if ok:
                hits.append(
                    ApiHit(url, host, path, kind or "openapi",
                           "https" if url.startswith("https") else "http", snippet=snippet)
                )

        # 3) REST roots - JSON API responses, not HTML.
        for path in REST_PATHS:
            if path in (h.path for h in hits):
                continue  # already captured as a spec/doc
            url = f"https://{host}{path}"
            resp = await self.http.request("GET", url, retries=0)
            if resp is None or resp.status_code >= 400:
                resp = await self.http.request("GET", f"http://{host}{path}", retries=0)
                if resp is not None and resp.status_code < 400:
                    url = f"http://{host}{path}"
            if resp is None or resp.status_code >= 400:
                continue
            ok, kind = classify_rest(resp.text, resp.status_code, resp.headers.get("content-type"))
            if ok:
                snippet = resp.text[:1500]
                hits.append(
                    ApiHit(url, host, path, kind or "rest",
                           "https" if url.startswith("https") else "http", snippet=snippet)
                )

        return hits

    # ------------------------------------------------------------------ record

    def _record(self, result: CollectorResult, graph: AttackSurfaceGraph, hit: ApiHit) -> None:
        node_id = Node.make_id(NodeType.API, hit.url)
        host_id = Node.make_id(
            NodeType.DOMAIN if hit.host == graph.meta.target else NodeType.SUBDOMAIN, hit.host
        )
        prov = self.prov(hit.url)
        attrs: dict[str, Any] = {
            "host": hit.host,
            "path": hit.path,
            "url": hit.url,
            "kind": hit.kind,
            "scheme": hit.scheme,
            "source": "api_exposure",
        }
        if hit.snippet:
            if hit.kind in ("openapi", "swagger"):
                attrs["api_spec_sdl"] = hit.snippet
            else:
                attrs["api_response_snippet"] = hit.snippet

        node = Node.create(
            NodeType.API, hit.url,
            label=f"{hit.kind.upper()} at {hit.host}{hit.path}",
            attrs=attrs,
            provenance=prov,
            tags={"exposed", "api", hit.kind},
        )
        result.nodes.append(node)
        result.edges.append(
            Edge(source=host_id, target=node.id, type=EdgeType.EXPOSES, provenance=[prov])
        )

        # A discovery finding per endpoint. Severity reflects the *exposure*,
        # not the deep impact (graphql_verify grades introspection separately).
        if hit.kind == "graphql":
            # Check if the endpoint is auth-locked (returns auth errors to
            # unauthenticated probes). If so, downgrade to INFO: the endpoint
            # exists but an attacker cannot freely query it.
            snippet = (hit.snippet or "").lower()
            auth_locked = any(
                kw in snippet
                for kw in ("unauthorized", "authentication required", "forbidden",
                           "must be authenticated", "login required", "access denied",
                           "jwt", "bearer")
            )
            if auth_locked:
                sev, title = Severity.INFO, f"GraphQL endpoint at {hit.host}{hit.path} requires authentication"
                desc = (
                    "A GraphQL endpoint answers at this path but requires "
                    "authentication. The endpoint is noted for completeness "
                    "but is not a direct exposure."
                )
                remediation = (
                    "Ensure authentication is enforced on all operations and "
                    "introspection remains disabled in production."
                )
            else:
                sev, title = Severity.LOW, f"GraphQL endpoint exposed at {hit.host}{hit.path}"
                desc = (
                    "A GraphQL endpoint answers queries at this path. Exposed GraphQL "
                    "widens the attack surface - the next stage verifies whether "
                    "introspection or mutations are open."
                )
                remediation = (
                    "Disable introspection in production, restrict mutations to "
                    "authenticated roles, and apply a depth/complexity limit."
                )
        elif hit.kind in ("openapi", "swagger"):
            sev, title = Severity.MEDIUM, f"API specification exposed at {hit.host}{hit.path}"
            desc = (
                f"The {hit.kind} document at this path openly documents the API "
                "(operations, parameters, schemas). It is a turnkey map of the "
                "backend for an attacker and is itself a reverse-engineering aid."
            )
            remediation = (
                "Gate the spec behind authentication or remove it from production; "
                "serve docs from a separate, access-controlled environment."
            )
        else:  # rest / api-root
            # Check if the endpoint is auth-locked (returns auth errors to
            # unauthenticated probes). If so, downgrade to INFO: the endpoint
            # exists but an attacker cannot freely query it.
            if is_auth_locked_rest(hit.snippet or ""):
                sev, title = Severity.INFO, f"REST API root at {hit.host}{hit.path} requires authentication"
                desc = (
                    "A machine-readable API root responds but requires "
                    "authentication. The endpoint is noted for completeness "
                    "but is not a direct exposure."
                )
                remediation = (
                    "Require authentication at the API gateway; return 401/403 "
                    "instead of a 200 envelope for unauthenticated callers."
                )
            else:
                sev, title = Severity.MEDIUM, f"Unauthenticated REST API root at {hit.host}{hit.path}"
                desc = (
                    "A machine-readable API root responds without authentication. Even a "
                    "200 with an empty envelope tells an attacker the surface exists and "
                    "where to begin enumeration."
                )
                remediation = (
                    "Require authentication at the API gateway; return 401/403 instead of "
                    "a 200 envelope for unauthenticated callers."
                )

        result.findings.append(
            Finding(
                title=title,
                severity=sev,
                category="api-exposure",
                node_ids=[node_id, host_id],
                description=desc,
                evidence={
                    "url": hit.url,
                    "kind": hit.kind,
                    "snippet": hit.snippet,
                },
                remediation=remediation,
                collector=self.name,
            )
        )
