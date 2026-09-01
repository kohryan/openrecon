"""Reverse-engineering exposure detection.

The "attack" stage so far finds *what* an app exposes (endpoints, GraphQL,
specs). This collector answers a different question: can an attacker rebuild
the *source* of the application without ever touching the server?

Modern web apps ship a lot of recoverable build output to the browser:

  * source maps (``app.js.map``) - a published .map restores original file
    names, line numbers, and (for bundled apps) the original module tree.
    That is a direct reverse-engineering shortcut, and leaks internal paths,
    secret-bearing filenames, and tech choices.
  * build manifests (``webpack://``, Vite ``@vite/client``, Angular
    ``3rdpartylicenses.txt``, sourcemap references in inline scripts) - they
    name the framework, the bundler, the dependency tree, and private module
    paths.
  * exposed API specs / docs (``.proto`` gRPC refs, raw ``.graphql`` schema
    files, ``swagger.yaml``) - a precise contract for the backend, often
    richer than the JSON the ``api_exposure`` collector captured.

All checks are read-only GETs against standard, predictable locations derived
from the JS/CSS the target already serves, plus a handful of well-known roots.
We never download source; we flag that the *target* is publishing it.

Findings anchor to the host (and to the related ``api`` node when one exists)
and are graded by how much of the original build they hand over.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any

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

# Inline ``//# sourceMappingURL=`` comments, or a JS file that we can fetch a
# sibling ``.map`` for. Many bundles also reference sourcemaps in the
# devtools-only ``SourceMap:`` / ``X-SourceMap`` header; we check both.
SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s\"'<>]+)", re.IGNORECASE)

# Build-manifest markers that name the framework / bundler / internal tree.
MANIFEST_MARKERS: list[tuple[str, str, Severity]] = [
    # (needle-in-body, human label, severity when leaked)
    ("webpackjsonp", "webpack bundle", Severity.LOW),
    ("__webpack_require__", "webpack module graph", Severity.LOW),
    ("@vite/client", "Vite dev client", Severity.INFO),
    ("vite_", "Vite build", Severity.INFO),
    ("nginject", "AngularJS build", Severity.INFO),
    ("3rdpartylicenses.txt", "Angular license manifest", Severity.LOW),
    ("parcelrequire", "Parcel bundle", Severity.INFO),
    ("esbuild", "esbuild bundle", Severity.INFO),
    ("rollup", "Rollup bundle", Severity.INFO),
    ("//# moduleid", "bundled module map", Severity.LOW),
]

# Well-known spec/doc roots that hand over a precise backend contract.
SPEC_PATHS = [
    "/swagger.yaml",
    "/swagger.yml",
    "/api/swagger.yaml",
    "/openapi.yaml",
    "/openapi.yml",
    "/docs/openapi.yaml",
    "/schema.graphql",
    "/api/schema.graphql",
    "/graphql/schema.graphql",
    "/.well-known/graphql.json",
    "/proto/api.proto",
    "/api/api.proto",
    "/v1/api.proto",
]

# Recognise a YAML OpenAPI/Swagger document by its opening keys.
_YAML_SPEC_RE = re.compile(r"^\s*(openapi|swagger)\s*:", re.IGNORECASE | re.MULTILINE)
# A GraphQL SDL schema file.
_GRAPHQL_SDL_RE = re.compile(r"^\s*(type|schema|interface|enum|input|scalar)\s+\w+", re.MULTILINE)
# A gRPC/protobuf service definition.
_PROTO_RE = re.compile(r"^\s*(syntax|service|message|package)\s*=", re.MULTILINE)


@dataclass
class ReHit:
    url: str
    host: str
    kind: str  # sourcemap | manifest | spec
    label: str
    evidence: str
    severity: Severity


@register
class ReverseEngineeringCollector(Collector):
    """Detect artifacts that let an attacker reverse-engineer the application.

    Looks for published source maps, build manifests, and raw API spec/doc files
    on in-scope web hosts. Read-only; never downloads application source.
    """

    name = "reverse_engineering"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Detect source maps, build manifests, and raw API specs that enable reverse engineering"

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
                "reverse_engineering: no in-scope web hosts to inspect "
                "(run fingerprint/http first, or this is a non-web target)"
            )
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        total = len(hosts)
        done = 0
        self.progress("reverse-start", {"total": total})

        async def inspect(host: str) -> None:
            nonlocal done
            async with sem:
                hits = await self._inspect_host(host, graph)
                for hit in hits:
                    self._record(result, graph, hit)
            done += 1
            self.progress("reverse", {"done": done, "total": total, "host": host})

        await asyncio.gather(*(inspect(h) for h in hosts))
        result.stats["re_hosts_inspected"] = total
        result.stats["re_artifacts_found"] = len(result.findings)
        self.progress("reverse-done", {"found": result.stats["re_artifacts_found"]})
        return result

    # --------------------------------------------------------------- inspecting

    async def _inspect_host(self, host: str, graph: AttackSurfaceGraph) -> list[ReHit]:
        hits: list[ReHit] = []

        # 1) Source maps: fetch the main JS/CSS entrypoints the host already
        #    served, then look for a sourceMappingURL we can pull a .map from.
        for ep in self._entrypoints(graph, host):
            for scheme in ("https", "http"):
                base = f"{scheme}://{host}{ep}"
                resp = await self.http.request("GET", base, retries=0)
                if resp is not None and resp.status_code < 400:
                    body = resp.text or ""
                    m = SOURCEMAP_RE.search(body[:500_000])
                    header_map = resp.headers.get("sourcemap") or resp.headers.get("x-sourcemap")
                    map_ref = (m.group(1) if m else None) or header_map
                    if map_ref:
                        map_url = self._resolve(base, map_ref)
                        mresp = await self.http.request("GET", map_url, retries=0)
                        if mresp is not None and mresp.status_code < 400:
                            is_map = '"sources"' in (mresp.text or "")[:2000] or map_url.endswith(".map")
                            if is_map:
                                n_sources = count_sources(mresp.text or "")
                                hits.append(ReHit(
                                    map_url, host, "sourcemap",
                                    f"JavaScript source map exposed ({n_sources} sources)",
                                    f"Original sources recoverable from {map_url}",
                                    Severity.HIGH if n_sources > 1 else Severity.MEDIUM,
                                ))
                    break  # https worked; skip http

        # 2) Build manifests: fetch the homepage + common bundle paths and grep
        #    for framework/bundler markers naming the internal build.
        manifest_paths = ["/", "/assets/", "/static/", "/js/", "/_next/static/"]
        for path in manifest_paths:
            url = f"https://{host}{path}"
            resp = await self.http.request("GET", url, retries=0)
            if resp is None or resp.status_code >= 400:
                resp = await self.http.request("GET", f"http://{host}{path}", retries=0)
            if resp is None or resp.status_code >= 400:
                continue
            raw = resp.text or ""
            lowered = raw[:500_000].lower()
            for needle, label, sev in MANIFEST_MARKERS:
                if needle.lower() in lowered:
                    hits.append(ReHit(
                        url, host, "manifest",
                        f"Build manifest leaks {label}",
                        f"{label} marker found in {url}",
                        sev,
                    ))
                    break  # one manifest note per path is enough

        # 3) Raw API specs / docs that hand over a precise contract.
        for spec_path in SPEC_PATHS:
            url = f"https://{host}{spec_path}"
            resp = await self.http.request("GET", url, retries=0)
            if resp is None or resp.status_code >= 400:
                resp = await self.http.request("GET", f"http://{host}{spec_path}", retries=0)
                if resp is not None and resp.status_code < 400:
                    url = f"http://{host}{spec_path}"
            if resp is None or resp.status_code >= 400:
                continue
            text = resp.text or ""
            if _YAML_SPEC_RE.search(text):
                hits.append(ReHit(
                    url, host, "spec",
                    "OpenAPI/Swagger YAML spec exposed",
                    f"Full API contract at {url}",
                    Severity.MEDIUM,
                ))
            elif _GRAPHQL_SDL_RE.search(text):
                hits.append(ReHit(
                    url, host, "spec",
                    "Raw GraphQL SDL schema exposed",
                    f"Backend schema at {url}",
                    Severity.MEDIUM,
                ))
            elif _PROTO_RE.search(text):
                hits.append(ReHit(
                    url, host, "spec",
                    "gRPC/protobuf service definition exposed",
                    f"Service contract at {url}",
                    Severity.MEDIUM,
                ))

        return hits

    # ------------------------------------------------------------------ helpers

    def _entrypoints(self, graph: AttackSurfaceGraph, host: str) -> list[str]:
        """JS/CSS paths the host already served, plus standard entrypoints."""
        known: list[str] = []
        for n in graph.nodes_of(NodeType.API):
            if n.attrs.get("host") == host and n.attrs.get("path"):
                known.append(n.attrs["path"])
        known += [
            "/main.js", "/app.js", "/index.js", "/bundle.js", "/static/js/main.js",
            "/_next/static/chunks/main.js", "/assets/index.js", "/js/app.js",
            "/app.js", "/dist/main.js",
        ]
        seen: set[str] = set()
        out: list[str] = []
        for p in known:
            if not p.startswith("/"):
                continue
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out[:15]

    @staticmethod
    def _resolve(base_url: str, ref: str) -> str:
        from urllib.parse import urljoin

        return urljoin(base_url, ref)

    # ------------------------------------------------------------------ record

    def _record(self, result: CollectorResult, graph: AttackSurfaceGraph, hit: ReHit) -> None:
        host_id = Node.make_id(
            NodeType.DOMAIN if hit.host == graph.meta.target else NodeType.SUBDOMAIN, hit.host
        )
        # Relate to an existing api node on the same host when one exists.
        api_node_id = None
        for n in graph.nodes_of(NodeType.API):
            if n.attrs.get("host") == hit.host:
                api_node_id = n.id
                break
        node_ids = [host_id] + ([api_node_id] if api_node_id else [])

        attrs: dict[str, Any] = {
            "host": hit.host,
            "url": hit.url,
            "kind": f"re-{hit.kind}",
            "source": "reverse_engineering",
            "leak_type": hit.kind,
        }
        node = Node.create(
            NodeType.API, hit.url,
            label=hit.label,
            attrs=attrs,
            provenance=self.prov(hit.url),
            tags={"exposed", "reverse-engineering", hit.kind},
        )
        result.nodes.append(node)
        result.edges.append(
            Edge(source=host_id, target=node.id, type=EdgeType.LEAKS, provenance=[self.prov(hit.url)])
        )

        if hit.kind == "sourcemap":
            desc = (
                "A JavaScript source map is publicly served, restoring the original "
                "source file names, structure, and often the internal module tree of "
                "the application. This is a direct reverse-engineering shortcut: it "
                "leaks internal paths, filenames, and tech choices an attacker would "
                "otherwise have to probe for."
            )
            remediation = (
                "Strip source maps from production builds (or serve them only from a "
                "separate, access-controlled origin). Never publish .map files alongside "
                "minified assets."
            )
        elif hit.kind == "manifest":
            desc = (
                "The page leaks a build manifest / bundler marker that names the "
                "framework, bundler, and internal module paths. Combined with other "
                "leaks it lets an attacker reconstruct the application's structure."
            )
            remediation = (
                "Minify and mangle aggressively, avoid debug-only globals in production, "
                "and keep build manifests off the public origin."
            )
        else:  # spec
            desc = (
                "A raw API specification is served in the open - a precise, machine-readable "
                "contract of every operation, parameter, and type the backend exposes. It is "
                "a turnkey map for reverse engineering and abuse."
            )
            remediation = (
                "Gate raw spec/doc files behind authentication or remove them from production; "
                "document APIs in a separate, access-controlled environment."
            )

        result.findings.append(
            Finding(
                title=hit.label,
                severity=hit.severity,
                category="reverse-engineering",
                node_ids=node_ids,
                description=desc,
                evidence={"url": hit.url, "leak_type": hit.kind},
                remediation=remediation,
                collector=self.name,
            )
        )


def count_sources(map_text: str) -> int:
    """How many original source files a .map recoverably lists."""
    try:
        obj = json.loads(map_text[:400_000])
    except ValueError:
        return 1 if '"sources"' in map_text else 0
    sources = obj.get("sources") if isinstance(obj, dict) else None
    if isinstance(sources, list):
        return len(sources)
    return 1
