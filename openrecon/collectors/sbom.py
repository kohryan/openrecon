"""Client-side dependency inventory from what the browser is already served.

External attack surface tools stop at the HTTP header. That leaves the largest
source of real vulnerabilities - the application's own dependency tree -
completely invisible, and a scanner that reports "Strong" while a repository has
thirteen vulnerable packages is not being cautious, it is being wrong.

Some of that tree is genuinely observable from outside:

* **Source maps.** A `.map` file left in production contains the full
  `node_modules` path list. That is both a disclosure finding in its own right
  and a near-complete dependency manifest.
* **Bundle fingerprints.** Bundlers preserve library banner comments
  (`/*! jQuery v3.5.1 */`) and embedded version constants. React, Vue, Angular
  and friends all ship an identifiable version string in their production build.

What this cannot see is equally important and reported as such: build-time and
server-side dependencies never reach the browser. Those need `npm audit`,
Dependabot, or an SBOM from CI - and `openrecon.coverage` says so rather than
letting silence read as an all-clear.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

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

SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*'\"]+)")
NODE_MODULES_RE = re.compile(r"node_modules/((?:@[\w.-]+/)?[\w.-]+)")

SEMVER = r"\d+\.\d+\.\d+(?:-[\w.]+)?"

# Banner comments survive minification in most UMD builds: `/*! jQuery v3.5.1 */`
BANNER_RE = re.compile(
    rf"[/*!\s]{{2,}}\s*(?P<name>[A-Za-z][\w.\-]{{1,30}})(?:\.js)?\s+v?(?P<version>{SEMVER})"
)

# Frameworks that publish an identifiable version constant in production builds.
# Each entry: (package, marker that must be present, pattern yielding the version)
# Ordered: the first entry that matches a package wins, so precise patterns
# come before loose fallbacks.
FRAMEWORK_FINGERPRINTS: list[tuple[str, str, re.Pattern[str]]] = [
    # Next.js writes `t.version="12.1.6",t.router=` into its main chunk. The
    # neighbouring `.router` assignment is what keeps this from matching any
    # other library's version constant in the same bundle.
    ("next", "__NEXT_DATA__", re.compile(rf'\.version\s*=\s*"({SEMVER})"\s*,[\w$]+\.router')),
    ("next", "__NEXT_P", re.compile(rf'\.version\s*=\s*"({SEMVER})"')),
    ("nuxt", "__NUXT__", re.compile(rf'version:"({SEMVER})"')),
    ("react-dom", "ReactCurrentDispatcher", re.compile(rf'version:"({SEMVER})"')),
    ("react", "react.production.min", re.compile(rf'version:"({SEMVER})"')),
    ("vue", "__VUE_DEVTOOLS", re.compile(rf'version:"({SEMVER})"')),
    ("@angular/core", "ng.ɵcompilerFacade", re.compile(rf'"({SEMVER})"')),
    ("jquery", "jQuery.fn.jquery", re.compile(rf'jquery\s*[:=]\s*"({SEMVER})"')),
    ("lodash", "lodash.templateSources", re.compile(rf'VERSION\s*=\s*"({SEMVER})"')),
    ("moment", "moment.defineLocale", re.compile(rf'version\s*=\s*"({SEMVER})"')),
    ("axios", "axios/lib/core", re.compile(rf'VERSION\s*[:=]\s*"({SEMVER})"')),
    ("bootstrap", "bs.collapse", re.compile(rf'VERSION\s*[:=]\s*"({SEMVER})"')),
    ("three", "THREE.WebGLRenderer", re.compile(r'REVISION\s*=\s*"(\d+)"')),
]

# Build-tool layouts that identify a framework even without a version.
BUILD_SIGNATURES: list[tuple[str, str]] = [
    ("/_next/static/", "next"),
    ("/_nuxt/", "nuxt"),
    ("/assets/index-", "vite"),
    ("/static/js/main.", "create-react-app"),
    ("/_astro/", "astro"),
    ("/build/_shared/", "remix"),
]

MAX_BUNDLES = 12
MAX_BUNDLE_BYTES = 3_000_000


@register
class SbomCollector(Collector):
    name = "sbom"
    stage = "fingerprint"
    mode = ScanMode.ACTIVE
    description = "Recover client-side dependency versions from bundles and source maps"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        # `http` runs in this same stage, so its `web` tag may not exist yet.
        # Fall back to anything that resolves rather than silently doing nothing.
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if n.attrs.get("http_status") or "web" in n.tags
        ]
        if not hosts:
            hosts = [
                n.label
                for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
                if n.attrs.get("resolves") is not False
            ]
        hosts = self.targets_in_scope(hosts)[:20]
        if not hosts:
            return result

        sem = asyncio.Semaphore(max(self.config.concurrency // 2, 2))
        outcomes = await asyncio.gather(
            *(self._analyze_host(sem, graph, host) for host in hosts), return_exceptions=True
        )
        packages_found = 0
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                result.errors.append(f"sbom: {type(outcome).__name__}: {outcome}")
                continue
            result.extend(outcome)
            packages_found += int(outcome.stats.get("packages", 0))

        result.stats["packages"] = packages_found
        result.stats["hosts_analyzed"] = len(hosts)
        return result

    # ------------------------------------------------------------------ per host

    async def _analyze_host(
        self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph, host: str
    ) -> CollectorResult:
        out = CollectorResult()
        base = f"https://{host}/"
        async with sem:
            response = await self.http.request("GET", base, retries=0)
        if response is None:
            return out
        if response.status_code in (401, 403, 405, 429):
            # Edge protection is refusing us. Reporting nothing found here would
            # be indistinguishable from a clean result, so say what happened.
            out.errors.append(
                f"blocked: {host} answered {response.status_code} to bundle analysis "
                "- dependency inspection was prevented, not completed"
            )
            return out
        html = response.text[:512_000]
        if not html:
            return out

        node_type = NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN
        host_id = Node.make_id(node_type, host)
        prov = self.prov(base)

        bundles = self._bundle_urls(base, html)
        packages: dict[str, str] = {}
        build_tool = self._build_tool(bundles)

        for url in bundles[:MAX_BUNDLES]:
            async with sem:
                body = await self.http.get_text(url, retries=0, max_bytes=MAX_BUNDLE_BYTES)
            if not body:
                continue

            found_map = await self._check_sourcemap(sem, url, body)
            if found_map:
                map_url, sources = found_map
                out.extend(self._sourcemap_finding(host, host_id, map_url, sources, prov))
                for package in sources:
                    packages.setdefault(package, "")

            for package, version in self._fingerprint(body).items():
                if version or package not in packages:
                    packages[package] = version

        if build_tool and build_tool not in packages:
            packages[build_tool] = ""

        for package, version in sorted(packages.items()):
            tech = Node.create(
                NodeType.TECHNOLOGY,
                f"npm:{package}:{version or 'unknown'}",
                label=f"{package} {version}".strip(),
                attrs={
                    "product": package,
                    "version": version,
                    "ecosystem": "npm",
                    "source": "client-bundle",
                    "host": host,
                },
                provenance=prov,
                tags={"dependency"} | ({"unversioned"} if not version else set()),
            )
            out.nodes.append(tech)
            out.edges.append(
                Edge(source=host_id, target=tech.id, type=EdgeType.RUNS, provenance=[prov])
            )

        unversioned = sorted(p for p, v in packages.items() if not v)
        if unversioned:
            out.findings.append(
                Finding(
                    title=f"{len(unversioned)} client-side component(s) on {host} expose no version",
                    severity=Severity.INFO,
                    category="coverage-gap",
                    node_ids=[host_id],
                    description=(
                        "These components were identified but not versioned, so they cannot be "
                        "matched against CVE data. Their absence from the findings list is a gap "
                        "in this scan, not evidence that they are patched."
                    ),
                    evidence={"components": unversioned},
                    remediation=(
                        "Audit the dependency tree where it is authoritative - `npm audit`, "
                        "`pip-audit`, or an SBOM generated in CI. External scanning cannot "
                        "substitute for it."
                    ),
                    collector=self.name,
                )
            )

        out.stats["packages"] = len(packages)
        return out

    # ------------------------------------------------------------------ helpers

    def _bundle_urls(self, base: str, html: str) -> list[str]:
        origin = urlparse(base).netloc
        urls: list[str] = []
        for src in SCRIPT_SRC_RE.findall(html):
            absolute = urljoin(base, src)
            # Only same-origin bundles: a CDN's copy of a library is not this
            # site's dependency decision, and fetching it is someone else's traffic.
            if urlparse(absolute).netloc != origin:
                continue
            if absolute not in urls:
                urls.append(absolute)
        return urls

    def _build_tool(self, bundles: list[str]) -> str:
        for url in bundles:
            for marker, tool in BUILD_SIGNATURES:
                if marker in url:
                    return tool
        return ""

    async def _check_sourcemap(
        self, sem: asyncio.Semaphore, bundle_url: str, body: str
    ) -> tuple[str, list[str]] | None:
        """A published source map is a disclosure and a dependency manifest at once."""
        match = SOURCEMAP_RE.search(body[-2000:]) or SOURCEMAP_RE.search(body)
        if not match:
            return None
        reference = match.group(1)
        if reference.startswith("data:"):
            return None
        map_url = urljoin(bundle_url, reference)

        async with sem:
            payload = await self.http.get_text(map_url, retries=0, max_bytes=MAX_BUNDLE_BYTES)
        if not payload or not payload.lstrip().startswith("{"):
            return None
        try:
            document: dict[str, Any] = json.loads(payload)
        except ValueError:
            return None

        packages = sorted(
            {
                NODE_MODULES_RE.search(source).group(1)
                for source in (document.get("sources") or [])
                if NODE_MODULES_RE.search(str(source))
            }
        )
        return map_url, packages

    def _sourcemap_finding(
        self, host: str, host_id: str, map_url: str, packages: list[str], prov: Any
    ) -> CollectorResult:
        out = CollectorResult()
        secret = Node.create(
            NodeType.SECRET,
            map_url,
            label=f"source map on {host}",
            attrs={
                "host": host,
                "url": map_url,
                "leaks": "application source code and dependency tree",
                "packages_disclosed": len(packages),
            },
            provenance=prov,
            tags={"exposed", "source-disclosure"},
        )
        out.nodes.append(secret)
        out.edges.append(
            Edge(source=host_id, target=secret.id, type=EdgeType.LEAKS, provenance=[prov])
        )
        out.findings.append(
            Finding(
                title=f"Source map published on {host}",
                severity=Severity.MEDIUM,
                category="information-disclosure",
                node_ids=[secret.id, host_id],
                description=(
                    "The production build ships its source map, which reconstructs the original "
                    f"source and names {len(packages)} bundled packages. Attackers use it to read "
                    "your client-side logic, find hard-coded endpoints and keys, and match your "
                    "exact dependency versions to public exploits."
                ),
                evidence={"url": map_url, "packages_disclosed": len(packages),
                          "sample": packages[:15]},
                remediation=(
                    "Disable source map emission for production builds, or restrict the .map "
                    "files at the edge so only your error-reporting service can fetch them."
                ),
                collector=self.name,
            )
        )
        return out

    def _fingerprint(self, body: str) -> dict[str, str]:
        """Pull package versions out of a minified bundle."""
        found: dict[str, str] = {}

        for package, marker, pattern in FRAMEWORK_FINGERPRINTS:
            if package in found or marker not in body:
                continue
            match = pattern.search(body)
            if match:
                found[package] = match.group(1)

        for match in BANNER_RE.finditer(body[:200_000]):
            name = match.group("name").lower()
            # Banner comments are noisy: require something that looks like a
            # package name rather than a minified identifier.
            if len(name) < 3 or name in ("var", "function", "return", "window", "module"):
                continue
            found.setdefault(name, match.group("version"))

        return found
