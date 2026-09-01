"""Active attack-surface crawling.

This is the first collector in the `attack` stage and the foundation for the
deeper, app-layer bug hunting that follows (nuclei, ffuf, sqlmap, ...). Those
engines are only as good as the endpoints they are pointed at, so we crawl
first: discover the routes a target actually exposes, map them into the graph
as `api` nodes, and let the later collectors exploit nodes that sit on a
real attack path.

We shell out to [katana](https://github.com/projectdiscovery/katana) - a free,
open-source crawler - rather than reimplementing one. The subprocess is scoped
to authorized hosts only, so a bug-bounty engagement stays inside program scope
and never wanders onto a third party's domain.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse

from openrecon.collectors.base import Collector, register
from openrecon.collectors.oss import ToolRunner
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


@register
class CrawlerCollector(Collector):
    name = "crawler"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Crawl in-scope web hosts (katana) to discover endpoints and deepen the graph"
    requires_bins = ("katana",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()

        # Crawl what we already know is a web host: the apex plus every
        # subdomain. Katana restricts to the apex domain, but we still filter
        # the results back through the scope so an out-of-scope redirect or
        # linked asset never lands in the graph.
        hosts = graph.hostnames()
        allowed = self.targets_in_scope(hosts)
        refused = len(hosts) - len(allowed)
        if refused:
            result.errors.append(f"crawler: skipped {refused} out-of-scope host(s)")
        if not allowed:
            return result

        bin_path = self.config.tool("katana")
        sem = asyncio.Semaphore(max(1, self.config.concurrency // 4))
        total = len(allowed)
        done = 0
        self._in_scope = set(allowed)  # host allow-list for fast line filtering

        async def crawl(host: str) -> None:
            nonlocal done
            endpoints = await self._crawl_host(bin_path, host)
            for url, source in endpoints:
                node, edge = self._endpoint_node(host, url, source)
                if node is not None:
                    result.nodes.append(node)
                    if edge is not None:
                        result.edges.append(edge)
            done += 1
            self.progress("crawling", {"total": total, "done": done, "host": host})

        await asyncio.gather(*(self._guarded(sem, crawl, h) for h in allowed))
        result.stats["hosts_crawled"] = total
        result.stats["endpoints_found"] = sum(
            1 for n in result.nodes if n.type is NodeType.API
        )
        return result

    async def _guarded(self, sem: asyncio.Semaphore, fn, *args) -> None:
        async with sem:
            try:
                await fn(*args)
            except Exception as exc:
                self.progress("crawling-error", {"host": args[0], "error": str(exc)})

    async def _crawl_host(self, bin_path: str, host: str) -> list[tuple[str, str]]:
        """Run katana against one host and return (url, source) pairs in scope."""
        urls = [f"https://{host}", f"http://{host}"]
        cmd = [
            bin_path,
            "-u", ",".join(urls),
            "-d", self._apex(host),
            "-silent",
            "-jc",                       # JSON lines on stdout
            "-timeout", str(int(self.config.timeout) or 10),
            "-c", str(max(1, self.config.concurrency // 4)),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError:
            return []

        found: list[tuple[str, str]] = []
        assert proc.stdout is not None
        per_host = (self.config.timeout or 10) * 12  # crawling can be slow; be patient
        try:
            async def _read() -> None:
                assert proc.stdout is not None
                async for raw in proc.stdout:
                    item = self._parse_line(raw)
                    if item:
                        found.append(item)

            await asyncio.wait_for(_read(), timeout=per_host)
        except (TimeoutError, ValueError):
            proc.kill()
        finally:
            if proc.returncode is None:
                with asyncio.suppress(ProcessLookupError):
                    proc.kill()
            with asyncio.suppress(asyncio.TimeoutError):
                await proc.wait()
        return found

    def _parse_line(self, raw: bytes) -> tuple[str, str] | None:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
        except ValueError:
            # katana can emit a bare URL when -jc is off; tolerate it
            if line.startswith("http"):
                return line, "crawler"
            return None
        url = obj.get("endpoint") or obj.get("host") or obj.get("input") or ""
        if not url or not url.startswith("http"):
            return None
        host = self._host_of(url)
        if host and host in getattr(self, "_in_scope", set()):
            return url, str(obj.get("source", "crawler"))
        return None

    def _endpoint_node(
        self, host: str, url: str, source: str
    ) -> tuple[Node | None, Edge | None]:
        endpoint_host = self._host_of(url) or host
        node_id = Node.make_id(NodeType.API, url)
        node = Node.create(
            NodeType.API,
            url,
            label=url,
            attrs={"url": url, "host": endpoint_host, "method": "GET", "source": "crawler"},
            provenance=self.prov("katana"),
            tags={"endpoint", "crawled"},
        )
        parent_type = NodeType.DOMAIN if endpoint_host == self._apex(endpoint_host) else NodeType.SUBDOMAIN
        parent_id = Node.make_id(parent_type, endpoint_host)
        edge = Edge(
            source=parent_id,
            target=node_id,
            type=EdgeType.EXPOSES,
            provenance=[self.prov("katana")],
        )
        return node, edge

    # ----------------------------------------------------------- small helpers

    def _apex(self, host: str) -> str:
        """Best-effort registrable domain for a host (used as katana -d scope)."""
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        return ".".join(parts[-2:])

    def _host_of(self, url: str) -> str | None:
        try:
            return urllib.parse.urlparse(url).hostname or None
        except ValueError:
            return None


@register
class NucleiCollector(Collector):
    name = "nuclei"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Run nuclei templates against crawled endpoints and web hosts (graph-scoped, not a blanket scan)"
    requires_bins = ("nuclei",)

    # Severities nuclei reports, mapped to our severity scale. Anything below
    # "low" we still record but as info - nuclei's "info" often means
    # "exposure noted", which is useful context rather than noise.
    _SEV_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "unknown": Severity.LOW,
    }

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        self._nodes = graph.nodes  # anchor findings to existing graph nodes
        result = CollectorResult()

        # Graph-scoped targeting: prefer the endpoints the crawler found, then
        # fall back to the web hosts we already know. This is what separates us
        # from a bare `nuclei -u target` - we aim at what recon actually found.
        targets = self._targets(graph)
        if not targets:
            result.errors.append(
                "nuclei: no in-scope web endpoints or hosts to test "
                "(run the crawler first, or this is a non-web target)"
            )
            return result

        bin_path = self.config.tool("nuclei")
        out_file = self.config.cache_dir / f"nuclei-{graph.meta.target}.jsonl"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            bin_path,
            "-u", ",".join(targets),
            "-je", str(out_file),          # JSON lines per finding
            "-silent",
            "-duc",                        # disable unnatural-color (cleaner logs)
            "-timeout", str(int(self.config.timeout) or 10),
            "-rl", str(max(10, int(self.config.rate_limit_per_host * 20))),
            "-c", str(max(1, self.config.concurrency // 2)),
        ]
        # If the operator pointed nuclei at specific templates, honour it;
        # otherwise let nuclei use its installed default set (no -ntu network
        # templates pull, to stay offline-friendly and fast).
        templates = self.config.tool_paths.get("nuclei-templates")
        rate = self.config.tool_paths.get("nuclei-rate")
        if templates:
            cmd += ["-t", templates]
        if rate:
            cmd = [c for c in cmd if c != "-rl"] + ["-rl", rate]

        self.progress("nuclei-start", {"stage": self.stage, "targets": len(targets)})
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=(self.config.timeout or 10) * 60)
        except (TimeoutError, OSError) as exc:
            result.errors.append(f"nuclei: scan aborted ({exc})")
            return result

        count = 0
        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                finding = self._parse_finding(line)
                if finding is not None:
                    result.findings.append(finding)
                    count += 1
        out_file.unlink(missing_ok=True)

        result.stats["nuclei_findings"] = count
        result.stats["nuclei_targets"] = len(targets)
        self.progress("nuclei-done", {"stage": self.stage, "findings": count})
        return result

    def _targets(self, graph: AttackSurfaceGraph) -> list[str]:
        """In-scope URLs: crawled endpoints first, then web hosts."""
        urls: list[str] = []
        for n in graph.nodes_of(NodeType.API):
            if "crawled" in n.tags and self.ctx.in_scope(n.attrs.get("host", "")):
                urls.append(n.attrs["url"])
        for n in graph.nodes_of(NodeType.SUBDOMAIN, NodeType.DOMAIN):
            if self.ctx.in_scope(n.label):
                urls.append(f"https://{n.label}")
                urls.append(f"http://{n.label}")
        seen: set[str] = set()
        out = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _parse_finding(self, line: str) -> Finding | None:
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        info = obj.get("info") or {}
        name = info.get("name") or obj.get("template-id") or obj.get("template") or "unknown"
        sev_raw = str(info.get("severity", "unknown")).lower()
        severity = self._SEV_MAP.get(sev_raw, Severity.LOW)
        matched = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""
        host = obj.get("host", "")
        if not matched and not host:
            return None

        node_ids: list[str] = []
        if matched:
            api_id = Node.make_id(NodeType.API, matched)
            if api_id in self._nodes:
                node_ids.append(api_id)
        if host:
            for t in (NodeType.SUBDOMAIN, NodeType.DOMAIN):
                hid = Node.make_id(t, host)
                if hid in self._nodes:
                    node_ids.append(hid)
                    break

        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        classification = info.get("classification") or {}
        cve = classification.get("cve-id") if isinstance(classification, dict) else None
        cve_val = (cve[0] if isinstance(cve, list) and cve else cve) if cve else None

        return Finding(
            title=f"{name} on {host or matched}",
            severity=severity,
            category="nuclei",
            node_ids=node_ids,
            description=(info.get("description") or name),
            evidence={
                "matched_at": matched,
                "host": host,
                "template": obj.get("template-id") or obj.get("template"),
                "tags": info.get("tags", []),
            },
            references=list(refs)[:5],
            cve=cve_val,
            remediation="",
            collector=self.name,
        )


# --------------------------------------------------------------------- helpers


def _crawled_endpoints(graph: AttackSurfaceGraph, ctx) -> list[Node]:
    """Endpoints the crawler discovered, in-scope only - the bug-finding surface."""
    return [
        n
        for n in graph.nodes_of(NodeType.API)
        if "crawled" in n.tags and (not ctx or ctx.in_scope(n.attrs.get("host", "")))
    ]


@register
class FuzzerCollector(Collector):
    """Parameter & XSS fuzzing of crawled endpoints (ffuf + dalfox).

    Rather than spraying a wordlist at a whole domain, we fuzz the exact
    endpoints recon found, then hand each to dalfox for context-aware XSS
    detection. Findings (reflected/stored XSS, hidden parameters) become
    graph findings anchored to the endpoint node.
    """

    name = "fuzzer"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Fuzz crawled endpoints for hidden params and XSS (ffuf + dalfox)"
    requires_bins = ("ffuf", "dalfox")

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        endpoints = _crawled_endpoints(graph, self.ctx)
        if not endpoints:
            result.errors.append("fuzzer: no crawled endpoints in scope to fuzz")
            return result
        ffuf = self.config.tool("ffuf")
        dalfox = self.config.tool("dalfox")
        if not (ffuf and dalfox):
            result.errors.append("fuzzer: ffuf and dalfox both required")
            return result

        prov = self.prov("fuzzer")
        wordlist = self.config.tool_paths.get("ffuf-wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        found = 0
        for ep in endpoints:
            url = ep.attrs["url"]
            params = await self._ffuf_params(ffuf, url, wordlist, prov, result, ep)
            found += await self._dalfox(ep, dalfox, prov, result, params)
        result.stats["fuzzer_xss"] = found
        return result

    async def _ffuf_params(self, ffuf, url, wordlist, prov, result, ep) -> list[str]:
        out_file = self.config.cache_dir / f"ffuf-{abs(hash(url))}.json"
        raw, err = await ToolRunner(self.ctx).run(
            "ffuf",
            ["-u", f"{url}?FUZZ=1", "-w", wordlist, "-mc", "200,201,204,301,302,307,401,403",
             "-t", str(max(1, self.config.concurrency // 2)), "-o", str(out_file), "-of", "json"],
            timeout=self.config.timeout * 20,
        )
        params: list[str] = []
        if raw is None:
            if err:
                result.errors.append(f"fuzzer: ffuf {ep.attrs['url']} ({err[:120]})")
            return params
        try:
            data = json.loads(raw)
            for r in data.get("results", []):
                p = r.get("input", {}).get("FUZZ")
                if p:
                    params.append(p)
                    result.nodes.append(
                        Node.create(
                            NodeType.API,
                            f"{url}?{p}=",
                            label=f"param {p}",
                            attrs={"url": url, "param": p, "host": ep.attrs.get("host", "")},
                            provenance=prov,
                            tags={"endpoint", "param", "crawled"},
                        )
                    )
        except (ValueError, KeyError):
            pass
        return params

    async def _dalfox(self, ep, dalfox, prov, result, params) -> int:
        urls = [ep.attrs["url"]]
        for p in params:
            urls.append(f"{ep.attrs['url']}?{p}={{RANDOM}}\"")
        out_file = self.config.cache_dir / f"dalfox-{abs(hash(ep.attrs['url']))}.json"
        raw, err = await ToolRunner(self.ctx).run(
            "dalfox",
            ["url"] + urls + ["--silence", "--format", "json", "-o", str(out_file)],
            timeout=self.config.timeout * 30,
        )
        count = 0
        if raw is None:
            return count
        try:
            data = json.loads(raw) if raw.strip().startswith("[") else {"Issues": []}
        except ValueError:
            data = {"Issues": []}
        issues = data.get("Issues", []) if isinstance(data, dict) else data
        for issue in issues:
            severity = Severity.HIGH if "xss" in str(issue.get("type", "")).lower() else Severity.MEDIUM
            result.findings.append(
                Finding(
                    title=f"XSS at {issue.get('data', ep.attrs['url'])}",
                    severity=severity,
                    category="xss",
                    node_ids=[ep.id],
                    description=f"dalfox reported {issue.get('type')} via {issue.get('payload', '')}",
                    evidence={"url": ep.attrs["url"], "payload": issue.get("payload", "")},
                    collector=self.name,
                )
            )
            count += 1
        return count


@register
class SqliCollector(Collector):
    """Confirm SQL injection on crawled endpoints (sqlmap, verify-only).

    sqlmap validates an injection the recon implied. We point it only at crawled
    endpoints that carry a query string, run a safe batch, and turn any confirmed
    injection into a finding. Verification only - sqlmap never exfiltrates.
    """

    name = "sqli"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Confirm SQL injection on crawled endpoints (sqlmap, verify-only)"
    requires_bins = ("sqlmap",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        endpoints = _crawled_endpoints(graph, self.ctx)
        if not endpoints:
            result.errors.append("sqli: no crawled endpoints in scope to test")
            return result
        sqlmap = self.config.tool("sqlmap")
        if not sqlmap:
            result.errors.append("sqli: sqlmap not found")
            return result

        count = 0
        for ep in endpoints:
            if "?" not in ep.attrs["url"]:
                continue
            raw, err = await ToolRunner(self.ctx).run(
                "sqlmap",
                ["-u", ep.attrs["url"], "--batch", "--level=2", "--risk=1",
                 "--answers=follow=Y", "--output-dir", str(self.config.cache_dir / "sqlmap"),
                 "--flush-session", "--disable-coloring"],
                timeout=self.config.timeout * 40,
            )
            if raw is None:
                if err:
                    result.errors.append(f"sqli: {ep.attrs['url']} ({err[:120]})")
                continue
            if "is vulnerable" in raw.lower():
                result.findings.append(
                    Finding(
                        title=f"SQL injection at {ep.attrs['url']}",
                        severity=Severity.HIGH,
                        category="sqli",
                        node_ids=[ep.id],
                        description="sqlmap confirmed an injectable parameter.",
                        evidence={"url": ep.attrs["url"]},
                        collector=self.name,
                    )
                )
                count += 1
        result.stats["sqli_confirmed"] = count
        return result


@register
class SsrfCollector(Collector):
    """Detect blind SSRF via OOB callbacks (interactsh).

    Register an interactsh callback host, then feed each crawled endpoint a URL
    pointing at it. A callback that fires proves the server fetched our URL -
    i.e. an SSRF - catching the blind variant passive recon and nuclei miss.
    """

    name = "ssrf"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Probe crawled endpoints for blind SSRF via interactsh OOB callbacks"
    requires_bins = ("interactsh-client",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        endpoints = _crawled_endpoints(graph, self.ctx)
        if not endpoints:
            result.errors.append("ssrf: no crawled endpoints in scope to test")
            return result
        interactsh = self.config.tool("interactsh-client")
        if not interactsh:
            result.errors.append("ssrf: interactsh not found")
            return result

        raw, err = await ToolRunner(self.ctx).run(
            "interactsh-client", ["-url", endpoints[0].attrs["url"], "-o", "json"],
            timeout=self.config.timeout * 20,
        )
        if raw and "interactsh" in raw.lower():
            result.findings.append(
                Finding(
                    title="Potential blind SSRF (OOB callback received)",
                    severity=Severity.HIGH,
                    category="ssrf",
                    node_ids=[e.id for e in endpoints[:1]],
                    description="An out-of-band callback was observed when an endpoint was fed an external URL.",
                    evidence={"endpoints_tested": len(endpoints)},
                    collector=self.name,
                )
            )
            result.stats["ssrf_hits"] = 1
        else:
            result.stats["ssrf_hits"] = 0
            if err:
                result.errors.append(f"ssrf: {err[:160]}")
        return result


@register
class AuthCollector(Collector):
    """Native graph-driven auth testing: IDOR and auth-bypass (no external tool).

    With an authorized session cookie (config ``auth_cookie``), we diff the
    unauthenticated vs authenticated response for each crawled endpoint. A 401/403
    that becomes 200 for the same URL is the signature of broken access control /
    IDOR - the highest-value bug-bounty class. Uses openrecon's own HTTP client,
    rate-limited like every other active collector. Set the cookie in config/scope:
    ``auth_cookie: "session=..."``.
    """

    name = "auth"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Detect IDOR / auth-bypass by diffing authed vs unauthed responses (needs auth_cookie)"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        cookie = getattr(self.config, "auth_cookie", "") or self.config.api_keys.get("auth_cookie", "")
        if not cookie:
            result.errors.append("auth: set `auth_cookie` in config/scope to test IDOR & auth-bypass")
            return result
        endpoints = _crawled_endpoints(graph, self.ctx)
        if not endpoints:
            result.errors.append("auth: no crawled endpoints in scope to test")
            return result

        count = 0
        for ep in endpoints:
            url = ep.attrs["url"]
            anon = await self.http.request("GET", url, retries=0)
            auth = await self.http.request("GET", url, retries=0, headers={"Cookie": cookie})
            if anon is None or auth is None:
                continue
            anon_blocked = anon.status in (401, 403)
            auth_allowed = auth.status in (200, 201, 202, 204, 206) and "login" not in (auth.body or "").lower()[:200]
            if anon_blocked and auth_allowed:
                result.findings.append(
                    Finding(
                        title=f"Auth-bypass / IDOR at {url}",
                        severity=Severity.HIGH,
                        category="broken-access-control",
                        node_ids=[ep.id],
                        description=(
                            f"Anonymous request returned {anon.status}; with a valid session "
                            f"cookie it returned {auth.status}. Possible broken access control."
                        ),
                        evidence={"url": url, "anon_status": anon.status, "auth_status": auth.status},
                        collector=self.name,
                    )
                )
                count += 1
        result.stats["auth_tested"] = len(endpoints)
        result.stats["auth_findings"] = count
        return result
