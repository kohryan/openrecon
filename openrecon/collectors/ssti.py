"""Server-Side Template Injection (SSTI) detector.

Probes crawled API/REST endpoints with template-engine payloads and detects
whether the server rendered them. Covers the major engines:

  * Jinja2 / Twig / Smarty:  {{7*7}}, ${{7*7}}
  * Velocity / Freemarker:   ${7*7}, #{7*7}
  * ERB / ASP:               <%= 7*7 %>
  * Generic polyglot:        ${{<%[%'"}}%.

A rendered result (e.g. "49" from "7*7") in the response body that was not in
the original payload is a positive detection. Read-only: payloads are
arithmetic only, no side effects.
"""
from __future__ import annotations

import asyncio
from typing import Any

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult, Finding, Node, NodeType, ScanMode, Severity
)

# (payload, expected_rendered_value) pairs covering major template engines.
SSTI_PROBES: list[tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("${{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("<%= 7*7 %>\n", "49"),
]


def render_probe(response_body: str, payload: str, expected: str = "49") -> bool:
    """Return True if the response body contains the rendered expected value
    where the payload was injected, indicating SSTI.

    Heuristic: the expected value appears in the response but the literal
    payload does not (it was consumed by the template engine and replaced
    with the rendered result).
    """
    if not response_body:
        return False
    # The payload was rendered: expected value present, original payload gone
    return expected in response_body and payload not in response_body


def _extract_params(url: str) -> list[str]:
    """Extract query parameter names from a URL."""
    from urllib.parse import urlparse, parse_qs
    try:
        qs = parse_qs(urlparse(url).query)
        return list(qs.keys())
    except ValueError:
        return []


@register
class SstiDetector(Collector):
    """Detect SSTI by injecting template payloads into endpoint parameters.

    Targets crawled API/REST nodes with query parameters. For each parameter,
    injects a payload and checks if the server rendered it. Read-only.
    """
    name = "ssti"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Detect Server-Side Template Injection (SSTI) via parameter probing"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        targets = self._targets(graph)
        if not targets:
            result.errors.append("ssti: no crawled endpoints with parameters to probe")
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._probe_endpoint(sem, graph, target, result) for target in targets]
        await asyncio.gather(*tasks)
        result.stats["ssti_targets"] = len(targets)
        result.stats["ssti_findings"] = len(result.findings)
        return result

    def _targets(self, graph: AttackSurfaceGraph) -> list[dict[str, Any]]:
        """Find crawled API/REST endpoints with query parameters."""
        targets = []
        for n in graph.nodes_of(NodeType.API):
            if n.attrs.get("kind") not in ("rest", "api-root", "graphql"):
                continue
            params = n.attrs.get("query_params", [])
            if not params:
                params = _extract_params(n.attrs.get("url", ""))
            if params:
                targets.append({
                    "url": n.attrs.get("url", ""),
                    "host": n.attrs.get("host", ""),
                    "path": n.attrs.get("path", ""),
                    "params": params,
                    "node_id": n.id,
                })
        return targets

    async def _probe_endpoint(self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph,
                              target: dict[str, Any], result: CollectorResult) -> None:
        async with sem:
            url = target["url"]
            host = target["host"]
            for param in target["params"]:
                for payload, expected in SSTI_PROBES:
                    probe_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    resp = await self.http.request("GET", probe_url, retries=0)
                    if resp is None or resp.status_code >= 500:
                        continue
                    if render_probe(resp.text or "", payload, expected):
                        host_id = Node.make_id(
                            NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN,
                            host
                        )
                        result.findings.append(Finding(
                            title=f"SSTI via parameter '{param}' at {host}{target['path']}",
                            severity=Severity.CRITICAL,
                            category="ssti",
                            node_ids=[target["node_id"], host_id],
                            description=(
                                f"Parameter '{param}' at {host}{target['path']} appears to "
                                f"render template payload '{payload}' -> '{expected}'. "
                                "This indicates Server-Side Template Injection, which can "
                                "lead to remote code execution."
                            ),
                            evidence={"url": probe_url, "payload": payload,
                                      "expected": expected, "param": param},
                            remediation=(
                                "Never pass user input directly into a template engine. "
                                "Use a sandboxed engine or pass data as context variables "
                                "only, not as template source."
                            ),
                            collector=self.name,
                        ))
                        return
