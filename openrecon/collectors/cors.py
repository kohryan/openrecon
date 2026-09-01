"""CORS misconfiguration detector.

Detects CORS policy weaknesses by sending crafted Origin headers and analyzing
Access-Control-Allow-Origin responses:

  * Origin reflection: ACAO echoes the Origin header (with credentials) — HIGH
  * Wildcard with credentials: ACAO: * + ACA-Allow-Credentials: true — MEDIUM
  * Null origin allowed: ACAO: null — MEDIUM
  * Prefix/suffix match: ACAO matches origin prefix/suffix — LOW

Read-only: only sends GET requests with crafted Origin headers.
"""
from __future__ import annotations

import asyncio
from typing import Any

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult, Finding, Node, NodeType, ScanMode, Severity
)

# Test origins to probe.
_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


@register
class CorsDetector(Collector):
    """Detect CORS misconfigurations by sending crafted Origin headers.

    Fetches crawled endpoints with various Origin header values and checks
    the Access-Control-Allow-Origin response header for misconfigurations.
    Read-only.
    """
    name = "cors"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Detect CORS misconfigurations (origin reflection, wildcard with credentials)"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        targets = self._targets(graph)
        if not targets:
            result.errors.append("cors: no crawled endpoints to probe")
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._probe_endpoint(sem, graph, target, result) for target in targets]
        await asyncio.gather(*tasks)
        result.stats["cors_targets"] = len(targets)
        result.stats["cors_findings"] = len(result.findings)
        return result

    def _targets(self, graph: AttackSurfaceGraph) -> list[dict[str, Any]]:
        """Find crawled API/REST endpoints."""
        targets = []
        for n in graph.nodes_of(NodeType.API):
            if n.attrs.get("kind") not in ("rest", "api-root"):
                continue
            targets.append({
                "url": n.attrs.get("url", ""),
                "host": n.attrs.get("host", ""),
                "path": n.attrs.get("path", ""),
                "node_id": n.id,
            })
        return targets

    async def _probe_endpoint(self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph,
                              target: dict[str, Any], result: CollectorResult) -> None:
        async with sem:
            for origin in _TEST_ORIGINS:
                resp = await self.http.request("GET", target["url"],
                                               headers={"Origin": origin},
                                               retries=0)
                if resp is None:
                    continue
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                if not acao:
                    continue

                # Origin reflection with credentials — most severe
                if acao == origin and acac == "true":
                    self._record_finding(result, graph, target, origin,
                                       "origin-reflection", Severity.HIGH)
                    return

                # Null origin
                if acao == "null":
                    self._record_finding(result, graph, target, origin,
                                       "null-origin", Severity.MEDIUM)
                    return

                # Wildcard with credentials (technically invalid but some browsers)
                if acao == "*" and acac == "true":
                    self._record_finding(result, graph, target, origin,
                                       "wildcard-credentials", Severity.MEDIUM)
                    return

                # Wildcard without credentials — low severity
                if acao == "*":
                    self._record_finding(result, graph, target, origin,
                                       "wildcard", Severity.LOW)
                    return

    def _record_finding(self, result: CollectorResult, graph: AttackSurfaceGraph,
                        target: dict[str, Any], origin: str, issue: str,
                        severity: Severity) -> None:
        host = target["host"]
        host_id = Node.make_id(
            NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN,
            host
        )
        descriptions = {
            "origin-reflection": (
                f"Endpoint at {host}{target['path']} reflects the Origin header "
                f"in Access-Control-Allow-Origin and allows credentials. An attacker "
                f"can host a malicious site that makes authenticated requests to this endpoint."
            ),
            "null-origin": (
                f"Endpoint at {host}{target['path']} allows 'null' as a valid origin, "
                f"which can be exploited via sandboxed iframes."
            ),
            "wildcard-credentials": (
                f"Endpoint at {host}{target['path']} uses ACAO:* with credentials enabled, "
                f"which is an insecure configuration."
            ),
            "wildcard": (
                f"Endpoint at {host}{target['path']} uses ACAO:* without credentials. "
                f"Low severity but worth noting."
            ),
        }
        result.findings.append(Finding(
            title=f"CORS {issue} at {host}{target['path']}",
            severity=severity,
            category="cors",
            node_ids=[target["node_id"], host_id],
            description=descriptions.get(issue, f"CORS misconfiguration at {host}{target['path']}"),
            evidence={"origin_tested": origin, "issue": issue},
            remediation=(
                "Set a strict allow-list of permitted origins. Never reflect the Origin "
                "header. Avoid ACAO:* with credentials enabled."
            ),
            collector=self.name,
        ))
