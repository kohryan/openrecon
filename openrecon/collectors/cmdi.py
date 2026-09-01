"""OS Command Injection detector.

Detects command injection via two techniques:

  1. Time-based blind: inject `sleep 5` variants and measure response time.
     A delay >= 4s (when baseline is <1s) indicates the command executed.
  2. Error-based: look for shell error messages in the response
     ("command not found", "sh: 1:", "bin/bash:", etc.).

Payloads use injection characters (; | & ` $()) to break out of the
intended command context. Read-only: only `sleep` and `echo` payloads,
no destructive operations.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import quote

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult, Finding, Node, NodeType, ScanMode, Severity
)

# Time-based blind payloads. Each injects a sleep command.
CMDI_TIME_PROBES: list[str] = [
    ";sleep 5",
    "|sleep 5",
    "&sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    ";sleep+5",
    "|sleep+5",
    "&&sleep+5",
]

# Verification payload: longer sleep to confirm initial findings.
_VERIFY_SLEEP_S = 10.0
_VERIFY_THRESHOLD_S = 8.0

# Error-based payloads that trigger shell errors.
CMDI_ERROR_PROBES: list[str] = [
    ";id",
    "|id",
    "&id",
    "`id`",
    "$(id)",
    ";whoami",
    "|whoami",
]

# Shell error signatures that indicate command execution.
_ERROR_SIGNATURES = [
    "command not found",
    "sh: 1:",
    "bin/bash:",
    "uid=",
    "gid=",
    "root:",
]

# Context patterns that indicate a real error message (not page content).
_ERROR_CONTEXT = [
    "sh: 1:",
    "bash:",
    "command not found",
    "syntax error",
    "unexpected",
]

# Time threshold: if response takes >= 4s longer than baseline, it's a hit.
TIME_THRESHOLD_S = 4.0


def _is_error_context(body: str, sig: str, window: int = 200) -> bool:
    """Check if the signature appears in an error-message context, not page content."""
    idx = body.find(sig)
    if idx < 0:
        return False
    start = max(0, idx - window)
    end = min(len(body), idx + len(sig) + window)
    context = body[start:end]
    return any(ec in context for ec in _ERROR_CONTEXT)


@register
class CmdiDetector(Collector):
    """Detect OS command injection via time-based blind and error-based techniques.

    Targets crawled API/REST nodes with query parameters. For each parameter,
    injects command injection payloads and checks for time delays or shell
    errors in the response. Read-only: only `sleep` and `id`/`whoami` payloads.
    """
    name = "cmdi"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Detect OS command injection via blind time-based and error-based probing"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        targets = self._targets(graph)
        if not targets:
            result.errors.append("cmdi: no crawled endpoints with parameters to probe")
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._probe_endpoint(sem, graph, target, result) for target in targets]
        await asyncio.gather(*tasks)
        result.stats["cmdi_targets"] = len(targets)
        result.stats["cmdi_findings"] = len(result.findings)
        return result

    def _targets(self, graph: AttackSurfaceGraph) -> list[dict[str, Any]]:
        """Find crawled API/REST endpoints with query parameters."""
        targets = []
        for n in graph.nodes_of(NodeType.API):
            if n.attrs.get("kind") not in ("rest", "api-root"):
                continue
            params = n.attrs.get("query_params", [])
            if not params:
                from urllib.parse import urlparse, parse_qs
                try:
                    qs = parse_qs(urlparse(n.attrs.get("url", "")).query)
                    params = list(qs.keys())
                except ValueError:
                    pass
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

            # Measure baseline response time
            baseline_resp = await self.http.request("GET", url, retries=0)
            baseline_time = getattr(baseline_resp, "elapsed", 0.5) or 0.5

            for param in target["params"]:
                # Time-based blind
                for payload in CMDI_TIME_PROBES:
                    encoded = quote(payload, safe="")
                    probe_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
                    start = time.monotonic()
                    resp = await self.http.request("GET", probe_url, retries=0)
                    if resp is None:
                        continue
                    resp_time = getattr(resp, "elapsed", None)
                    if resp_time is None:
                        resp_time = time.monotonic() - start
                    if resp_time - baseline_time >= TIME_THRESHOLD_S:
                        # Verification: inject longer sleep to confirm real cmdi
                        verify_payload = f";sleep+{_VERIFY_SLEEP_S}"
                        verify_encoded = quote(verify_payload, safe="")
                        verify_url = f"{url}{'&' if '?' in url else '?'}{param}={verify_encoded}"
                        verify_start = time.monotonic()
                        verify_resp = await self.http.request("GET", verify_url, retries=0)
                        if verify_resp is None:
                            continue
                        verify_time = getattr(verify_resp, "elapsed", None)
                        if verify_time is None:
                            verify_time = time.monotonic() - verify_start
                        if verify_time - baseline_time >= _VERIFY_THRESHOLD_S:
                            self._record_finding(result, graph, target, payload,
                                               "time-based", resp_time, verified=True)
                            return

                # Error-based
                for payload in CMDI_ERROR_PROBES:
                    encoded = quote(payload, safe="")
                    probe_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
                    resp = await self.http.request("GET", probe_url, retries=0)
                    if resp is None:
                        continue
                    body = (resp.text or "").lower()
                    for sig in _ERROR_SIGNATURES:
                        if sig in body:
                            # Verify: real error messages appear in structured context
                            if _is_error_context(body, sig):
                                self._record_finding(result, graph, target, payload,
                                                   "error-based", sig, verified=True)
                                return

    def _record_finding(self, result: CollectorResult, graph: AttackSurfaceGraph,
                        target: dict[str, Any], payload: str, method: str,
                        evidence_val: float | str, verified: bool = False) -> None:
        host = target["host"]
        host_id = Node.make_id(
            NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN,
            host
        )
        # Lower severity if not verified, to reduce false positives
        severity = Severity.CRITICAL if verified else Severity.HIGH
        result.findings.append(Finding(
            title=f"Command injection via parameter '{target['params'][0]}' at {host}{target['path']}",
            severity=severity,
            category="cmdi",
            node_ids=[target["node_id"], host_id],
            description=(
                f"Parameter '{target['params'][0]}' at {host}{target['path']} appears to "
                f"execute OS commands ({method}). Payload: '{payload}'. "
                f"{'Verified with secondary test. ' if verified else ''}"
                "This can lead to full server compromise."
            ),
            evidence={"url": target["url"], "payload": payload,
                      "method": method, "indicator": str(evidence_val)},
            remediation=(
                "Never pass user input to a shell command. Use parameterized APIs "
                "or an allow-list of permitted values."
            ),
            collector=self.name,
        ))
