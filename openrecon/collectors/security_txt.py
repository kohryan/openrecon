"""Security.txt disclosure posture checker.

Checks for the presence and validity of /.well-known/security.txt
as an indicator of vulnerability disclosure posture.

This is NOT a CVE discovery mechanism — it measures whether a target
has a published security contact/disclosure process.
"""
from __future__ import annotations

import asyncio
from typing import Any

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult, Finding, Node, NodeType, ScanMode, Severity
)

SECURITY_TXT_PATH = "/.well-known/security.txt"
REQUIRED_FIELDS = {"Contact", "Expires"}
RECOMMENDED_FIELDS = {"Policy", "Acknowledgments", "Hiring", "Encryption"}


@register
class SecurityTxtCollector(Collector):
    """Check for security.txt disclosure posture.

    Checks /.well-known/security.txt on in-scope web hosts and reports
    whether a valid security disclosure policy is published.
    """
    name = "security_txt"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Check for security.txt vulnerability disclosure posture"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        targets = self._targets(graph)
        if not targets:
            result.errors.append("security_txt: no in-scope web hosts to check")
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._check_host(sem, graph, target, result) for target in targets]
        await asyncio.gather(*tasks)
        result.stats["security_txt_targets"] = len(targets)
        result.stats["security_txt_findings"] = len(result.findings)
        return result

    def _targets(self, graph: AttackSurfaceGraph) -> list[dict[str, Any]]:
        """Find crawled web hosts."""
        targets = []
        for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN):
            if n.attrs.get("http_status") or "web" in n.tags:
                targets.append({
                    "host": n.label,
                    "node_id": n.id,
                })
        return targets

    async def _check_host(self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph,
                          target: dict[str, Any], result: CollectorResult) -> None:
        async with sem:
            host = target["host"]
            url = f"https://{host}{SECURITY_TXT_PATH}"
            resp = await self.http.request("GET", url, retries=0)
            if resp is None or resp.status_code >= 400:
                return

            text = resp.text or ""
            if not text.strip():
                return

            # Parse security.txt fields
            fields = self._parse_fields(text)
            has_contact = "Contact" in fields
            has_expires = "Expires" in fields
            is_valid = has_contact and has_expires

            severity = Severity.LOW if is_valid else Severity.INFO
            title = f"security.txt {'valid' if is_valid else 'present but invalid'} at {host}"

            evidence = [
                {"type": "url", "value": url},
                {"type": "status_code", "value": resp.status_code},
                {"type": "has_contact", "value": has_contact},
                {"type": "has_expires", "value": has_expires},
            ]
            if "Contact" in fields:
                evidence.append({"type": "contact", "value": fields["Contact"]})
            if "Expires" in fields:
                evidence.append({"type": "expires", "value": fields["Expires"]})
            if "Policy" in fields:
                evidence.append({"type": "policy", "value": fields["Policy"]})

            result.findings.append(Finding(
                title=title,
                severity=severity,
                category="information-disclosure",
                type="finding",
                node_ids=[target["node_id"]],
                description=(
                    f"security.txt at {host} is {'valid' if is_valid else 'invalid'}. "
                    f"Contact: {'present' if has_contact else 'missing'}. "
                    f"Expires: {'present' if has_expires else 'missing'}."
                ),
                evidence=evidence,
                remediation=(
                    "Ensure security.txt contains at minimum Contact and Expires fields. "
                    "Add Policy, Acknowledgments, and Hiring fields for completeness."
                ),
                references=["https://securitytxt.org/"],
                collector=self.name,
                confidence=0.95,
                detection_method="HTTP_GET",
                source="security_txt",
            ))

    def _parse_fields(self, text: str) -> dict[str, str]:
        """Parse security.txt fields from text content."""
        fields: dict[str, str] = {}
        current_key = ""
        current_value = ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line and not line.startswith(" "):
                if current_key:
                    fields[current_key] = current_value.strip()
                key, _, value = line.partition(":")
                current_key = key.strip()
                current_value = value.strip()
            else:
                current_value += " " + line.strip()
        if current_key:
            fields[current_key] = current_value.strip()
        return fields
