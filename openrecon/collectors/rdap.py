"""Registration data (RDAP, the structured successor to WHOIS)."""

from __future__ import annotations

from datetime import UTC, datetime
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

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


def _event(events: list[dict[str, Any]], action: str) -> str | None:
    for e in events or []:
        if e.get("eventAction") == action:
            return e.get("eventDate")
    return None


def _entity_name(entities: list[dict[str, Any]], role: str) -> str | None:
    for ent in entities or []:
        if role not in (ent.get("roles") or []):
            continue
        vcard = ent.get("vcardArray") or []
        if len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn":
                    return str(item[3])
        if ent.get("handle"):
            return str(ent["handle"])
    return None


@register
class RdapCollector(Collector):
    name = "rdap"
    stage = "registration"
    mode = ScanMode.PASSIVE
    description = "Domain registration data, registrar, and lifecycle dates via RDAP"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        data = await self.http.get_json(RDAP_BOOTSTRAP.format(domain=apex))
        if not data:
            result.errors.append(f"rdap: no registration data for {apex}")
            return result

        events = data.get("events") or []
        registered = _event(events, "registration")
        expires = _event(events, "expiration")
        updated = _event(events, "last changed")
        registrar = _entity_name(data.get("entities") or [], "registrar")
        statuses = data.get("status") or []

        domain_id = Node.make_id(NodeType.DOMAIN, apex)
        result.nodes.append(
            Node.create(
                NodeType.DOMAIN,
                apex,
                attrs={
                    "registrar": registrar,
                    "registered_at": registered,
                    "expires_at": expires,
                    "updated_at": updated,
                    "rdap_status": statuses,
                    "handle": data.get("handle"),
                },
                provenance=self.prov("rdap.org"),
            )
        )

        if registrar:
            org = Node.create(
                NodeType.ORGANIZATION,
                registrar,
                attrs={"role": "registrar"},
                provenance=self.prov("rdap.org"),
            )
            result.nodes.append(org)
            result.edges.append(
                Edge(
                    source=domain_id,
                    target=org.id,
                    type=EdgeType.REGISTERED_BY,
                    provenance=[self.prov("rdap.org")],
                )
            )

        result.findings.extend(self._lifecycle_findings(apex, domain_id, expires, statuses))
        result.stats["registrar"] = registrar
        return result

    def _lifecycle_findings(
        self, apex: str, domain_id: str, expires: str | None, statuses: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        if expires:
            try:
                exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=UTC)
                days = (exp - datetime.now(UTC)).days
                if days < 0:
                    sev, title = Severity.CRITICAL, f"Domain {apex} has expired"
                elif days <= 30:
                    sev, title = Severity.HIGH, f"Domain {apex} expires in {days} days"
                elif days <= 90:
                    sev, title = Severity.MEDIUM, f"Domain {apex} expires in {days} days"
                else:
                    sev, title = Severity.INFO, ""
                if title:
                    findings.append(
                        Finding(
                            title=title,
                            severity=sev,
                            category="domain-lifecycle",
                            node_ids=[domain_id],
                            description=(
                                "An expiring or expired domain can be re-registered by a third "
                                "party, handing them your email, SSO callbacks, and brand."
                            ),
                            evidence={"expires_at": expires, "days_remaining": days},
                            remediation="Renew the domain and enable registrar auto-renew.",
                            collector=self.name,
                        )
                    )
            except ValueError:
                pass

        locks = {s.lower() for s in statuses}
        if locks and not any("transfer prohibited" in s for s in locks):
            findings.append(
                Finding(
                    title=f"Registrar transfer lock not set on {apex}",
                    severity=Severity.MEDIUM,
                    category="domain-lifecycle",
                    node_ids=[domain_id],
                    description="Without clientTransferProhibited the domain is easier to hijack.",
                    evidence={"status": statuses},
                    remediation="Enable clientTransferProhibited (registrar lock) and 2FA on the registrar account.",
                    collector=self.name,
                )
            )
        return findings
