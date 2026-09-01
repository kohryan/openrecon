"""Zone records, and the email/DNS hygiene findings that fall out of them."""

from __future__ import annotations

import asyncio

from openrecon.collectors._platforms import tenant_platform
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

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")

# Nameserver suffixes whose zones are commonly abused for subdomain takeover.
DANGLING_HINTS = ("azure-dns", "awsdns", "domaincontrol", "cloudflare")


@register
class DnsRecordsCollector(Collector):
    name = "dns"
    stage = "dns"
    mode = ScanMode.PASSIVE
    description = "Apex zone records (A/AAAA/MX/NS/TXT/SOA/CAA) and email-auth posture"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        domain_id = Node.make_id(NodeType.DOMAIN, apex)

        answers = dict(
            zip(
                RECORD_TYPES,
                await asyncio.gather(*(self.dns.query(apex, rt) for rt in RECORD_TYPES)),
                strict=True,
            )
        )
        dmarc = await self.dns.query(f"_dmarc.{apex}", "TXT")

        result.nodes.append(
            Node.create(
                NodeType.DOMAIN,
                apex,
                attrs={f"dns_{k.lower()}": v for k, v in answers.items() if v},
                provenance=self.prov("dns"),
            )
        )

        for ns in answers["NS"]:
            host = ns.rstrip(".")
            if not host:
                continue
            node = Node.create(
                NodeType.NAMESERVER, host, provenance=self.prov("dns"), tags={"infrastructure"}
            )
            result.nodes.append(node)
            result.edges.append(
                Edge(
                    source=domain_id,
                    target=node.id,
                    type=EdgeType.DELEGATES_TO,
                    provenance=[self.prov("dns")],
                )
            )

        for mx in answers["MX"]:
            parts = mx.split()
            host = parts[-1].rstrip(".")
            if not host:
                # RFC 7505 "null MX" (0 .) - the domain declares it accepts no mail.
                continue
            node = Node.create(
                NodeType.MAILSERVER,
                host,
                attrs={"priority": parts[0] if len(parts) > 1 else None},
                provenance=self.prov("dns"),
                tags={"infrastructure"},
            )
            result.nodes.append(node)
            result.edges.append(
                Edge(
                    source=domain_id,
                    target=node.id,
                    type=EdgeType.MAIL_VIA,
                    provenance=[self.prov("dns")],
                )
            )

        platform = tenant_platform(apex)
        if platform:
            # The tenant owns the app, not the zone. SPF/DMARC/CAA advice here
            # is a change only the platform can make, so reporting it as their
            # finding is noise that displaces something they can act on.
            result.findings.append(
                Finding(
                    title=f"{apex} is a tenant hostname on {platform}",
                    severity=Severity.INFO,
                    category="attack-surface-sprawl",
                    node_ids=[domain_id],
                    description=(
                        f"This hostname sits inside {platform}'s zone. DNS-level controls "
                        "(SPF, DMARC, CAA, registrar locks) are set by the platform and are "
                        "not yours to change, so they are not reported as findings against you. "
                        "A custom domain you control would put those controls back in your hands."
                    ),
                    evidence={"platform": platform},
                    remediation=(
                        f"For anything that must carry your own trust decisions, move it to a "
                        f"domain you own and point it at {platform} with a CNAME."
                    ),
                    collector=self.name,
                )
            )
        else:
            result.findings.extend(
                self._email_auth_findings(apex, domain_id, answers["TXT"], dmarc, answers["MX"])
            )
            result.findings.extend(self._dns_hygiene_findings(apex, domain_id, answers))
        result.stats["records"] = {k: len(v) for k, v in answers.items()}
        return result

    # ------------------------------------------------------------------ checks

    def _email_auth_findings(
        self,
        apex: str,
        domain_id: str,
        txt: list[str],
        dmarc: list[str],
        mx: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        spf = [t for t in txt if t.lower().startswith("v=spf1")]

        if not spf:
            findings.append(
                Finding(
                    title=f"No SPF record on {apex}",
                    severity=Severity.MEDIUM if mx else Severity.LOW,
                    category="email-security",
                    node_ids=[domain_id],
                    description="Without SPF, anyone can send mail claiming to be this domain.",
                    remediation='Publish a TXT record: "v=spf1 include:<your provider> -all"',
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                    collector=self.name,
                )
            )
        else:
            record = spf[0]
            if record.rstrip().endswith("+all"):
                findings.append(
                    Finding(
                        title=f"SPF record on {apex} ends in +all",
                        severity=Severity.HIGH,
                        category="email-security",
                        node_ids=[domain_id],
                        description="`+all` authorizes the entire internet to send as this domain.",
                        evidence={"spf": record},
                        remediation="Replace `+all` with `-all` (hard fail) or `~all` (soft fail).",
                        collector=self.name,
                    )
                )
            elif "~all" not in record and "-all" not in record:
                findings.append(
                    Finding(
                        title=f"SPF record on {apex} has no terminating all mechanism",
                        severity=Severity.LOW,
                        category="email-security",
                        node_ids=[domain_id],
                        evidence={"spf": record},
                        remediation="Append `-all` so unlisted senders fail.",
                        collector=self.name,
                    )
                )
            if len(spf) > 1:
                findings.append(
                    Finding(
                        title=f"Multiple SPF records on {apex}",
                        severity=Severity.MEDIUM,
                        category="email-security",
                        node_ids=[domain_id],
                        description="RFC 7208 requires exactly one; receivers will PermError.",
                        evidence={"records": spf},
                        remediation="Merge into a single v=spf1 TXT record.",
                        collector=self.name,
                    )
                )

        policy = ""
        for record in dmarc:
            if not record.lower().startswith("v=dmarc1"):
                continue
            for tag in record.split(";"):
                k, _, v = tag.strip().partition("=")
                if k.strip().lower() == "p":
                    policy = v.strip().lower()
        if not dmarc:
            findings.append(
                Finding(
                    title=f"No DMARC record on {apex}",
                    severity=Severity.MEDIUM if mx else Severity.LOW,
                    category="email-security",
                    node_ids=[domain_id],
                    description="Nothing tells receivers what to do with mail failing SPF/DKIM.",
                    remediation='Publish _dmarc TXT: "v=DMARC1; p=quarantine; rua=mailto:..."',
                    collector=self.name,
                )
            )
        elif policy in ("none", ""):
            findings.append(
                Finding(
                    title=f"DMARC policy on {apex} is p=none",
                    severity=Severity.LOW,
                    category="email-security",
                    node_ids=[domain_id],
                    description="Monitoring only - spoofed mail is still delivered.",
                    evidence={"dmarc": dmarc},
                    remediation="Move to p=quarantine, then p=reject once reports are clean.",
                    collector=self.name,
                )
            )
        return findings

    def _dns_hygiene_findings(
        self, apex: str, domain_id: str, answers: dict[str, list[str]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not answers["CAA"]:
            findings.append(
                Finding(
                    title=f"No CAA record on {apex}",
                    severity=Severity.LOW,
                    category="certificate-governance",
                    node_ids=[domain_id],
                    description="Any public CA may issue certificates for this domain.",
                    remediation='Publish CAA: 0 issue "yourca.example"',
                    collector=self.name,
                )
            )
        providers = {
            hint
            for ns in answers["NS"]
            for hint in DANGLING_HINTS
            if hint in ns.lower()
        }
        if len(providers) > 1:
            findings.append(
                Finding(
                    title=f"Nameservers for {apex} span multiple DNS providers",
                    severity=Severity.INFO,
                    category="dns-hygiene",
                    node_ids=[domain_id],
                    description="Split-provider delegation is a common source of stale zones.",
                    evidence={"providers": sorted(providers), "ns": answers["NS"]},
                    collector=self.name,
                )
            )
        return findings
