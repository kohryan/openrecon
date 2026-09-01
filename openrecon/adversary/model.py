"""The cost model: what an attacker must spend to use each weakness.

Every other attack surface tool ranks by CVSS - a measure of how bad a flaw is
*if* exploited. An attacker does not choose that way. They choose the cheapest
route to something they want, and a CVSS 5.3 with a public one-liner beats a
CVSS 9.8 that needs three weeks of research every time.

So openrecon prices weaknesses in attacker-hours, tags each with the capability
tier it demands and the noise it makes, and lets the pathfinder answer the
question a defender actually has: *how long would this take someone, and what is
the cheapest thing I can fix to make it take longer?*

These are modelled estimates, not measurements. The whole table is here, in the
open, and every number is overridable - a cost model you cannot inspect is
astrology. Defaults are calibrated against public incident reporting and
exploitation timelines; treat them as a shared starting point to argue with,
not as ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from openrecon.core.models import Finding, Node, NodeType


class Capability(IntEnum):
    """How skilled the attacker must be. Higher tiers are rarer adversaries."""

    OPPORTUNIST = 1
    """Runs a public script against whatever a search engine indexed."""
    COMMODITY = 2
    """Uses off-the-shelf tooling: Metasploit modules, exploit-db, leaked creds."""
    SKILLED = 3
    """Chains flaws, writes their own exploit for a known bug, phishes credibly."""
    ADVANCED = 4
    """Burns research effort or a private exploit; targeted, patient, funded."""

    @property
    def label(self) -> str:
        return self.name.lower()


class ObjectiveKind(StrEnum):
    """What the attacker is actually after. Impact is scoped to these."""

    DATA_ACCESS = "data-access"
    CODE_EXECUTION = "code-execution"
    CREDENTIAL_ACCESS = "credential-access"
    DOMAIN_CONTROL = "domain-control"
    IMPERSONATION = "impersonation"


# Business impact of reaching an objective, 0-100. Used to rank campaigns when
# two paths cost the same: stealing the database beats defacing a landing page.
OBJECTIVE_IMPACT: dict[ObjectiveKind, int] = {
    ObjectiveKind.DATA_ACCESS: 95,
    ObjectiveKind.CODE_EXECUTION: 90,
    ObjectiveKind.CREDENTIAL_ACCESS: 85,
    ObjectiveKind.DOMAIN_CONTROL: 80,
    ObjectiveKind.IMPERSONATION: 55,
}


@dataclass(frozen=True)
class Technique:
    """One move an attacker can make, and what it costs them."""

    id: str
    name: str
    hours: float
    """Attacker effort in hours. Wall-clock for a competent operator, not CPU time."""
    capability: Capability
    success: float
    """Probability the move works on the first serious attempt, 0-1."""
    noise: float
    """Probability a competent defender notices, 0-1. Low noise is worse for you."""
    mitre: str = ""
    """ATT&CK technique ID, so findings map onto detection coverage you already own."""
    grants: ObjectiveKind | None = None
    rationale: str = ""

    @property
    def effective_hours(self) -> float:
        """Expected cost including retries. A 50%-success move costs about double."""
        return self.hours / max(self.success, 0.05)


# --------------------------------------------------------------------- catalog

# Keyed by finding category, then by a discriminator drawn from the finding.
# Anything absent is simply not a route the model knows how to price, and the
# pathfinder will not invent one.
_CATALOG: dict[str, Technique] = {
    # --- things that are already open ---------------------------------------
    "exposed-service/datastore": Technique(
        id="exposed-service/datastore",
        name="Connect to an unauthenticated datastore",
        hours=0.25,
        capability=Capability.OPPORTUNIST,
        success=0.90,
        noise=0.15,
        mitre="T1190",
        grants=ObjectiveKind.DATA_ACCESS,
        rationale="Internet-facing database with no authentication: one client connection.",
    ),
    "exposed-service/admin": Technique(
        id="exposed-service/admin",
        name="Reach an exposed administrative interface",
        hours=2.0,
        capability=Capability.COMMODITY,
        success=0.45,
        noise=0.35,
        mitre="T1133",
        grants=ObjectiveKind.CREDENTIAL_ACCESS,
        rationale="Panel is reachable; access still needs default or stuffed credentials.",
    ),
    "exposed-service/generic": Technique(
        id="exposed-service/generic",
        name="Probe an exposed service",
        hours=6.0,
        capability=Capability.COMMODITY,
        success=0.25,
        noise=0.45,
        mitre="T1046",
        grants=None,
        rationale="Listening port with no known flaw: reconnaissance value only.",
    ),
    # --- secrets and credentials --------------------------------------------
    "secret-exposure/credential": Technique(
        id="secret-exposure/credential",
        name="Fetch leaked credential material from a public path",
        hours=0.1,
        capability=Capability.OPPORTUNIST,
        success=0.95,
        noise=0.10,
        mitre="T1552.001",
        grants=ObjectiveKind.CREDENTIAL_ACCESS,
        rationale="One HTTP GET returns live keys. The cheapest move on the board.",
    ),
    "secret-exposure/config": Technique(
        id="secret-exposure/config",
        name="Read an exposed configuration file",
        hours=0.5,
        capability=Capability.OPPORTUNIST,
        success=0.80,
        noise=0.10,
        mitre="T1552.001",
        grants=ObjectiveKind.DATA_ACCESS,
        rationale="Config discloses internal structure and often partial secrets.",
    ),
    "credential-exposure/breach": Technique(
        id="credential-exposure/breach",
        name="Credential-stuff accounts found in breach corpora",
        hours=3.0,
        capability=Capability.COMMODITY,
        success=0.35,
        noise=0.55,
        mitre="T1110.004",
        grants=ObjectiveKind.CREDENTIAL_ACCESS,
        rationale="Password reuse across a breached corpus; noisy but consistently effective.",
    ),
    # --- software flaws ------------------------------------------------------
    "known-vulnerability/kev": Technique(
        id="known-vulnerability/kev",
        name="Run a public exploit for an actively exploited CVE",
        hours=1.0,
        capability=Capability.COMMODITY,
        success=0.75,
        noise=0.40,
        mitre="T1190",
        grants=ObjectiveKind.CODE_EXECUTION,
        rationale="In CISA KEV: weaponised code exists and is already in use.",
    ),
    "known-vulnerability/weaponised": Technique(
        id="known-vulnerability/weaponised",
        name="Run an off-the-shelf exploit for a near-certainly-attacked CVE",
        hours=1.5,
        capability=Capability.COMMODITY,
        success=0.70,
        noise=0.40,
        mitre="T1190",
        grants=ObjectiveKind.CODE_EXECUTION,
        rationale=(
            "EPSS above 50%: exploitation in the next 30 days is close to certain, which "
            "means working code is already circulating whether or not CISA has listed it."
        ),
    ),
    "known-vulnerability/high-epss": Technique(
        id="known-vulnerability/high-epss",
        name="Adapt a published exploit for a widely-attacked CVE",
        hours=8.0,
        capability=Capability.SKILLED,
        success=0.50,
        noise=0.40,
        mitre="T1190",
        grants=ObjectiveKind.CODE_EXECUTION,
        rationale="High EPSS: exploitation is happening in the wild, tooling is emerging.",
    ),
    "known-vulnerability/theoretical": Technique(
        id="known-vulnerability/theoretical",
        name="Develop an exploit from a CVE advisory",
        hours=80.0,
        capability=Capability.ADVANCED,
        success=0.30,
        noise=0.25,
        mitre="T1190",
        grants=ObjectiveKind.CODE_EXECUTION,
        rationale="Disclosed but not weaponised: weeks of work for an uncertain result.",
    ),
    # --- name and trust ------------------------------------------------------
    "subdomain-takeover/dangling": Technique(
        id="subdomain-takeover/dangling",
        name="Claim an unclaimed platform resource behind a dangling CNAME",
        hours=1.5,
        capability=Capability.OPPORTUNIST,
        success=0.70,
        noise=0.05,
        mitre="T1584.001",
        grants=ObjectiveKind.DOMAIN_CONTROL,
        rationale="Register the released resource; the victim's DNS points traffic at you.",
    ),
    "domain-lifecycle/expired": Technique(
        id="domain-lifecycle/expired",
        name="Re-register the lapsed domain",
        hours=2.0,
        capability=Capability.OPPORTUNIST,
        success=0.60,
        noise=0.05,
        mitre="T1583.001",
        grants=ObjectiveKind.DOMAIN_CONTROL,
        rationale="Drop-catch services automate this; competition is the only obstacle.",
    ),
    "email-security/spoofable": Technique(
        id="email-security/spoofable",
        name="Phish using the organization's own domain",
        hours=4.0,
        capability=Capability.COMMODITY,
        success=0.30,
        noise=0.50,
        mitre="T1566.002",
        grants=ObjectiveKind.CREDENTIAL_ACCESS,
        rationale="No SPF/DMARC enforcement: mail from the real domain reaches inboxes.",
    ),
    "dns-exposure/zone-transfer": Technique(
        id="dns-exposure/zone-transfer",
        name="Transfer the zone to map internal naming",
        hours=0.2,
        capability=Capability.OPPORTUNIST,
        success=0.95,
        noise=0.20,
        mitre="T1590.002",
        grants=None,
        rationale="Full internal hostname inventory in a single query.",
    ),
    "threat-intelligence/compromised": Technique(
        id="threat-intelligence/compromised",
        name="Use infrastructure someone has already compromised",
        hours=0.5,
        capability=Capability.OPPORTUNIST,
        success=0.85,
        noise=0.30,
        mitre="T1584",
        grants=ObjectiveKind.CODE_EXECUTION,
        rationale="Threat feeds already show malicious content served here: someone is inside.",
    ),
    # --- pivots --------------------------------------------------------------
    "pivot/shared-host": Technique(
        id="pivot/shared-host",
        name="Pivot to a service on the same host",
        hours=1.0,
        capability=Capability.COMMODITY,
        success=0.70,
        noise=0.30,
        mitre="T1210",
        grants=None,
        rationale="Same machine: local access usually reaches every service on it.",
    ),
    "pivot/shared-credential": Technique(
        id="pivot/shared-credential",
        name="Reuse captured credentials against a sibling system",
        hours=2.0,
        capability=Capability.COMMODITY,
        success=0.45,
        noise=0.35,
        mitre="T1078",
        grants=None,
        rationale="Credentials from one system are routinely valid on its neighbours.",
    ),
}


class TechniqueCatalog:
    """Maps findings onto priced techniques. Costs are overridable per deployment."""

    def __init__(self, overrides: dict[str, dict[str, Any]] | None = None) -> None:
        self.techniques: dict[str, Technique] = dict(_CATALOG)
        for tid, patch in (overrides or {}).items():
            base = self.techniques.get(tid)
            if base is None:
                continue
            self.techniques[tid] = Technique(
                **{**base.__dict__, **{k: v for k, v in patch.items() if k in base.__dict__}}
            )

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def for_finding(self, finding: Finding, node: Node | None = None) -> Technique | None:
        """Price a finding. Returns None when the model knows no route from it.

        A finding without a technique is not harmless - it is simply not a step
        an attacker takes on its own. Missing security headers matter when
        something else already gave the attacker a foothold, which is exactly
        what the pathfinder is for.
        """
        return self.get(self._discriminate(finding, node))

    def _discriminate(self, finding: Finding, node: Node | None) -> str:
        category = finding.category

        if category == "known-vulnerability":
            epss = finding.epss or 0
            if finding.kev:
                return "known-vulnerability/kev"
            # KEV is a curated list and lags reality. An EPSS above 50% says the
            # same thing the catalogue would, weeks earlier.
            if epss >= 0.50:
                return "known-vulnerability/weaponised"
            if epss >= 0.10:
                return "known-vulnerability/high-epss"
            return "known-vulnerability/theoretical"

        if category == "exposed-service":
            tags = node.tags if node else set()
            if "unauthenticated-risk" in tags:
                return "exposed-service/datastore"
            service = str((node.attrs.get("service") if node else "") or "").lower()
            if any(k in service for k in ("kibana", "grafana", "rabbitmq", "kubernetes", "kubelet")):
                return "exposed-service/admin"
            if any(k in finding.title.lower() for k in ("rdp", "vnc", "telnet", "smb")):
                return "exposed-service/admin"
            return "exposed-service/generic"

        if category == "secret-exposure":
            # Handle both dict (legacy) and list (coerced) evidence formats
            ev = finding.evidence
            if isinstance(ev, dict):
                if ev.get("credential_types"):
                    return "secret-exposure/credential"
            elif isinstance(ev, list):
                for item in ev:
                    if item.get("type") == "credential_types":
                        return "secret-exposure/credential"
            return "secret-exposure/config"

        if category == "credential-exposure":
            return "credential-exposure/breach"

        if category == "subdomain-takeover":
            return "subdomain-takeover/dangling"

        if category == "domain-lifecycle":
            # Handle both dict (legacy) and list (coerced) evidence formats
            ev = finding.evidence
            days = None
            if isinstance(ev, dict):
                days = ev.get("days_remaining")
            elif isinstance(ev, list):
                for item in ev:
                    if item.get("type") == "days_remaining":
                        days = item.get("value")
                        break
            if isinstance(days, (int, float)) and days <= 0:
                return "domain-lifecycle/expired"
            return ""

        if category == "email-security":
            title = finding.title.lower()
            if "no spf" in title or "no dmarc" in title or "+all" in title:
                return "email-security/spoofable"
            return ""

        if category == "dns-exposure":
            return "dns-exposure/zone-transfer"

        if category == "threat-intelligence":
            return "threat-intelligence/compromised"

        return ""


@dataclass
class Objective:
    """Something worth reaching, and what reaching it would mean."""

    id: str
    kind: ObjectiveKind
    label: str
    node_id: str
    impact: int
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


def objectives_for(node: Node, findings: list[Finding]) -> list[Objective]:
    """Derive what an attacker would want from this asset."""
    found: list[Objective] = []

    def add(kind: ObjectiveKind, label: str, detail: str) -> None:
        found.append(
            Objective(
                id=f"{kind.value}:{node.id}",
                kind=kind,
                label=label,
                node_id=node.id,
                impact=OBJECTIVE_IMPACT[kind],
                detail=detail,
            )
        )

    if node.type is NodeType.SECRET:
        if node.attrs.get("credential_types"):
            add(ObjectiveKind.CREDENTIAL_ACCESS, f"credentials in {node.label}",
                "Live credential material is served over the public internet.")
        else:
            add(ObjectiveKind.DATA_ACCESS, f"configuration at {node.label}",
                "Internal configuration is readable by anyone.")

    if node.type is NodeType.CREDENTIAL_LEAK:
        add(ObjectiveKind.CREDENTIAL_ACCESS, node.label,
            "Corporate accounts appear in public breach corpora.")

    if node.type is NodeType.SERVICE and "unauthenticated-risk" in node.tags:
        add(ObjectiveKind.DATA_ACCESS, f"data in {node.label}",
            "A datastore is answering on the public internet.")

    if node.type is NodeType.VULNERABILITY and (
        node.attrs.get("kev")
        or (node.attrs.get("cvss") or 0) >= 9
        or (node.attrs.get("epss") or 0) >= 0.5
    ):
        add(ObjectiveKind.CODE_EXECUTION, f"execution via {node.label}",
            "The flaw yields code execution or an authorization bypass on the affected host.")

    if "takeover" in node.tags:
        add(ObjectiveKind.DOMAIN_CONTROL, f"control of {node.label}",
            "The hostname can be claimed by a third party.")

    if node.type is NodeType.THREAT:
        add(ObjectiveKind.CODE_EXECUTION, f"foothold on {node.label}",
            "Threat intelligence indicates this asset is already serving attacker content.")

    for finding in findings:
        if finding.category == "email-security" and "dmarc" in finding.title.lower():
            add(ObjectiveKind.IMPERSONATION, f"trusted mail from {node.label}",
                "Mail claiming to come from this domain is delivered unchallenged.")
            break

    return found
