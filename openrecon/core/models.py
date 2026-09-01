"""Domain model for the attack surface graph.

Everything openrecon discovers becomes a `Node`, everything it infers becomes an
`Edge`, and everything it judges becomes a `Finding`. Collectors only ever speak
in these three types, which is what keeps the pipeline pluggable.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScanMode(StrEnum):
    """How aggressively a collector is allowed to behave.

    PASSIVE never sends a packet to the target: it only reads third-party
    sources (CT logs, RDAP, public resolvers, threat feeds). ACTIVE talks
    directly to target-owned infrastructure and therefore requires an explicit
    authorization scope. See `openrecon.scope`.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class NodeType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    NETBLOCK = "netblock"
    ASN = "asn"
    CERTIFICATE = "certificate"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    CREDENTIAL_LEAK = "credential_leak"
    API = "api"
    ORGANIZATION = "organization"
    NAMESERVER = "nameserver"
    MAILSERVER = "mailserver"
    CLOUD_RESOURCE = "cloud_resource"
    THREAT = "threat"


class EdgeType(StrEnum):
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    CNAME_TO = "cname_to"
    DELEGATES_TO = "delegates_to"
    MAIL_VIA = "mail_via"
    SECURED_BY = "secured_by"
    COVERS = "covers"
    IN_NETBLOCK = "in_netblock"
    ANNOUNCED_BY = "announced_by"
    EXPOSES = "exposes"
    RUNS = "runs"
    VULNERABLE_TO = "vulnerable_to"
    LEAKS = "leaks"
    REGISTERED_BY = "registered_by"
    FLAGGED_AS = "flagged_as"
    RELATED_TO = "related_to"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 10.0,
}

SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Provenance(BaseModel):
    """Where a claim came from. Every node/edge/finding carries at least one."""

    collector: str
    source: str = ""
    observed_at: datetime = Field(default_factory=utcnow)
    confidence: float = 1.0

    def key(self) -> str:
        return f"{self.collector}|{self.source}"


class Node(BaseModel):
    """A single asset in the attack surface."""

    id: str
    type: NodeType
    label: str
    attrs: dict[str, Any] = Field(default_factory=dict)
    provenance: list[Provenance] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    # Filled in by the risk engine.
    risk_score: float = 0.0
    risk_severity: Severity = Severity.INFO
    tags: set[str] = Field(default_factory=set)

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, v: Any) -> Any:
        return set(v) if isinstance(v, (list, tuple)) else v

    @staticmethod
    def make_id(node_type: NodeType, key: str) -> str:
        return f"{node_type.value}:{key.lower().strip()}"

    @classmethod
    def create(
        cls,
        node_type: NodeType,
        key: str,
        *,
        label: str | None = None,
        attrs: dict[str, Any] | None = None,
        provenance: Provenance | None = None,
        tags: set[str] | None = None,
    ) -> Node:
        return cls(
            id=cls.make_id(node_type, key),
            type=node_type,
            label=label or key,
            attrs=attrs or {},
            provenance=[provenance] if provenance else [],
            tags=tags or set(),
        )

    def merge(self, other: Node) -> None:
        """Fold another observation of the same asset into this node."""
        for k, v in other.attrs.items():
            if v in (None, "", [], {}):
                continue
            existing = self.attrs.get(k)
            if existing is None:
                self.attrs[k] = v
            elif isinstance(existing, list) and isinstance(v, list):
                merged = list(existing)
                for item in v:
                    if item not in merged:
                        merged.append(item)
                self.attrs[k] = merged
        seen = {p.key() for p in self.provenance}
        for p in other.provenance:
            if p.key() not in seen:
                self.provenance.append(p)
                seen.add(p.key())
        self.tags |= other.tags
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)

    @property
    def sources(self) -> list[str]:
        return sorted({p.collector for p in self.provenance})


class Edge(BaseModel):
    source: str
    target: str
    type: EdgeType
    attrs: dict[str, Any] = Field(default_factory=dict)
    provenance: list[Provenance] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.source}->{self.type.value}->{self.target}"


class Finding(BaseModel):
    """A judgement about one or more nodes: the unit the risk engine scores."""

    id: str = ""
    title: str
    severity: Severity
    category: str
    type: str = "finding"  # finding | vulnerability | exposure | misconfiguration
    status: str = "open"  # open | resolved | suppressed
    node_ids: list[str] = Field(default_factory=list)
    description: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)  # structured evidence
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    # Vulnerability intelligence, when the finding maps to a known CVE.
    cve: str | None = None
    cwe: str | None = None
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    vendor: str = ""
    product: str = ""
    detected_version: str = ""
    affected_versions: str = ""
    fixed_version: str = ""
    collector: str = ""
    detected_at: datetime = Field(default_factory=utcnow)
    # Filled in by the risk engine.
    risk_score: float = 0.0
    confidence: float = 1.0
    detection_method: str = ""
    source: str = ""
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    # Asset attribution: whether this finding is confirmed to belong to the
    # target organization's infrastructure or to shared/edge infrastructure.
    asset_attribution: dict[str, Any] = Field(default_factory=dict)
    # Key: status (confirmed | probable | unconfirmed | shared-edge)
    # Value: {"status": str, "provider": str|null, "evidence": str, "notes": str}

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: Any) -> Any:
        """Normalize dict evidence to list format for backward compatibility."""
        if isinstance(v, dict):
            return [
                {"type": k, "value": val}
                for k, val in v.items()
                if val is not None
            ]
        return v

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            seed = f"{self.category}|{self.title}|{'|'.join(sorted(self.node_ids))}"
            self.id = hashlib.sha1(seed.encode()).hexdigest()[:16]


class CollectorResult(BaseModel):
    """What a collector hands back to the pipeline."""

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)

    def extend(self, other: CollectorResult) -> None:
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        self.stats.update(other.stats)


class ExposureSummary(BaseModel):
    """The numbers on the DIGITAL EXPOSURE panel."""

    domains: int = 0
    subdomains: int = 0
    exposed_services: int = 0
    leaked_credentials: int = 0
    known_vulnerabilities: int = 0
    suspicious_assets: int = 0
    expired_certificates: int = 0
    secrets_detected: int = 0
    ip_addresses: int = 0
    asns: int = 0
    technologies: int = 0

    def rows(self) -> list[tuple[str, int]]:
        return [
            ("Domains", self.domains),
            ("Subdomains", self.subdomains),
            ("IP addresses", self.ip_addresses),
            ("Exposed services", self.exposed_services),
            ("Leaked credentials", self.leaked_credentials),
            ("Known vulnerabilities", self.known_vulnerabilities),
            ("Suspicious assets", self.suspicious_assets),
            ("Expired certificates", self.expired_certificates),
            ("Secrets detected", self.secrets_detected),
        ]
