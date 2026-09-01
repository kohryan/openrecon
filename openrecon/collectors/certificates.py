"""TLS certificate intelligence.

`certs_ct` (passive) reconstructs the certificate inventory from CT log data.
`tls` (active) performs a real handshake to see what is actually served today -
which is the only way to catch expired-but-still-deployed certificates.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from openrecon.collectors._ct import fetch_ct
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

WEAK_SIGNATURES = ("md5", "sha1")

# Key strength is only comparable within a key type: 2048-bit RSA and 256-bit
# P-256 are roughly equivalent. Comparing an EC key against an RSA threshold
# flags every modern certificate as weak.
MIN_BITS = {"rsa": 2048, "dsa": 2048, "ec": 224}


def _key_profile(public_key: Any) -> tuple[str, int | None, bool]:
    """(algorithm, size in bits, is_weak)."""
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return ("ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "ed448"), None, False
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        bits = public_key.curve.key_size
        return f"ec/{public_key.curve.name}", bits, bits < MIN_BITS["ec"]
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size, public_key.key_size < MIN_BITS["rsa"]
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsa", public_key.key_size, public_key.key_size < MIN_BITS["dsa"]
    return "unknown", getattr(public_key, "key_size", None), False
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    for parse in (datetime.fromisoformat,):
        try:
            dt = parse(text)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


@register
class TlsHandshakeCollector(Collector):
    name = "tls"
    stage = "certificates"
    mode = ScanMode.ACTIVE
    description = "Live TLS handshake: served certificate, protocol version, and expiry"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if n.attrs.get("resolves") is not False
        ]
        hosts = self.targets_in_scope(hosts)[: self.config.max_subdomains]
        if not hosts:
            return result

        sem = asyncio.Semaphore(min(self.config.concurrency, 30))

        async def handshake(host: str) -> tuple[str, dict[str, Any] | None]:
            async with sem:
                return host, await self._probe(host)

        for host, info in await asyncio.gather(*(handshake(h) for h in hosts)):
            if not info:
                continue
            result.extend(self._to_result(graph, host, info))
        return result

    async def _probe(self, host: str, port: int = 443) -> dict[str, Any] | None:
        loop = asyncio.get_running_loop()

        def connect() -> dict[str, Any] | None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                with (
                    socket.create_connection((host, port), timeout=self.config.timeout) as sock,
                    context.wrap_socket(sock, server_hostname=host) as tls,
                ):
                    return {
                        "der": tls.getpeercert(binary_form=True),
                        "protocol": tls.version(),
                        "cipher": tls.cipher(),
                    }
            except (TimeoutError, OSError, ssl.SSLError):
                return None

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, connect), timeout=self.config.timeout * 2
            )
        except TimeoutError:
            return None

    def _to_result(
        self, graph: AttackSurfaceGraph, host: str, info: dict[str, Any]
    ) -> CollectorResult:
        out = CollectorResult()
        der = info.get("der")
        if not der:
            return out
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            return out

        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        sig_alg = (cert.signature_algorithm_oid._name or "").lower()
        try:
            sans = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        key_algorithm, key_bits, key_is_weak = _key_profile(cert.public_key())
        node_type = NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN
        host_id = Node.make_id(node_type, host)
        prov = self.prov(f"tls://{host}:443")

        cert_node = Node.create(
            NodeType.CERTIFICATE,
            fingerprint,
            label=subject.split(",")[0].replace("CN=", "") or fingerprint[:16],
            attrs={
                "fingerprint_sha256": fingerprint,
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "san": sans,
                "signature_algorithm": sig_alg,
                "self_signed": subject == issuer,
                "protocol": info.get("protocol"),
                "cipher": (info.get("cipher") or [None])[0],
                "key_algorithm": key_algorithm,
                "key_size": key_bits,
                "served_on": [host],
            },
            provenance=prov,
        )
        out.nodes.append(cert_node)
        out.edges.append(
            Edge(source=host_id, target=cert_node.id, type=EdgeType.SECURED_BY, provenance=[prov])
        )

        now = datetime.now(UTC)
        days_left = (not_after - now).days
        if not_after < now:
            out.findings.append(
                Finding(
                    title=f"Expired TLS certificate served on {host}",
                    severity=Severity.HIGH,
                    category="tls",
                    node_ids=[host_id, cert_node.id],
                    description=f"The certificate expired {abs(days_left)} days ago; browsers "
                    "hard-fail and users are trained to click through warnings.",
                    evidence={"not_after": not_after.isoformat(), "issuer": issuer},
                    remediation="Renew and deploy the certificate; automate with ACME.",
                    collector=self.name,
                )
            )
        elif days_left <= 14:
            out.findings.append(
                Finding(
                    title=f"TLS certificate on {host} expires in {days_left} days",
                    severity=Severity.MEDIUM,
                    category="tls",
                    node_ids=[host_id, cert_node.id],
                    evidence={"not_after": not_after.isoformat()},
                    remediation="Renew now; verify automated renewal is actually running.",
                    collector=self.name,
                )
            )

        if subject == issuer:
            out.findings.append(
                Finding(
                    title=f"Self-signed certificate on {host}",
                    severity=Severity.MEDIUM,
                    category="tls",
                    node_ids=[host_id, cert_node.id],
                    description="Clients cannot distinguish this from an interception attack.",
                    evidence={"subject": subject},
                    remediation="Issue a publicly trusted certificate, or remove the host from the internet.",
                    collector=self.name,
                )
            )

        if any(weak in sig_alg for weak in WEAK_SIGNATURES):
            out.findings.append(
                Finding(
                    title=f"Weak certificate signature algorithm on {host} ({sig_alg})",
                    severity=Severity.HIGH,
                    category="tls",
                    node_ids=[host_id, cert_node.id],
                    evidence={"signature_algorithm": sig_alg},
                    remediation="Reissue with SHA-256 or stronger.",
                    collector=self.name,
                )
            )

        protocol = info.get("protocol")
        if protocol in DEPRECATED_PROTOCOLS:
            out.findings.append(
                Finding(
                    title=f"Deprecated TLS protocol negotiated on {host} ({protocol})",
                    severity=Severity.MEDIUM,
                    category="tls",
                    node_ids=[host_id],
                    description="TLS 1.0/1.1 are deprecated (RFC 8996) and fail modern compliance baselines.",
                    evidence={"protocol": protocol, "cipher": info.get("cipher")},
                    remediation="Disable everything below TLS 1.2; prefer TLS 1.3.",
                    collector=self.name,
                )
            )

        if key_is_weak:
            out.findings.append(
                Finding(
                    title=f"Weak public key on {host} ({key_algorithm}, {key_bits} bits)",
                    severity=Severity.HIGH,
                    category="tls",
                    node_ids=[host_id, cert_node.id],
                    description=(
                        f"A {key_bits}-bit {key_algorithm.split('/')[0].upper()} key is below the "
                        "modern minimum and is within reach of a well-resourced attacker."
                    ),
                    evidence={"key_algorithm": key_algorithm, "key_size": key_bits},
                    remediation="Reissue with a >=2048-bit RSA key or a P-256 (or stronger) EC key.",
                    collector=self.name,
                )
            )
        return out


@register
class CtCertificateCollector(Collector):
    name = "certs_ct"
    stage = "certificates"
    mode = ScanMode.PASSIVE
    description = "Certificate inventory reconstructed from certificate transparency logs"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        records, errors = await fetch_ct(self.http, apex, token=self.config.key("certspotter"))
        result.errors.extend(errors)
        if not records:
            return result

        now = datetime.now(UTC)
        prov = self.prov("certificate-transparency")
        wildcard_certs = 0
        expired_certs = 0

        for record in records[:1500]:
            not_after = _parse_dt(record["not_after"])
            not_before = _parse_dt(record["not_before"])
            names = record["names"]
            if any(n.startswith("*.") for n in names):
                wildcard_certs += 1
            is_expired = bool(not_after and not_after < now)
            if is_expired:
                expired_certs += 1

            cert_node = Node.create(
                NodeType.CERTIFICATE,
                record["serial"] or f"{record['common_name']}|{record['not_after']}",
                label=record["common_name"] or (record["serial"] or "")[:16],
                attrs={
                    "serial": record["serial"],
                    "issuer": record["issuer"],
                    "common_name": record["common_name"],
                    "san": names[:50],
                    "not_before": not_before.isoformat() if not_before else None,
                    "not_after": not_after.isoformat() if not_after else None,
                    "expired": is_expired,
                    "source": record["source"],
                },
                provenance=prov,
                tags={"expired"} if is_expired else set(),
            )
            result.nodes.append(cert_node)

            for name in names:
                if name.startswith("*.") or not name.endswith(apex):
                    continue
                host_type = NodeType.DOMAIN if name == apex else NodeType.SUBDOMAIN
                host_id = Node.make_id(host_type, name)
                if host_id in graph.nodes:
                    result.edges.append(
                        Edge(
                            source=host_id,
                            target=cert_node.id,
                            type=EdgeType.SECURED_BY,
                            provenance=[prov],
                        )
                    )

        if wildcard_certs:
            result.findings.append(
                Finding(
                    title=f"{wildcard_certs} wildcard certificate(s) issued for {apex}",
                    severity=Severity.LOW,
                    category="certificate-governance",
                    node_ids=[Node.make_id(NodeType.DOMAIN, apex)],
                    description=(
                        "A leaked wildcard key impersonates every host under the domain, and "
                        "wildcards hide which hostnames actually exist."
                    ),
                    evidence={"wildcard_certificates": wildcard_certs},
                    remediation="Prefer per-host certificates with short lifetimes and automated renewal.",
                    collector=self.name,
                )
            )
        result.stats["ct_certificates_indexed"] = len(records)
        result.stats["ct_certificates_expired"] = expired_certs
        return result
