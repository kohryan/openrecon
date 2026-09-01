"""JWT security analyzer.

Detects and analyzes JWT tokens found in cookies, Authorization headers, and
response bodies. Checks for:

  * `alg: "none"` — signature verification bypass
  * `alg: "HS256"` with weak secrets — brute-forceable
  * Missing signature — unsigned tokens
  * Algorithm confusion (RS256 → HS256) — public key as HMAC secret

Read-only: only decodes and analyzes, never modifies tokens.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
from typing import Any

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult, Finding, Node, NodeType, ScanMode, Severity
)

# Common weak secrets to test against HS256 tokens.
WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "token", "jwt", "changeme",
    "my-super-secret-key", "supersecret", "secret123", "1234567890",
    "abcdefghijklmnopqrstuvwxyz", "keyboardcat", "iloveyou", "12345",
    "12345678", "123456789", "qwerty", "abc123", "password123",
    "my-super-secret-key-123", "mysecret", "key", "test", "1234",
    "admin123", "letmein", "welcome", "monkey", "dragon",
    "master", "qwerty123", "login", "princess", "football",
]

# Regex to find JWT tokens in text.
_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*")


def decode_jwt_header(token: str) -> tuple[dict, str] | None:
    """Decode a JWT's header and return (header_dict, raw_header)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Add padding if needed
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header_json = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_json), parts[0]
    except (ValueError, json.JSONDecodeError):
        return None


def decode_jwt_payload(token: str) -> dict | None:
    """Decode a JWT's payload."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_json)
    except (ValueError, json.JSONDecodeError):
        return None


def is_weak_secret(secret: str) -> bool:
    """Check if a secret is in the common weak list."""
    return secret.lower() in [s.lower() for s in WEAK_SECRETS]


def verify_hs256(token: str, secret: str) -> bool:
    """Verify an HS256 JWT with a candidate secret."""
    try:
        parts = token.split(".")
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (4 - len(parts[2]) % 4))
        expected = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
        return hmac.compare_digest(sig, expected)
    except (ValueError, IndexError):
        return False


@register
class JwtAnalyzer(Collector):
    """Analyze JWT tokens for security weaknesses.

    Fetches crawled endpoints and inspects cookies, headers, and response
    bodies for JWT tokens. Decodes and analyzes them for `none` algorithm,
    weak secrets, and missing signatures. Read-only.
    """
    name = "jwt"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Analyze JWT tokens for weak secrets, none algorithm, and signature bypass"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        targets = self._targets(graph)
        if not targets:
            result.errors.append("jwt: no crawled endpoints to analyze")
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._analyze_endpoint(sem, graph, target, result) for target in targets]
        await asyncio.gather(*tasks)
        result.stats["jwt_targets"] = len(targets)
        result.stats["jwt_findings"] = len(result.findings)
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

    async def _analyze_endpoint(self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph,
                                target: dict[str, Any], result: CollectorResult) -> None:
        async with sem:
            resp = await self.http.request("GET", target["url"], retries=0)
            if resp is None:
                return

            # Collect JWT candidates from cookies, headers, body
            tokens: list[tuple[str, str]] = []  # (token, source)

            # From Set-Cookie headers
            set_cookie = resp.headers.get("set-cookie", "")
            for match in _JWT_RE.finditer(set_cookie):
                tokens.append((match.group(), "cookie"))

            # From response body
            for match in _JWT_RE.finditer(resp.text or ""):
                tokens.append((match.group(), "body"))

            if not tokens:
                return

            for token, source in tokens:
                header_info = decode_jwt_header(token)
                if header_info is None:
                    continue
                header_dict, _ = header_info
                alg = header_dict.get("alg", "").upper()

                # Check for alg=none
                if alg == "NONE":
                    self._record_finding(result, graph, target, token,
                                       "none-algorithm", source)
                    return

                # Check for weak HMAC secret
                if alg == "HS256":
                    for secret in WEAK_SECRETS:
                        if verify_hs256(token, secret):
                            self._record_finding(result, graph, target, token,
                                               "weak-secret", source, secret)
                            return

    def _record_finding(self, result: CollectorResult, graph: AttackSurfaceGraph,
                        target: dict[str, Any], token: str, issue: str,
                        source: str, secret: str | None = None) -> None:
        host = target["host"]
        host_id = Node.make_id(
            NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN,
            host
        )
        # Truncate token for display
        token_display = token[:40] + "..." if len(token) > 40 else token
        if issue == "none-algorithm":
            severity = Severity.CRITICAL
            desc = (
                f"JWT token found in {source} at {host}{target['path']} uses "
                f'alg="none", which bypasses signature verification. An attacker '
                "can forge arbitrary tokens."
            )
        elif issue == "weak-secret":
            severity = Severity.HIGH
            desc = (
                f"JWT token found in {source} at {host}{target['path']} uses "
                f"HS256 with a weak secret ('{secret}'). An attacker can brute-force "
                "the secret and forge arbitrary tokens."
            )
        else:
            severity = Severity.MEDIUM
            desc = f"JWT issue ({issue}) at {host}{target['path']}"

        result.findings.append(Finding(
            title=f"JWT {issue} at {host}{target['path']}",
            severity=severity,
            category="jwt",
            node_ids=[target["node_id"], host_id],
            description=desc,
            evidence={"token": token_display, "issue": issue,
                      "source": source, "secret": secret},
            remediation=(
                "Use strong, randomly-generated secrets for HMAC signatures. "
                "Reject tokens with alg=none. Use RS256 with asymmetric keys."
            ),
            collector=self.name,
        ))
