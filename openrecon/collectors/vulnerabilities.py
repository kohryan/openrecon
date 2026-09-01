"""Vulnerability correlation.

Takes the technologies the fingerprint stage identified and asks three public
sources what is known about them:
  * NVD  - the CVE record and CVSS score
  * EPSS - the probability the CVE is exploited in the wild in the next 30 days
  * KEV  - CISA's catalog of vulnerabilities known to be actively exploited

EPSS and KEV are what turn "12 known vulnerabilities" into a ranked worklist.
"""

from __future__ import annotations

import asyncio
import re
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

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/query"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

VERSION_PART_RE = re.compile(r"\d+|[a-z]+")

# Products where a bare keyword search returns mostly noise.
SKIP_PRODUCTS = {"unknown", "cloudflare", "http", "https", "server", "apache-coyote"}

# GHSA publishes a severity label rather than a score. These are the midpoints of
# each CVSS band - good enough to rank, and never presented as a measured score.
GHSA_NOMINAL_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}


def _version_key(version: str) -> tuple:
    parts = VERSION_PART_RE.findall(version.lower())
    return tuple(int(p) if p.isdigit() else -1 for p in parts)


def _version_lt(a: str, b: str) -> bool:
    return _version_key(a) < _version_key(b)


def _version_le(a: str, b: str) -> bool:
    return _version_key(a) <= _version_key(b)


def _cpe_matches(node: dict[str, Any], product: str, version: str) -> bool:
    criteria = (node.get("criteria") or "").lower()
    fields = criteria.split(":")
    if len(fields) < 6 or product not in fields[4]:
        return False
    cpe_version = fields[5]
    if cpe_version not in ("*", "-"):
        return cpe_version == version.lower()
    if not version:
        return True
    start_incl = node.get("versionStartIncluding")
    start_excl = node.get("versionStartExcluding")
    end_incl = node.get("versionEndIncluding")
    end_excl = node.get("versionEndExcluding")
    if start_incl and _version_lt(version, start_incl):
        return False
    if start_excl and _version_le(version, start_excl):
        return False
    if end_incl and _version_lt(end_incl, version):
        return False
    if end_excl and _version_le(end_excl, version):
        return False
    return any([start_incl, start_excl, end_incl, end_excl])


def _cvss_of(metrics: dict[str, Any]) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString", "")
    return None, ""


@register
class VulnerabilityCollector(Collector):
    name = "vulns"
    stage = "vulnerabilities"
    mode = ScanMode.PASSIVE
    description = "Correlate detected software versions with NVD CVEs, EPSS scores, and CISA KEV"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        kev = await self._kev_catalog()

        # Two correlation paths. Package-ecosystem components (npm, PyPI) go to
        # OSV, which indexes them precisely; everything else goes to NVD, whose
        # CPE model is the only thing that covers servers and appliances but is
        # close to useless for a JavaScript dependency.
        technologies = [
            n
            for n in graph.nodes_of(NodeType.TECHNOLOGY)
            if n.attrs.get("product") not in SKIP_PRODUCTS and n.attrs.get("version")
        ]
        packages = [n for n in technologies if n.attrs.get("ecosystem")]
        technologies = [n for n in technologies if not n.attrs.get("ecosystem")]
        # Anything Shodan already attributed to a service is free signal.
        direct_cves: dict[str, list[str]] = {}
        for svc in graph.nodes_of(NodeType.SERVICE):
            for cve in svc.attrs.get("shodan_cves") or []:
                direct_cves.setdefault(str(cve).upper(), []).append(svc.id)

        matches: dict[str, dict[str, Any]] = {}
        # NVD's unauthenticated rate limit is 5 requests / 30s - stay well under it.
        gate = asyncio.Semaphore(1 if not self.config.key("nvd") else 4)

        async def lookup(tech: Node) -> None:
            product = str(tech.attrs["product"])
            version = str(tech.attrs["version"])
            async with gate:
                cves = await self._nvd_search(product, version)
                if not self.config.key("nvd"):
                    await asyncio.sleep(6.5)
            for cve_id, payload in cves.items():
                entry = matches.setdefault(cve_id, {**payload, "node_ids": []})
                entry["node_ids"].append(tech.id)

        async def lookup_package(node: Node) -> None:
            entries = await self._osv_search(
                str(node.attrs["product"]),
                str(node.attrs["version"]),
                str(node.attrs["ecosystem"]),
            )
            for cve_id, payload in entries.items():
                entry = matches.setdefault(cve_id, {**payload, "node_ids": []})
                entry["node_ids"].append(node.id)

        await asyncio.gather(
            *(lookup(t) for t in technologies[:40]),
            *(lookup_package(p) for p in packages[:60]),
        )

        for cve_id, node_ids in direct_cves.items():
            entry = matches.setdefault(
                cve_id, {"id": cve_id, "description": "", "cvss": None, "vector": "", "node_ids": []}
            )
            entry["node_ids"].extend(node_ids)

        epss = await self._epss_scores(list(matches))
        prov = self.prov("nvd+epss+kev")

        for cve_id, payload in matches.items():
            score = payload.get("cvss")
            severity = Severity.from_cvss(score)
            is_kev = cve_id in kev
            epss_score = epss.get(cve_id)
            if is_kev:
                severity = Severity.CRITICAL

            vuln = Node.create(
                NodeType.VULNERABILITY,
                cve_id,
                label=cve_id,
                attrs={
                    "cve": cve_id,
                    "cvss": score,
                    "vector": payload.get("vector"),
                    "epss": epss_score,
                    "kev": is_kev,
                    "kev_due_date": kev.get(cve_id, {}).get("dueDate"),
                    "description": (payload.get("description") or "")[:600],
                },
                provenance=prov,
                tags={"kev"} if is_kev else set(),
            )
            result.nodes.append(vuln)
            for node_id in set(payload["node_ids"]):
                result.edges.append(
                    Edge(
                        source=node_id,
                        target=vuln.id,
                        type=EdgeType.VULNERABLE_TO,
                        provenance=[prov],
                    )
                )

            affected = ", ".join(
                sorted({graph.nodes[n].label for n in set(payload["node_ids"]) if n in graph.nodes})
            )
            result.findings.append(
                Finding(
                    title=f"{cve_id} affects {affected or 'discovered software'}",
                    severity=severity,
                    category="known-vulnerability",
                    type="vulnerability",
                    node_ids=[vuln.id, *set(payload["node_ids"])],
                    description=(payload.get("description") or "")[:800],
                    evidence=[
                        {"type": "cve_id", "value": cve_id},
                        {"type": "cvss_score", "value": score},
                        {"type": "vector", "value": payload.get("vector")},
                        {"type": "epss_score", "value": epss_score},
                        {"type": "kev", "value": is_kev},
                        {"type": "source", "value": payload.get("source", "nvd")},
                    ],
                    remediation=(
                        "Patch to a fixed release. This CVE is in CISA's Known Exploited "
                        "Vulnerabilities catalog - treat it as an active incident risk."
                        if is_kev
                        else "Upgrade the affected component to a patched version."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                    cve=cve_id,
                    cvss=score,
                    epss=epss_score,
                    kev=is_kev,
                    vendor=payload.get("vendor", ""),
                    product=payload.get("product", ""),
                    detected_version=payload.get("detected_version", ""),
                    affected_versions=payload.get("affected_versions", ""),
                    fixed_version=payload.get("fixed_version", ""),
                    collector=self.name,
                    confidence=0.95 if payload.get("source") == "osv" else 0.85,
                    detection_method="CPE_match" if payload.get("source") != "osv" else "OSV_version_range",
                    source=payload.get("source", "nvd"),
                )
            )

        result.stats["cves_matched"] = len(matches)
        result.stats["kev_hits"] = sum(1 for c in matches if c in kev)
        return result

    # ----------------------------------------------------------------- sources

    async def _kev_catalog(self) -> dict[str, dict[str, Any]]:
        data = await self.http.get_json(KEV_FEED)
        if not data:
            return {}
        return {str(v.get("cveID", "")).upper(): v for v in data.get("vulnerabilities", [])}

    async def _nvd_search(self, product: str, version: str) -> dict[str, dict[str, Any]]:
        headers = {}
        api_key = self.config.key("nvd")
        if api_key:
            headers["apiKey"] = api_key
        data = await self.http.get_json(
            NVD_API,
            params={"keywordSearch": product, "resultsPerPage": 200},
            headers=headers or None,
            retries=1,
        )
        out: dict[str, dict[str, Any]] = {}
        for item in (data or {}).get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = str(cve.get("id", "")).upper()
            if not cve_id:
                continue
            if not self._configuration_matches(cve, product, version):
                continue
            score, vector = _cvss_of(cve.get("metrics", {}))
            description = next(
                (
                    d.get("value", "")
                    for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                "",
            )
            out[cve_id] = {
                "id": cve_id,
                "cvss": score,
                "vector": vector,
                "description": description,
            }
        return out

    def _configuration_matches(self, cve: dict[str, Any], product: str, version: str) -> bool:
        for config in cve.get("configurations", []) or []:
            for node in config.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    if match.get("vulnerable") and _cpe_matches(match, product, version):
                        return True
        return False

    async def _osv_search(
        self, package: str, version: str, ecosystem: str
    ) -> dict[str, dict[str, Any]]:
        """Ask OSV what is known about this exact package version.

        OSV resolves version ranges itself, so an answer here is a real match
        rather than the keyword guess NVD's CPE search forces on us.
        """
        response = await self.http.request(
            "POST",
            OSV_API,
            json={"version": version, "package": {"name": package, "ecosystem": ecosystem}},
            retries=1,
        )
        if response is None or response.status_code >= 400:
            return {}
        try:
            body = response.json()
        except ValueError:
            return {}

        out: dict[str, dict[str, Any]] = {}
        for vuln in body.get("vulns", [])[:50]:
            aliases = [a for a in (vuln.get("aliases") or []) if str(a).upper().startswith("CVE-")]
            identifier = (aliases[0] if aliases else vuln.get("id", "")).upper()
            if not identifier:
                continue
            label = str(
                (vuln.get("database_specific") or {}).get("severity", "")
            ).upper()
            out[identifier] = {
                "id": identifier,
                "cvss": GHSA_NOMINAL_CVSS.get(label),
                "vector": next(
                    (s.get("score") for s in (vuln.get("severity") or []) if s.get("score")), ""
                ),
                "description": (vuln.get("summary") or vuln.get("details") or "")[:600],
                "source": "osv",
                "advisory": vuln.get("id", ""),
                "package": f"{ecosystem}:{package}@{version}",
            }
        return out

    async def _epss_scores(self, cves: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for i in range(0, len(cves), 100):
            batch = cves[i : i + 100]
            data = await self.http.get_json(EPSS_API, params={"cve": ",".join(batch)})
            for row in (data or {}).get("data", []):
                try:
                    scores[str(row["cve"]).upper()] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        return scores
