"""Shared certificate transparency fetch.

crt.sh is the richest CT source and also the least reliable - it returns 502 for
long stretches. Cert Spotter is the fallback. Both are queried once per scan and
normalized into the same record shape, so the subdomain collector and the
certificate collector read from one result instead of hitting the APIs twice.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, TypedDict

from openrecon.core.net import HttpClient

CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"

HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9_]([a-z0-9\-_]*[a-z0-9])?)*$")


class CtRecord(TypedDict):
    serial: str
    issuer: str | None
    common_name: str | None
    names: list[str]
    not_before: str | None
    not_after: str | None
    source: str


def valid_host(name: str, apex: str) -> bool:
    name = name.lower().strip().rstrip(".")
    if not name or name.startswith("*."):
        return False
    if not (name == apex or name.endswith(f".{apex}")):
        return False
    return bool(HOSTNAME_RE.match(name))


async def fetch_ct(
    http: HttpClient, apex: str, *, token: str | None = None
) -> tuple[list[CtRecord], list[str]]:
    """Return (records, errors), fetched once per scan. Never raises."""
    return await http.memoize(f"ct:{apex}", lambda: _fetch_ct(http, apex, token))


async def _fetch_ct(
    http: HttpClient, apex: str, token: str | None
) -> tuple[list[CtRecord], list[str]]:
    crtsh, spotter = await asyncio.gather(
        _crtsh(http, apex), _certspotter(http, apex, token), return_exceptions=True
    )
    records: list[CtRecord] = []
    errors: list[str] = []
    for name, payload in (("crt.sh", crtsh), ("certspotter", spotter)):
        if isinstance(payload, BaseException):
            errors.append(f"ct: {name} raised {type(payload).__name__}")
            continue
        if not payload:
            errors.append(f"ct: {name} returned no data")
            continue
        records.extend(payload)

    deduped: dict[str, CtRecord] = {}
    for record in records:
        key = record["serial"] or f"{record['common_name']}|{record['not_after']}"
        deduped.setdefault(key, record)
    return list(deduped.values()), errors


def names_from(records: list[CtRecord], apex: str) -> set[str]:
    found: set[str] = set()
    for record in records:
        for name in record["names"]:
            if valid_host(name, apex):
                found.add(name.lower().strip().rstrip("."))
    return found


async def _crtsh(http: HttpClient, apex: str) -> list[CtRecord]:
    data = await http.get_json(CRTSH, params={"q": f"%.{apex}", "output": "json"}, retries=2)
    out: list[CtRecord] = []
    for row in data or []:
        names = [n.strip().lower() for n in str(row.get("name_value", "")).split("\n") if n.strip()]
        common = str(row.get("common_name") or "").lower().strip()
        if common:
            names.append(common)
        out.append(
            CtRecord(
                serial=str(row.get("serial_number") or row.get("id") or ""),
                issuer=row.get("issuer_name"),
                common_name=common or None,
                names=sorted(set(names)),
                not_before=_iso(row.get("not_before")),
                not_after=_iso(row.get("not_after")),
                source="crt.sh",
            )
        )
    return out


async def _certspotter(http: HttpClient, apex: str, token: str | None) -> list[CtRecord]:
    # Unauthenticated queries are capped at a small sample of issuances; a free
    # Cert Spotter token lifts that to the full history.
    headers = {"Authorization": f"Bearer {token}"} if token else None
    data = await http.get_json(
        CERTSPOTTER,
        params={"domain": apex, "include_subdomains": "true", "expand": "dns_names"},
        headers=headers,
        retries=1,
    )
    out: list[CtRecord] = []
    for row in data or []:
        names = [str(n).lower().strip() for n in (row.get("dns_names") or [])]
        issuer = row.get("issuer")
        out.append(
            CtRecord(
                serial=str(row.get("id") or ""),
                issuer=issuer.get("name") if isinstance(issuer, dict) else issuer,
                common_name=names[0] if names else None,
                names=sorted(set(names)),
                not_before=_iso(row.get("not_before")),
                not_after=_iso(row.get("not_after")),
                source="certspotter",
            )
        )
    return out


def _iso(value: Any) -> str | None:
    return str(value) if value else None
