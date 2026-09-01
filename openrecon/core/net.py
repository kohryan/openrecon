"""Shared network primitives: a polite async HTTP client and a DNS resolver.

Every collector goes through `HttpClient` so that rate limiting, caching,
retries, and the user agent are enforced in exactly one place.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import dns.reversename
import httpx

from openrecon.config import Config
from openrecon.core.cache import DiskCache


class RateLimiter:
    """Per-host token bucket; keeps us welcome at free public APIs."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate = max(rate_per_second, 0.1)
        self._last: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, host: str) -> None:
        async with self._locks[host]:
            interval = 1.0 / self.rate
            elapsed = time.monotonic() - self._last[host]
            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)
            self._last[host] = time.monotonic()


class HttpClient:
    """Async HTTP with caching, per-host rate limiting, and bounded retries."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.cache = DiskCache(config.cache_dir / "http", config.cache_ttl, config.use_cache)
        self.limiter = RateLimiter(config.rate_limit_per_host)
        self._client: httpx.AsyncClient | None = None
        self._sem = asyncio.Semaphore(config.concurrency)
        # Results shared between collectors within one scan (e.g. the CT fetch),
        # including failures - a dead upstream should be hit once, not per caller.
        self._memo: dict[str, Any] = {}
        self._memo_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        # Consecutive refusals per host. A scanner that keeps hammering a host
        # that has started rejecting it earns a longer block and collects worse
        # data for the rest of the run - so it stops instead.
        self._refusals: dict[str, int] = defaultdict(int)
        self.cooled_off: set[str] = set()

    async def __aenter__(self) -> HttpClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.http_timeout),
            follow_redirects=True,
            headers={"User-Agent": self.config.user_agent, "Accept": "*/*"},
            limits=httpx.Limits(max_connections=self.config.concurrency * 2),
            verify=False,  # target certs are evidence, not a trust decision
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("HttpClient used outside its async context manager")
        return self._client

    async def memoize(self, key: str, factory: Callable[[], Awaitable[Any]]) -> Any:
        """Run `factory` at most once per scan for a given key."""
        async with self._memo_locks[key]:
            if key not in self._memo:
                self._memo[key] = await factory()
            return self._memo[key]

    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache: bool = True,
        retries: int = 2,
    ) -> Any | None:
        key = f"GET|{url}|{sorted((params or {}).items())}"
        if cache:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
        resp = await self.request("GET", url, params=params, headers=headers, retries=retries)
        if resp is None or resp.status_code >= 400:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if cache:
            self.cache.set(key, data)
        return data

    async def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cache: bool = True,
        retries: int = 1,
        max_bytes: int = 512_000,
    ) -> str | None:
        key = f"GETTEXT|{url}"
        if cache:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
        resp = await self.request("GET", url, headers=headers, retries=retries)
        if resp is None or resp.status_code >= 400:
            return None
        text = resp.text[:max_bytes]
        if cache:
            self.cache.set(key, text)
        return text

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 1,
        **kwargs: Any,
    ) -> httpx.Response | None:
        host = urlparse(url).hostname or url
        if host in self.cooled_off:
            return None
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            await self.limiter.acquire(host)
            async with self._sem:
                try:
                    resp = await self.client.request(
                        method, url, params=params, headers=headers, **kwargs
                    )
                except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
                    last_exc = exc
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
            if resp.status_code == 429 and attempt < retries:
                retry_after = float(resp.headers.get("retry-after", 2))
                await asyncio.sleep(min(retry_after, 10))
                continue
            if resp.status_code >= 500 and attempt < retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue

            if resp.status_code in (403, 429):
                self._refusals[host] += 1
                if self._refusals[host] >= self.config.refusal_threshold:
                    self.cooled_off.add(host)
            else:
                self._refusals[host] = 0
            return resp
        if last_exc:
            return None
        return None


class DnsClient:
    """Async DNS lookups over the configured public resolvers."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = list(config.resolvers)
        self.resolver.timeout = config.dns_timeout
        self.resolver.lifetime = config.dns_timeout * 2
        self.cache = DiskCache(config.cache_dir / "dns", config.cache_ttl, config.use_cache)
        self._sem = asyncio.Semaphore(config.concurrency * 2)

    async def query(self, name: str, rdtype: str) -> list[str]:
        key = f"{name}|{rdtype}"
        hit = self.cache.get(key)
        if hit is not None:
            return list(hit)
        async with self._sem:
            try:
                answer = await self.resolver.resolve(name, rdtype, raise_on_no_answer=False)
            except (dns.exception.DNSException, ValueError, OSError):
                self.cache.set(key, [])
                return []
        values = [r.to_text().strip('"') for r in answer] if answer.rrset else []
        self.cache.set(key, values)
        return values

    async def resolves(self, name: str) -> tuple[bool, list[str], str | None]:
        """(exists, ip addresses, cname target) - the subdomain-validation workhorse."""
        cname = None
        cnames = await self.query(name, "CNAME")
        if cnames:
            cname = cnames[0].rstrip(".")
        ips = await self.query(name, "A")
        ips += await self.query(name, "AAAA")
        return (bool(ips or cname), ips, cname)

    async def reverse(self, ip: str) -> list[str]:
        try:
            rev = dns.reversename.from_address(ip)
        except (dns.exception.SyntaxError, ValueError):
            return []
        return [v.rstrip(".") for v in await self.query(str(rev), "PTR")]

