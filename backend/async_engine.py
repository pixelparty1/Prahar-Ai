"""
async_engine.py — Global Async HTTP Engine
--------------------------------------------
Shared async infrastructure for Prahaar AI.

Provides:
  • AsyncHTTPClient — aiohttp.ClientSession wrapper with connection pooling,
    semaphore-based rate control, and request deduplication.
  • RequestDedupCache — global cache of (url, method, body) → response to
    prevent duplicate payload tests.
  • measure_latency_async() — async server latency measurement.
  • run_sync() — helper to run an async coroutine from synchronous code.

Does NOT modify any attack detection logic.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# ── Defaults ──────────────────────────────────────────────────────────────

# Max concurrent HTTP requests in the async engine
DEFAULT_MAX_CONCURRENT = min(64, (os.cpu_count() or 2) * 8)
DEFAULT_TIMEOUT = 10.0
DEFAULT_CONN_LIMIT = 100  # aiohttp TCPConnector limit


# ── Request Deduplication Cache ───────────────────────────────────────────

class RequestDedupCache:
    """
    Thread-safe cache of (url, method, body_hash) keys to avoid sending
    the same request twice.  Used at the orchestration layer to skip
    redundant payload tests across parallel workers.
    """

    def __init__(self):
        self._seen: Set[Tuple[str, str, str]] = set()
        self._lock = asyncio.Lock()

    def _key(self, url: str, method: str, body: Optional[str] = None) -> Tuple[str, str, str]:
        body_hash = hashlib.md5((body or "").encode(), usedforsecurity=False).hexdigest()
        return (url, method.upper(), body_hash)

    async def is_duplicate(self, url: str, method: str, body: Optional[str] = None) -> bool:
        key = self._key(url, method, body)
        async with self._lock:
            if key in self._seen:
                return True
            self._seen.add(key)
            return False

    def is_duplicate_sync(self, url: str, method: str, body: Optional[str] = None) -> bool:
        """Non-async version for use in threaded contexts."""
        key = self._key(url, method, body)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def clear(self):
        self._seen.clear()

    @property
    def size(self) -> int:
        return len(self._seen)


# Global singleton dedup cache for the scan session
_global_dedup = RequestDedupCache()


def get_dedup_cache() -> RequestDedupCache:
    """Return the global request dedup cache."""
    return _global_dedup


def reset_dedup_cache():
    """Reset the global dedup cache and latency cache (call at start of each scan)."""
    _global_dedup.clear()
    _latency_cache.clear()


# ── Async HTTP Client ────────────────────────────────────────────────────

class AsyncHTTPClient:
    """
    Reusable async HTTP client with:
      • aiohttp.ClientSession + TCPConnector for connection pooling (Opt 4)
      • asyncio.Semaphore for rate control (Opt 14)
      • Request deduplication (Opt 6)

    Usage::

        async with AsyncHTTPClient() as client:
            resp = await client.get("http://example.com/page")
    """

    def __init__(
        self,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        timeout: float = DEFAULT_TIMEOUT,
        conn_limit: int = DEFAULT_CONN_LIMIT,
        user_agent: str = "PrahaarCrawler/2.0",
        dedup: bool = False,
    ):
        self._max_concurrent = max_concurrent
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._conn_limit = conn_limit
        self._user_agent = user_agent
        self._dedup = dedup
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self._conn_limit,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
            headers={"User-Agent": self._user_agent},
        )
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        return self

    async def __aexit__(self, *exc):
        if self._session:
            await self._session.close()
            self._session = None

    async def get(
        self,
        url: str,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        return await self._request("GET", url, allow_redirects=allow_redirects, **kwargs)

    async def head(
        self,
        url: str,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        return await self._request("HEAD", url, allow_redirects=allow_redirects, **kwargs)

    async def post(
        self,
        url: str,
        data: Any = None,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        return await self._request("POST", url, data=data, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        return await self._request(method, url, **kwargs)

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        if not self._session or not self._semaphore:
            raise RuntimeError("Client not initialized — use 'async with' context")

        if self._dedup:
            body = str(kwargs.get("data", ""))
            if await get_dedup_cache().is_duplicate(url, method, body):
                return None

        async with self._semaphore:
            try:
                return await self._session.request(method, url, **kwargs)
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError, OSError):
                # One immediate retry with a shorter timeout to avoid
                # doubling the wait on genuine timeouts.
                try:
                    retry_kw = dict(kwargs)
                    retry_kw["timeout"] = aiohttp.ClientTimeout(
                        total=min(self._timeout.total or 10.0, 5.0)
                    )
                    return await self._session.request(method, url, **retry_kw)
                except Exception as exc:
                    logger.debug("[AsyncHTTPClient] %s %s retry failed: %s", method, url, exc)
                    return None
            except Exception as exc:
                logger.debug("[AsyncHTTPClient] %s %s failed: %s", method, url, exc)
                return None


# ── Async Latency Measurement ────────────────────────────────────────────

async def measure_latency_async(
    target_url: str,
    n_probes: int = 3,
    timeout: float = 5.0,
) -> Optional[float]:
    """
    Send HEAD probes to measure average server response time.
    Returns average latency in seconds, or None if all probes fail.

    Results are cached for 60 seconds per target_url so that multiple
    runners sharing the same target avoid redundant probes.
    """
    cached = _latency_cache.get(target_url)
    if cached is not None:
        logger.debug("[LatencyCache] HIT for %s → %.3fs", target_url, cached)
        return cached

    times: List[float] = []
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        for _ in range(n_probes):
            try:
                start = time.time()
                async with session.head(target_url, allow_redirects=True):
                    pass
                times.append(time.time() - start)
            except Exception:
                pass
    result = sum(times) / len(times) if times else None
    _latency_cache.put(target_url, result)
    return result


# ── Latency Cache ─────────────────────────────────────────────────────────

class _LatencyCache:
    """Thread-safe TTL cache for latency measurements (~60 s lifespan)."""
    _TTL = 60.0

    def __init__(self):
        self._store: Dict[str, Tuple[float, Optional[float]]] = {}
        self._lock = threading.Lock()

    def get(self, url: str) -> Optional[float]:
        with self._lock:
            entry = self._store.get(url)
            if entry is None:
                return None
            ts, val = entry
            if time.time() - ts > self._TTL:
                del self._store[url]
                return None
            return val

    def put(self, url: str, val: Optional[float]) -> None:
        with self._lock:
            self._store[url] = (time.time(), val)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


_latency_cache = _LatencyCache()


def reset_latency_cache():
    """Reset the latency cache (call at start of each scan)."""
    _latency_cache.clear()


# ── Sync → Async Bridge ──────────────────────────────────────────────────

def run_sync(coro):
    """
    Run an async coroutine from synchronous code.
    Creates a new event loop if none is running.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside an existing event loop (e.g. Jupyter, nested call).
        # Create a new loop in a thread.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)
