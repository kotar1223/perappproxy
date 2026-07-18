"""Free proxy pool — fetch, validate, and manage public proxies."""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import httpx

PROXY_CACHE = Path.home() / ".perappproxy" / "proxy_pool.json"

FREE_PROXY_SOURCES = [
    # SOCKS5
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    # HTTP
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    # Combined
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]

TEST_URL = "http://httpbin.org/ip"
TEST_TIMEOUT = 5


@dataclass
class ProxyEntry:
    address: str          # host:port
    protocol: str         # socks5, http, https
    country: str = ""
    latency_ms: float = 0
    last_checked: float = 0
    alive: bool = True

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.address}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ProxyEntry":
        return cls(**d)


class ProxyPool:
    def __init__(self) -> None:
        self.proxies: list[ProxyEntry] = []
        self._load_cache()

    def _load_cache(self) -> None:
        if PROXY_CACHE.exists():
            try:
                data = json.loads(PROXY_CACHE.read_text(encoding="utf-8"))
                self.proxies = [ProxyEntry.from_dict(p) for p in data]
            except Exception:
                self.proxies = []

    def _save_cache(self) -> None:
        PROXY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        data = [p.to_dict() for p in self.proxies]
        PROXY_CACHE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def fetch_free_proxies(self, progress_callback=None) -> list[ProxyEntry]:
        """Fetch proxies from public sources."""
        new_proxies: list[ProxyEntry] = []
        existing = {p.address for p in self.proxies}

        client = httpx.Client(timeout=10, follow_redirects=True)

        for url in FREE_PROXY_SOURCES:
            try:
                if progress_callback:
                    progress_callback(f"Fetching from {url.split('/')[-1]}...")
                resp = client.get(url)
                resp.raise_for_status()
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    # Determine protocol from URL
                    if "socks5" in url:
                        proto = "socks5"
                    elif "https" in url:
                        proto = "https"
                    else:
                        proto = "http"

                    if line not in existing:
                        new_proxies.append(ProxyEntry(address=line, protocol=proto))
                        existing.add(line)
            except Exception:
                continue

        client.close()
        return new_proxies

    def validate_proxies(self, proxies: list[ProxyEntry] | None = None, progress_callback=None) -> list[ProxyEntry]:
        """Test which proxies actually work."""
        to_test = proxies or self.proxies
        alive: list[ProxyEntry] = []
        total = len(to_test)

        client = httpx.Client(timeout=TEST_TIMEOUT, follow_redirects=True)

        for i, proxy in enumerate(to_test):
            if progress_callback:
                progress_callback(f"Testing {proxy.address} ({i+1}/{total})")
            try:
                start = time.time()
                resp = client.get(
                    TEST_URL,
                    proxy=proxy.url,
                    timeout=TEST_TIMEOUT,
                )
                latency = (time.time() - start) * 1000
                if resp.status_code == 200:
                    proxy.alive = True
                    proxy.latency_ms = round(latency, 1)
                    proxy.last_checked = time.time()
                    alive.append(proxy)
            except Exception:
                proxy.alive = False

        client.close()
        return alive

    def add_proxy(self, address: str, protocol: str = "socks5") -> ProxyEntry:
        """Add a custom proxy."""
        entry = ProxyEntry(address=address, protocol=protocol, alive=True, last_checked=time.time())
        # Remove existing with same address
        self.proxies = [p for p in self.proxies if p.address != address]
        self.proxies.append(entry)
        self._save_cache()
        return entry

    def remove_proxy(self, address: str) -> bool:
        before = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.address != address]
        if len(self.proxies) < before:
            self._save_cache()
            return True
        return False

    def get_random(self, alive_only: bool = True) -> Optional[ProxyEntry]:
        """Get a random proxy from the pool."""
        pool = [p for p in self.proxies if p.alive] if alive_only else self.proxies
        if not pool:
            return None
        return random.choice(pool)

    def get_best(self, count: int = 1, alive_only: bool = True) -> list[ProxyEntry]:
        """Get the fastest proxies."""
        pool = [p for p in self.proxies if p.alive] if alive_only else self.proxies
        pool.sort(key=lambda p: p.latency_ms if p.latency_ms > 0 else 99999)
        return pool[:count]

    def list_all(self) -> list[ProxyEntry]:
        return self.proxies

    def list_alive(self) -> list[ProxyEntry]:
        return [p for p in self.proxies if p.alive]

    def count(self) -> dict:
        alive = sum(1 for p in self.proxies if p.alive)
        return {"total": len(self.proxies), "alive": alive, "dead": len(self.proxies) - alive}

    def clear(self) -> None:
        self.proxies.clear()
        self._save_cache()
