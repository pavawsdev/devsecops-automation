"""Threat-intelligence enrichment with caching and graceful degradation."""
from __future__ import annotations

import logging
import time

import requests

log = logging.getLogger(__name__)


class ThreatIntelClient:
    """Generic reputation API: GET {base}/ip/{ip} -> {"score": 0-100, "tags": [...]}."""

    def __init__(self, base_url: str, api_key: str, session: requests.Session | None = None,
                 ttl: int = 3600):
        self.base = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"X-Api-Key": api_key, "Accept": "application/json"})
        self.ttl = ttl
        self._cache: dict[str, tuple[float, dict]] = {}

    def ip_reputation(self, ip: str) -> dict:
        hit = self._cache.get(ip)
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]
        try:
            r = self.session.get(f"{self.base}/ip/{ip}", timeout=10)
            if r.status_code == 429:
                log.warning("TI rate limited for %s", ip)
                return {"score": None, "status": "rate_limited"}
            r.raise_for_status()
            data = r.json()
            result = {"score": int(data.get("score", 0)), "tags": data.get("tags", []),
                      "status": "ok"}
        except (requests.RequestException, ValueError) as exc:
            log.warning("TI lookup failed for %s: %s", ip, type(exc).__name__)
            return {"score": None, "status": "unavailable"}   # degrade, never crash
        self._cache[ip] = (time.time(), result)
        return result
