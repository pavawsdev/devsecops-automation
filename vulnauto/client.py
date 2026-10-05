"""REST client: auth, timeouts, retry with backoff, pagination, error mapping."""
from __future__ import annotations

import logging
import random
import time
from collections.abc import Iterator

import requests

from .config import Settings
from .exceptions import ApiError, AuthError

log = logging.getLogger(__name__)
RETRYABLE = {429, 500, 502, 503, 504}


class VulnApiClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None,
                 sleep=time.sleep):
        self.s = settings
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {settings.api_token}",
            "Accept": "application/json",
            "User-Agent": "vulnauto/1.0",
        })
        self._sleep = sleep            # injectable -> fast unit tests

    def _get(self, url: str, params: dict | None = None) -> dict:
        for attempt in range(1, self.s.max_retries + 1):
            try:
                r = self.session.get(url, params=params, timeout=self.s.timeout)
            except (requests.ConnectionError, requests.Timeout) as exc:
                log.warning("network error on attempt %d: %s", attempt, type(exc).__name__)
                self._backoff(attempt, None)
                continue
            if r.status_code in (401, 403):
                raise AuthError(f"authentication failed: HTTP {r.status_code}")
            if r.status_code in RETRYABLE:
                log.warning("HTTP %d on attempt %d/%d", r.status_code, attempt, self.s.max_retries)
                self._backoff(attempt, r.headers.get("Retry-After"))
                continue
            if r.status_code >= 400:
                raise ApiError(f"non-retryable HTTP {r.status_code}")
            try:
                return r.json()
            except ValueError as exc:
                raise ApiError("response is not valid JSON") from exc
        raise ApiError(f"giving up after {self.s.max_retries} attempts")

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        if retry_after and retry_after.isdigit():
            delay = float(retry_after)
        else:
            delay = min(60.0, 2 ** (attempt - 1)) + random.uniform(0, 1)   # jitter
        self._sleep(delay)

    def iter_vulnerabilities(self) -> Iterator[dict]:
        """Cursor pagination: follow `next_cursor` until it is empty."""
        url = f"{self.s.api_url}/vulnerabilities"
        params: dict = {"limit": self.s.page_size}
        pages = 0
        while True:
            body = self._get(url, params)
            pages += 1
            yield from body.get("vulnerabilities", [])
            cursor = body.get("next_cursor")
            if not cursor:
                log.info("fetched %d page(s)", pages)
                return
            params["cursor"] = cursor
