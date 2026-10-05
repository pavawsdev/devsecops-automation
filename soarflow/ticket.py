"""Idempotent ticket creation: search by correlation id before creating."""
from __future__ import annotations

import hashlib

import requests


def correlation_id(alert: dict) -> str:
    return hashlib.sha256(f"{alert.get('source', 'siem')}:{alert['id']}".encode()).hexdigest()[:32]


class TicketClient:
    def __init__(self, base_url: str, token: str, session: requests.Session | None = None):
        self.base = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def upsert(self, alert: dict, payload: dict) -> tuple[str, bool]:
        corr = correlation_id(alert)
        r = self.session.get(f"{self.base}/tickets", params={"correlation_id": corr}, timeout=15)
        r.raise_for_status()
        existing = r.json().get("items", [])
        if existing:
            return existing[0]["id"], False
        r = self.session.post(f"{self.base}/tickets", json={**payload, "correlation_id": corr},
                              headers={"Idempotency-Key": corr}, timeout=15)
        r.raise_for_status()
        return r.json()["id"], True
