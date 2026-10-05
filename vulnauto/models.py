"""Normalised finding model shared by every source."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass

log = logging.getLogger(__name__)
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    id: str
    asset: str
    package: str
    installed_version: str
    fixed_version: str | None
    severity: str
    cvss: float
    title: str

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    @property
    def fingerprint(self) -> str:
        key = f"{self.asset}|{self.id}|{self.package}".lower()
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {**asdict(self), "fingerprint": self.fingerprint}


def parse_finding(raw: dict) -> Finding | None:
    """Tolerate optional fields; skip (and log) records missing required ones."""
    try:
        sev = str(raw.get("severity", "UNKNOWN")).upper()
        return Finding(
            id=raw["cve_id"],
            asset=raw["asset"],
            package=raw.get("package", "unknown"),
            installed_version=raw.get("installed_version", ""),
            fixed_version=raw.get("fixed_version") or None,
            severity=sev if sev in SEVERITY_RANK else "UNKNOWN",
            cvss=float(raw.get("cvss", 0.0) or 0.0),
            title=str(raw.get("title", ""))[:200],
        )
    except (KeyError, TypeError, ValueError) as exc:
        log.warning("skipping malformed record: %s", exc)
        return None


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint, f)
    return list(seen.values())
