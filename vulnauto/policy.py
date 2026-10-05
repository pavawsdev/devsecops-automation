"""Security gate policy: decide pass/fail from normalised findings."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .models import SEVERITY_RANK, Finding


@dataclass
class GateResult:
    passed: bool
    blocking: list[Finding]
    counts: dict[str, int]


def evaluate(findings: list[Finding], threshold: str, ignore_unfixed: bool = False,
             allowlist: set[str] | None = None) -> GateResult:
    limit = SEVERITY_RANK[threshold]
    allowlist = allowlist or set()
    blocking = [
        f for f in findings
        if f.rank >= limit
        and f.id not in allowlist
        and not (ignore_unfixed and not f.fixed_version)
    ]
    blocking.sort(key=lambda f: (-f.rank, -f.cvss))
    counts = dict(Counter(f.severity for f in findings))
    return GateResult(passed=not blocking, blocking=blocking, counts=counts)
