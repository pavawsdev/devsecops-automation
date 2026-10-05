"""Transparent, explainable risk scoring."""
from __future__ import annotations

SEVERITY_BASE = {"low": 10, "medium": 30, "high": 50, "critical": 70}


def score(alert: dict, intel: dict[str, dict], asset_criticality: str = "normal") -> tuple[int, list[str]]:
    reasons: list[str] = []
    total = SEVERITY_BASE.get(str(alert.get("severity", "low")).lower(), 10)
    reasons.append(f"alert severity {alert.get('severity', 'low')} -> {total}")
    worst = max((i["score"] for i in intel.values() if i.get("score") is not None), default=None)
    if worst is not None and worst >= 80:
        total += 25
        reasons.append(f"IP reputation {worst} >= 80 -> +25")
    elif worst is not None and worst >= 50:
        total += 10
        reasons.append(f"IP reputation {worst} >= 50 -> +10")
    if any(i.get("status") != "ok" for i in intel.values()):
        reasons.append("some enrichment unavailable -> analyst review required")
    if asset_criticality == "crown_jewel":
        total += 15
        reasons.append("crown-jewel asset -> +15")
    return min(total, 100), reasons


def decide(total: int, enrichment_complete: bool) -> str:
    if total >= 85 and enrichment_complete:
        return "auto_contain"
    if total >= 50:
        return "escalate"
    return "auto_close"
