"""Orchestrates: extract -> enrich -> score -> decide -> ticket -> (guarded) action."""
from __future__ import annotations

import json
import logging
import sys

from .ioc import extract
from .risk import decide, score

log = logging.getLogger(__name__)
NEVER_BLOCK = {"8.8.8.8", "1.1.1.1"}           # resolvers/partners: version-controlled list


def handle_alert(alert: dict, ti, tickets, blocker=None, dry_run: bool = True,
                 asset_criticality: str = "normal") -> dict:
    ind = extract(alert)
    intel = {ip: ti.ip_reputation(ip) for ip in sorted(ind.public_ips)}
    complete = all(v.get("status") == "ok" for v in intel.values())
    total, reasons = score(alert, intel, asset_criticality)
    decision = decide(total, complete)

    ticket_id, created = tickets.upsert(alert, {
        "title": f"[{decision}] {alert.get('rule', 'SIEM alert')}",
        "risk_score": total, "reasons": reasons,
        "indicators": {"public_ips": sorted(ind.public_ips), "users": sorted(ind.users),
                       "hosts": sorted(ind.hosts), "domains": sorted(ind.domains)},
        "enrichment": intel,
    })

    actions = []
    if decision == "auto_contain" and blocker is not None:
        for ip in sorted(ind.public_ips):
            if ip in NEVER_BLOCK or (intel[ip].get("score") or 0) < 80:
                continue
            if dry_run:
                actions.append(f"DRY-RUN would block {ip}")
            else:
                blocker.block(ip, ttl_hours=24, reason=f"ticket {ticket_id}")
                actions.append(f"blocked {ip} for 24h")
    result = {"alert_id": alert["id"], "decision": decision, "risk_score": total,
              "ticket": ticket_id, "ticket_created": created, "actions": actions}
    log.info(json.dumps(result))
    return result


if __name__ == "__main__":        # demo: python -m soarflow.pipeline samples/alert.json
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    class FakeTI:
        def ip_reputation(self, ip):
            return {"score": 92, "tags": ["bruteforce"], "status": "ok"}

    class FakeTickets:
        def upsert(self, alert, payload):
            return "SEC-1001", True

    with open(sys.argv[1], encoding="utf-8") as fh:
        alert = json.load(fh)
    print(json.dumps(handle_alert(alert, FakeTI(), FakeTickets(),
                                  blocker=object(), dry_run=True), indent=2))
