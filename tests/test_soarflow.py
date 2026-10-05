import responses

from soarflow.enrich import ThreatIntelClient
from soarflow.ioc import extract
from soarflow.pipeline import handle_alert
from soarflow.ticket import TicketClient

ALERT = {"id": "A-1", "rule": "SSH brute force", "severity": "high",
         "src_ip": "45.155.205.10", "user": "Admin", "host": "bastion-01",
         "message": "failed logins from 45.155.205.10 and 10.0.0.5 via evil-domain.example"}


def test_extract_splits_public_and_internal_ips():
    ind = extract(ALERT)
    assert ind.public_ips == {"45.155.205.10"}
    assert "10.0.0.5" in ind.internal_ips
    assert ind.users == {"admin"}
    assert "evil-domain.example" in ind.domains


def test_invalid_ip_is_ignored():
    ind = extract({"id": "x", "message": "bad ip 999.1.1.1"})
    assert not ind.public_ips and not ind.internal_ips


@responses.activate
def test_ti_failure_degrades_gracefully():
    responses.get("https://ti.example.com/ip/8.8.4.4", status=503)
    ti = ThreatIntelClient("https://ti.example.com", "k")
    assert ti.ip_reputation("8.8.4.4")["status"] == "unavailable"


@responses.activate
def test_ti_results_are_cached():
    responses.get("https://ti.example.com/ip/8.8.4.4", json={"score": 90})
    ti = ThreatIntelClient("https://ti.example.com", "k")
    ti.ip_reputation("8.8.4.4"); ti.ip_reputation("8.8.4.4")
    assert len(responses.calls) == 1


@responses.activate
def test_ticket_upsert_is_idempotent():
    responses.get("https://t.example.com/tickets", json={"items": [{"id": "SEC-9"}]})
    tid, created = TicketClient("https://t.example.com", "t").upsert(ALERT, {"title": "x"})
    assert (tid, created) == ("SEC-9", False)
    assert len(responses.calls) == 1                  # no POST -> no duplicate


class TI:
    def __init__(self, score, status="ok"):
        self.score, self.status = score, status

    def ip_reputation(self, ip):
        return {"score": self.score, "status": self.status}


class Tickets:
    def upsert(self, alert, payload):
        return "SEC-1", True


class Blocker:
    def __init__(self):
        self.blocked = []

    def block(self, ip, ttl_hours, reason):
        self.blocked.append(ip)


def public_alert(sev="critical"):
    return {**ALERT, "severity": sev, "src_ip": "185.220.101.4", "message": ""}


def test_high_risk_auto_contains_in_dry_run_only():
    b = Blocker()
    r = handle_alert(public_alert(), TI(95), Tickets(), blocker=b, dry_run=True)
    assert r["decision"] == "auto_contain" and b.blocked == []
    assert r["actions"] == ["DRY-RUN would block 185.220.101.4"]


def test_real_block_when_dry_run_disabled():
    b = Blocker()
    handle_alert(public_alert(), TI(95), Tickets(), blocker=b, dry_run=False)
    assert b.blocked == ["185.220.101.4"]


def test_incomplete_enrichment_never_auto_contains():
    r = handle_alert(public_alert(), TI(None, "unavailable"), Tickets(), blocker=Blocker())
    assert r["decision"] != "auto_contain"


def test_low_risk_auto_closes():
    r = handle_alert({**public_alert("low")}, TI(5), Tickets())
    assert r["decision"] == "auto_close"
