"""Extract and validate indicators (IOCs) from a SIEM alert."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)


@dataclass
class Indicators:
    public_ips: set[str] = field(default_factory=set)
    internal_ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)


def extract(alert: dict) -> Indicators:
    ind = Indicators()
    # 1. structured fields first (reliable)
    for key in ("src_ip", "dest_ip", "source.ip", "destination.ip"):
        if alert.get(key):
            _add_ip(ind, str(alert[key]))
    if alert.get("user"):
        ind.users.add(str(alert["user"]).lower())
    if alert.get("host"):
        ind.hosts.add(str(alert["host"]).lower())
    # 2. free text (raw log / description) second
    text = " ".join(str(alert.get(k, "")) for k in ("message", "raw", "description"))
    for ip in IPV4.findall(text):
        _add_ip(ind, ip)
    ind.hashes.update(h.lower() for h in SHA256.findall(text))
    for d in DOMAIN.findall(text):
        if not IPV4.fullmatch(d):
            ind.domains.add(d.lower())
    return ind


def _add_ip(ind: Indicators, value: str) -> None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return                                   # e.g. 999.1.1.1 -> not an IP
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        ind.internal_ips.add(str(ip))
    else:
        ind.public_ips.add(str(ip))
