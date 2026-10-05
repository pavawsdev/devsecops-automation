"""JSON, CSV and Markdown reports. CSV cells are sanitised against formula injection."""
from __future__ import annotations

import csv
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding
from .policy import GateResult

CSV_FIELDS = ["fingerprint", "id", "severity", "cvss", "asset", "package",
              "installed_version", "fixed_version", "title"]


def _safe_cell(value) -> str:
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)                  # atomic on POSIX


def write_json(path: Path, findings: list[Finding], gate: GateResult) -> None:
    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": gate.passed,
        "summary": gate.counts,
        "blocking": [f.to_dict() for f in gate.blocking],
        "findings": [f.to_dict() for f in findings],
    }
    _atomic_write(path, json.dumps(doc, indent=2))


def write_csv(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for f in findings:
            d = f.to_dict()
            w.writerow({k: _safe_cell(d.get(k)) for k in CSV_FIELDS})


def markdown_summary(gate: GateResult, threshold: str) -> str:
    status = "PASSED" if gate.passed else "FAILED"
    lines = [f"## Security gate: {status} (threshold: {threshold})", "",
             "| Severity | Count |", "|---|---|"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        lines.append(f"| {sev} | {gate.counts.get(sev, 0)} |")
    if gate.blocking:
        lines += ["", "### Blocking findings", ""]
        for f in gate.blocking[:20]:
            fix = f.fixed_version or "no fix yet"
            lines.append(f"- **{f.id}** ({f.severity}, CVSS {f.cvss}) in `{f.package}` "
                         f"{f.installed_version} on {f.asset} - fix: {fix}")
    return "\n".join(lines) + "\n"
