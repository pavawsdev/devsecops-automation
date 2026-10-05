"""Command-line entry point.

Exit codes (the contract with the CI/CD pipeline):
  0  gate passed
  1  gate failed - findings at/above threshold
  2  configuration or authentication error
  3  upstream API / network error after retries
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .client import VulnApiClient
from .config import SEVERITIES, load_settings
from .exceptions import VulnAutoError
from .models import dedupe, parse_finding
from .policy import evaluate
from .report import markdown_summary, write_csv, write_json

log = logging.getLogger("vulnauto")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnauto", description="Vulnerability security gate")
    p.add_argument("--threshold", choices=SEVERITIES, help="fail at/above this severity")
    p.add_argument("--input", type=Path, help="read findings from a JSON file (offline mode)")
    p.add_argument("--out-dir", type=Path, default=Path("reports"))
    p.add_argument("--allowlist", type=Path, help="file with accepted CVE ids, one per line")
    p.add_argument("--ignore-unfixed", action="store_true", default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(stream=sys.stderr,           # stdout stays clean for reports
                        level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def load_raw(args):
    if args.input:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        raw = data.get("vulnerabilities", []) if isinstance(data, dict) else data
        return raw, args.threshold or "CRITICAL", bool(args.ignore_unfixed)
    s = load_settings(args.threshold, args.ignore_unfixed)
    log.info("loaded %r", s)
    return list(VulnApiClient(s).iter_vulnerabilities()), s.threshold, s.ignore_unfixed


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    try:
        raw, threshold, ignore_unfixed = load_raw(args)
        findings = dedupe([f for f in map(parse_finding, raw) if f])
        allow: set[str] = set()
        if args.allowlist and args.allowlist.exists():
            allow = {ln.strip() for ln in args.allowlist.read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")}
        gate = evaluate(findings, threshold, ignore_unfixed, allow)
        write_json(args.out_dir / "report.json", findings, gate)
        write_csv(args.out_dir / "report.csv", findings)
        summary = markdown_summary(gate, threshold)
        print(summary)
        if os.getenv("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
                fh.write(summary)
        for f in gate.blocking:
            print(f"::error title={f.id}::{f.severity} {f.package} on {f.asset}", file=sys.stderr)
        log.info("findings=%d blocking=%d", len(findings), len(gate.blocking))
        return 0 if gate.passed else 1
    except VulnAutoError as exc:
        log.error("%s: %s", type(exc).__name__, exc)
        return exc.exit_code
    except (OSError, json.JSONDecodeError) as exc:
        log.error("input/output error: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())
