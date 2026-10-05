from vulnauto.models import dedupe, parse_finding
from vulnauto.policy import evaluate
from vulnauto.report import _safe_cell

RAW = [
    {"cve_id": "CVE-1", "asset": "api", "package": "openssl", "severity": "critical",
     "cvss": 9.8, "fixed_version": "3.0.14"},
    {"cve_id": "CVE-2", "asset": "api", "package": "zlib", "severity": "HIGH", "cvss": 7.5},
    {"cve_id": "CVE-3", "asset": "web", "package": "glibc", "severity": "CRITICAL", "cvss": 9.1},
    {"asset": "broken-record"},                                       # missing cve_id
]


def findings():
    return [f for f in map(parse_finding, RAW) if f]


def test_malformed_records_are_skipped():
    assert len(findings()) == 3


def test_dedupe_by_fingerprint():
    fs = findings()
    assert len(dedupe(fs + fs)) == 3


def test_gate_fails_on_critical():
    g = evaluate(findings(), "CRITICAL")
    assert not g.passed and [f.id for f in g.blocking] == ["CVE-1", "CVE-3"]


def test_ignore_unfixed_and_allowlist():
    g = evaluate(findings(), "CRITICAL", ignore_unfixed=True, allowlist={"CVE-1"})
    assert g.passed


def test_high_threshold_includes_high():
    assert len(evaluate(findings(), "HIGH").blocking) == 3


def test_csv_formula_injection_is_neutralised():
    assert _safe_cell("=HYPERLINK(\"http://evil\")").startswith("'")
    assert _safe_cell("openssl") == "openssl"
