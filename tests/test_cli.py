import json

from vulnauto.cli import main


def write(tmp_path, vulns):
    p = tmp_path / "in.json"
    p.write_text(json.dumps({"vulnerabilities": vulns}))
    return p


def test_exit_0_when_clean(tmp_path):
    p = write(tmp_path, [{"cve_id": "C", "asset": "a", "severity": "LOW"}])
    assert main(["--input", str(p), "--out-dir", str(tmp_path / "r")]) == 0
    assert (tmp_path / "r" / "report.json").exists()
    assert (tmp_path / "r" / "report.csv").exists()


def test_exit_1_on_critical(tmp_path):
    p = write(tmp_path, [{"cve_id": "C", "asset": "a", "severity": "CRITICAL"}])
    assert main(["--input", str(p), "--out-dir", str(tmp_path / "r")]) == 1


def test_exit_2_when_token_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_API_URL", "https://vuln.example.com")
    monkeypatch.delenv("VULN_API_TOKEN", raising=False)
    assert main(["--out-dir", str(tmp_path)]) == 2


def test_exit_2_when_url_not_https(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_API_URL", "http://insecure.example.com")
    monkeypatch.setenv("VULN_API_TOKEN", "x")
    assert main(["--out-dir", str(tmp_path)]) == 2
