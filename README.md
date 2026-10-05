# devsecops-automation

Two reference projects for a "DevSecOps engineer who uses Python to automate security operations".

## 1. vulnauto - vulnerability management security gate
Calls a vulnerability API (bearer token from env), follows cursor pagination, retries 429/5xx
with exponential backoff + jitter, normalises and de-duplicates findings, applies a severity
threshold (with allowlist and ignore-unfixed options), writes JSON + CSV + Markdown reports and
returns an exit code the pipeline can act on.

| Situation | Behaviour | Exit |
|---|---|---|
| HTTP 200, nothing at/above threshold | reports written | 0 |
| HTTP 200, blocking findings | reports + ::error annotations | 1 |
| HTTP 401/403, missing token, non-https URL | logged, no retry | 2 |
| HTTP 429 / 5xx / network | retried with backoff; then fail | 3 |

```bash
pip install -r requirements-dev.txt
pytest -q
python -m vulnauto.cli --input samples/vulnerabilities.json --threshold HIGH
python -m vulnauto.cli --input samples/vulnerabilities.json --allowlist samples/allowlist.txt
export VULN_API_URL=https://vuln.example.com/api VULN_API_TOKEN=...   # online mode
python -m vulnauto.cli
```

## 2. soarflow - SIEM alert enrichment and response
SIEM alert -> IOC extraction (public vs internal IPs, users, hosts, domains, hashes) ->
threat-intel enrichment (cached, degrades gracefully) -> explainable risk score ->
idempotent ticket upsert -> guarded containment (dry-run default, never-block list, TTL).

```bash
python -m soarflow.pipeline samples/alert.json
```

## Pipelines
`.github/workflows/devsecops.yml`: lint/type/test -> SAST (Semgrep, Bandit) -> SCA (pip-audit)
-> container (Trivy) -> Python vulnerability gate. Pin actions to SHAs in production.

`.github/workflows/infra.yml`: Terraform for dev/stage/prod from one codebase - PRs plan all
three environments, merges promote dev -> stage -> prod with approvals. See [infra/README.md](infra/README.md).
