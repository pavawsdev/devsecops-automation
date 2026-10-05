"""Configuration loaded from environment variables, validated at start-up."""
from __future__ import annotations

import os
from dataclasses import dataclass

from .exceptions import ConfigError

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True)
class Settings:
    api_url: str
    api_token: str
    threshold: str = "CRITICAL"      # fail the build at or above this severity
    page_size: int = 100
    timeout: float = 30.0
    max_retries: int = 5
    ignore_unfixed: bool = False

    def __repr__(self) -> str:        # never print the token
        return f"Settings(api_url={self.api_url!r}, threshold={self.threshold!r}, token=***)"


def load_settings(threshold: str | None = None, ignore_unfixed: bool | None = None) -> Settings:
    """Precedence: CLI argument > environment variable > default."""
    url = os.getenv("VULN_API_URL", "").rstrip("/")
    token = os.getenv("VULN_API_TOKEN", "")
    if not url.startswith("https://"):
        raise ConfigError("VULN_API_URL must be set and must use https://")
    if not token:
        raise ConfigError("VULN_API_TOKEN is not set (inject it from a secret store)")
    thr = (threshold or os.getenv("VULN_THRESHOLD") or "CRITICAL").upper()
    if thr not in SEVERITIES:
        raise ConfigError(f"threshold must be one of {SEVERITIES}")
    unfixed = ignore_unfixed if ignore_unfixed is not None else \
        os.getenv("VULN_IGNORE_UNFIXED", "false").lower() == "true"
    return Settings(api_url=url, api_token=token, threshold=thr,
                    page_size=int(os.getenv("VULN_PAGE_SIZE", "100")),
                    timeout=float(os.getenv("VULN_TIMEOUT", "30")),
                    max_retries=int(os.getenv("VULN_MAX_RETRIES", "5")),
                    ignore_unfixed=unfixed)
