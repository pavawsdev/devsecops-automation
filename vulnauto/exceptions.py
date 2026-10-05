"""Exception hierarchy. Each error type maps to one CLI exit code."""


class VulnAutoError(Exception):
    """Base class for all tool errors."""
    exit_code = 3


class ConfigError(VulnAutoError):
    """Missing or invalid configuration (e.g. no API token)."""
    exit_code = 2


class AuthError(VulnAutoError):
    """HTTP 401/403 from the security API."""
    exit_code = 2


class ApiError(VulnAutoError):
    """Upstream API failure after all retries (5xx, 429, network)."""
    exit_code = 3
