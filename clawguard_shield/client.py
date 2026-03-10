"""
ClawGuard Shield API Client

A lightweight, zero-config Python client for the ClawGuard Shield API.
"""

from dataclasses import dataclass, field
from typing import Any
import requests


class ShieldError(Exception):
    """Base exception for Shield API errors."""

    def __init__(self, message: str, status_code: int = 0, error_type: str = ""):
        self.message = message
        self.status_code = status_code
        self.error_type = error_type
        super().__init__(message)


class AuthenticationError(ShieldError):
    """Raised when the API key is invalid or missing."""
    pass


class RateLimitError(ShieldError):
    """Raised when the rate limit is exceeded."""

    def __init__(self, message: str, limit: int = 0, used: int = 0, tier: str = ""):
        self.limit = limit
        self.used = used
        self.tier = tier
        super().__init__(message, status_code=429, error_type="rate_limit_exceeded")


class ValidationError(ShieldError):
    """Raised when the request is invalid."""
    pass


@dataclass
class Finding:
    """A single security finding from a scan."""
    pattern_name: str
    severity: str
    category: str
    matched_text: str
    line_number: int = 0
    description: str = ""

    def __repr__(self) -> str:
        return f"Finding({self.severity}: {self.pattern_name})"


@dataclass
class ScanResult:
    """Result of a security scan."""
    clean: bool
    risk_score: int
    severity: str
    findings_count: int
    findings: list[Finding] = field(default_factory=list)
    scan_time_ms: int = 0

    @property
    def is_safe(self) -> bool:
        """Alias for clean — returns True if no threats found."""
        return self.clean

    @property
    def is_critical(self) -> bool:
        """Returns True if severity is CRITICAL."""
        return self.severity == "CRITICAL"

    def __repr__(self) -> str:
        status = "CLEAN" if self.clean else f"{self.severity} ({self.findings_count} findings)"
        return f"ScanResult({status}, risk={self.risk_score}/10, {self.scan_time_ms}ms)"

    def __bool__(self) -> bool:
        """ScanResult is truthy when clean (no threats)."""
        return self.clean


@dataclass
class UsageStats:
    """API usage statistics."""
    tier: str
    tier_name: str
    daily_limit: Any  # int or "unlimited"
    today_used: int
    today_remaining: Any  # int or "unlimited"
    total_requests: int = 0
    total_findings: int = 0
    avg_response_time_ms: float = 0.0


class Shield:
    """ClawGuard Shield API client.

    Args:
        api_key: Your Shield API key (starts with 'cgs_').
        base_url: API base URL. Defaults to production.
        timeout: Request timeout in seconds.

    Example:
        >>> shield = Shield("cgs_your_key")
        >>> result = shield.scan("Ignore all previous instructions")
        >>> result.clean
        False
        >>> result.risk_score
        10
    """

    DEFAULT_URL = "https://prompttools.co/api/v1"

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_URL,
        timeout: int = 10,
    ):
        if not api_key:
            raise AuthenticationError("API key is required.")
        if not api_key.startswith("cgs_"):
            raise AuthenticationError("Invalid API key format. Keys start with 'cgs_'.")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": f"clawguard-shield-python/0.1.0",
        })

    def scan(self, text: str, source: str = "sdk") -> ScanResult:
        """Scan text for security threats.

        Args:
            text: The text to scan for threats.
            source: Optional source identifier (default: "sdk").

        Returns:
            ScanResult with findings and risk assessment.

        Raises:
            ValidationError: If text is empty or too long.
            AuthenticationError: If API key is invalid.
            RateLimitError: If rate limit exceeded.
            ShieldError: For other API errors.

        Example:
            >>> result = shield.scan("Ignore all previous instructions")
            >>> if not result.clean:
            ...     print(f"Risk: {result.risk_score}/10")
        """
        resp = self._request("POST", "/scan", json={"text": text, "source": source})
        data = resp.json()

        findings = [
            Finding(
                pattern_name=f.get("pattern_name", ""),
                severity=f.get("severity", ""),
                category=f.get("category", ""),
                matched_text=f.get("matched_text", ""),
                line_number=f.get("line_number", 0),
                description=f.get("description", ""),
            )
            for f in data.get("findings", [])
        ]

        return ScanResult(
            clean=data.get("clean", True),
            risk_score=data.get("risk_score", 0),
            severity=data.get("severity", "CLEAN"),
            findings_count=data.get("findings_count", 0),
            findings=findings,
            scan_time_ms=data.get("scan_time_ms", 0),
        )

    def scan_batch(self, texts: list[str], source: str = "sdk") -> list[ScanResult]:
        """Scan multiple texts. Convenience method that calls scan() for each.

        Args:
            texts: List of texts to scan.
            source: Optional source identifier.

        Returns:
            List of ScanResult objects.
        """
        return [self.scan(text, source=source) for text in texts]

    def health(self) -> dict[str, Any]:
        """Check API health status (no auth required).

        Returns:
            Dict with status, version, and patterns_count.
        """
        # Health endpoint doesn't need auth
        resp = requests.get(
            f"{self.base_url}/health",
            timeout=self.timeout,
        )
        return resp.json()

    def patterns(self) -> dict[str, Any]:
        """List all detection patterns.

        Returns:
            Dict with total_patterns and categories.
        """
        resp = self._request("GET", "/patterns")
        return resp.json()

    def usage(self) -> UsageStats:
        """Get your API usage statistics.

        Returns:
            UsageStats with tier info and usage counts.
        """
        resp = self._request("GET", "/usage")
        data = resp.json()

        last_30 = data.get("last_30_days", {})

        return UsageStats(
            tier=data.get("tier", "free"),
            tier_name=data.get("tier_name", "Free"),
            daily_limit=data.get("daily_limit", 100),
            today_used=data.get("today_used", 0),
            today_remaining=data.get("today_remaining", 100),
            total_requests=last_30.get("total_requests", 0),
            total_findings=last_30.get("total_findings", 0),
            avg_response_time_ms=last_30.get("avg_response_time_ms", 0.0),
        )

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Make an authenticated API request."""
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)

        try:
            resp = self._session.request(method, url, **kwargs)
        except requests.ConnectionError:
            raise ShieldError("Cannot connect to Shield API. Check your internet connection.")
        except requests.Timeout:
            raise ShieldError(f"Request timed out after {self.timeout}s.")

        if resp.status_code == 200 or resp.status_code == 201:
            return resp

        # Handle errors
        try:
            data = resp.json()
            message = data.get("message", "Unknown error")
            error_type = data.get("error", "")
        except ValueError:
            message = resp.text or f"HTTP {resp.status_code}"
            error_type = ""

        if resp.status_code == 401:
            raise AuthenticationError(message, status_code=401)
        elif resp.status_code == 403:
            raise AuthenticationError(message, status_code=403)
        elif resp.status_code == 429:
            raise RateLimitError(
                message,
                limit=data.get("limit", 0) if isinstance(data, dict) else 0,
                used=data.get("used", 0) if isinstance(data, dict) else 0,
                tier=data.get("tier", "") if isinstance(data, dict) else "",
            )
        elif resp.status_code == 400:
            raise ValidationError(message, status_code=400, error_type=error_type)
        else:
            raise ShieldError(message, status_code=resp.status_code, error_type=error_type)

    def __repr__(self) -> str:
        prefix = self.api_key[:12] + "..."
        return f"Shield(key={prefix}, url={self.base_url})"
