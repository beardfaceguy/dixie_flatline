"""Have I Been Pwned (HIBP) breach data collector.

Free tier: No API key required for breach lookups.
Rate limit: 1.5 seconds between requests (enforced).
API docs: https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import IntelSource, ThreatEntry

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_USER_AGENT = "DixieFlatline-IntelCollector"
MIN_REQUEST_INTERVAL = 1.6  # HIBP requires 1.5s between requests


class HibpBreachCollector(Collector):
    """Collect breach data from Have I Been Pwned free API.

    No API key required for breach enumeration.
    Collects breach metadata including:
    - Breach name, description, date
    - Compromised data classes (email, password, etc.)
    - Pwned accounts count
    - Whether passwords are crackable
    """

    source = IntelSource.HIBP
    name = "Have I Been Pwned"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._last_request_time: float = 0.0

    def _rate_limited_get(self, url: str) -> httpx.Response:
        """Make rate-limited GET request to HIBP."""
        elapsed = time.time() - self._last_request_time
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)

        headers = {
            "User-Agent": HIBP_USER_AGENT,
            "Accept": "application/json",
        }
        if self.api_key:
            headers["hibp-api-key"] = self.api_key

        resp = httpx.get(url, headers=headers, timeout=30)
        self._last_request_time = time.time()
        resp.raise_for_status()
        return resp

    def fetch(self) -> list[ThreatEntry]:
        """Fetch all known breaches from HIBP."""
        resp = self._rate_limited_get(HIBP_BREACHES_URL)
        breaches = resp.json()

        entries = []
        for breach in breaches:
            breach_name = breach.get("Name", "unknown")
            entries.append(
                ThreatEntry(
                    id=f"hibp:{breach_name}",
                    title=f"Breach: {breach.get('Title', breach_name)}",
                    description=breach.get("Description", ""),
                    source=IntelSource.HIBP,
                    source_url=(
                        f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"
                        if breach.get("Domain")
                        else None
                    ),
                    first_seen=_parse_breach_date(breach.get("BreachDate", "")),
                    last_updated=datetime.now(timezone.utc),
                    tags=_build_tags(breach),
                    # Store breach-specific fields in affected_products for now
                    affected_products=[
                        f"domain:{breach.get('Domain', 'unknown')}",
                        f"accounts:{breach.get('PwnCount', 0)}",
                        f"data_classes:{','.join(breach.get('DataClasses', []))}",
                    ],
                )
            )

        return entries


def _parse_breach_date(date_str: str) -> datetime:
    """Parse YYYY-MM-DD breach date."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def _build_tags(breach: dict) -> list[str]:
    """Build tags from breach metadata."""
    tags = ["breach", "credential_leak"]

    if breach.get("IsVerified"):
        tags.append("verified")
    if breach.get("IsFabricated"):
        tags.append("fabricated")
    if breach.get("IsSensitive"):
        tags.append("sensitive")
    if breach.get("IsRetired"):
        tags.append("retired")
    if breach.get("IsSpamList"):
        tags.append("spam_list")

    # Add data class tags
    for dc in breach.get("DataClasses", []):
        tag = dc.lower().replace(" ", "_")
        tags.append(f"data:{tag}")

    return tags


class HibpDomainCollector(Collector):
    """Collect breach data for a specific domain (requires API key).

    This searches HIBP for breaches affecting a specific domain,
    useful when targeting an organization during engagement.
    """

    source = IntelSource.HIBP
    name = "HIBP Domain Search"

    def __init__(self, domain: str, api_key: str | None = None):
        self.domain = domain
        self.api_key = api_key
        self._last_request_time: float = 0.0

    def _rate_limited_get(self, url: str) -> httpx.Response:
        """Make rate-limited GET request to HIBP."""
        elapsed = time.time() - self._last_request_time
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)

        headers = {
            "User-Agent": HIBP_USER_AGENT,
            "Accept": "application/json",
        }
        if self.api_key:
            headers["hibp-api-key"] = self.api_key

        resp = httpx.get(url, headers=headers, timeout=30)
        self._last_request_time = time.time()
        resp.raise_for_status()
        return resp

    def fetch(self) -> list[ThreatEntry]:
        """Fetch breaches for the configured domain."""
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
        resp = self._rate_limited_get(url)
        breaches = resp.json()

        entries = []
        for breach in breaches:
            breach_name = breach.get("Name", "unknown")
            entries.append(
                ThreatEntry(
                    id=f"hibp:{self.domain}:{breach_name}",
                    title=f"Domain Breach: {self.domain} in {breach.get('Title', breach_name)}",
                    description=breach.get("Description", ""),
                    source=IntelSource.HIBP,
                    source_url=f"https://haveibeenpwned.com/api/v3/breach/{breach_name}",
                    first_seen=_parse_breach_date(breach.get("BreachDate", "")),
                    last_updated=datetime.now(timezone.utc),
                    tags=_build_tags(breach) + ["domain_targeted"],
                    affected_products=[
                        f"domain:{self.domain}",
                        f"breach:{breach_name}",
                        f"accounts:{breach.get('PwnCount', 0)}",
                        f"data_classes:{','.join(breach.get('DataClasses', []))}",
                    ],
                )
            )

        return entries
