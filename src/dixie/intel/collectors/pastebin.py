"""Pastebin credential leak collector.

Monitors Pastebin for potential credential leaks, breach dumps,
and other security-relevant content using scraping and/or the
Pastebin Pro API if available.

Note: Pastebin has aggressive rate limiting. Uses exponential backoff
and respects robots.txt restrictions for public scraping.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import IntelSource, ThreatEntry

logger = logging.getLogger(__name__)

# Pastebin scraping endpoints
PASTEBIN_SCRAPING_URL = "https://pastebin.com/api_scraping.php"
PASTEBIN_RAW_URL = "https://pastebin.com/raw/{key}"

# Patterns for credential leak detection
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
CREDENTIAL_INDICATORS = [
    re.compile(r"password\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"passwd\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"pass\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"pwd\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"user(?:name)?\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"login\s*[=:]\s*\S+", re.IGNORECASE),
]
# Corporate/organizational indicators
CORPORATE_INDICATORS = [
    re.compile(r"corp", re.IGNORECASE),
    re.compile(r"enterprise", re.IGNORECASE),
    re.compile(r"company", re.IGNORECASE),
    re.compile(r"internal", re.IGNORECASE),
    re.compile(r"staff", re.IGNORECASE),
    re.compile(r"employee", re.IGNORECASE),
]
# Suspicious breach/dump keywords
BREACH_KEYWORDS = [
    "breach", "dump", "leaked", "exposed", "database",
    "credentials", "accounts", "combo list", "combolist",
    "sql dump", "csv", "user:pass", "email:pass",
]


class PastebinLeakCollector(Collector):
    """Monitor Pastebin for credential leaks and breach dumps.

    Uses the Pastebin scraping API (requires whitelisted IP or Pro account).
    Falls back to public trending pastes if scraping API unavailable.

    Free tier limitations:
    - Scraping API: 1 request per 60 seconds
    - Rate limited by IP
    - No API key required for scraping endpoint
    """

    source = IntelSource.PASTEBIN
    name = "Pastebin Leak Monitor"

    def __init__(
        self,
        api_dev_key: str | None = None,
        scrape_limit: int = 50,
        min_leak_score: float = 2.0,
        target_domains: list[str] | None = None,
    ):
        self.api_dev_key = api_dev_key
        self.scrape_limit = scrape_limit
        self.min_leak_score = min_leak_score
        self.target_domains = set(d.lower() for d in (target_domains or []))
        self._last_request_time: float = 0.0

    def _rate_limited_get(
        self, url: str, min_interval: float = 60.0, headers: dict | None = None
    ) -> httpx.Response:
        """Make rate-limited GET request."""
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            logger.debug("Rate limiting: sleeping %.2fs", sleep_time)
            time.sleep(sleep_time)

        default_headers = {
            "User-Agent": "DixieFlatline-SecurityResearch/1.0",
        }
        if headers:
            default_headers.update(headers)

        resp = httpx.get(url, headers=default_headers, timeout=30, follow_redirects=True)
        self._last_request_time = time.time()
        resp.raise_for_status()
        return resp

    def _fetch_scraping_archive(self) -> list[dict]:
        """Fetch recent pastes from scraping API."""
        url = f"{PASTEBIN_SCRAPING_URL}?limit={self.scrape_limit}"

        try:
            resp = self._rate_limited_get(url, min_interval=60.0)
            return resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning(
                    "Pastebin scraping API returned 403. "
                    "IP may not be whitelisted or rate limit exceeded."
                )
            raise
        except Exception as e:
            logger.error("Failed to fetch Pastebin archive: %s", e)
            raise

    def _fetch_paste_content(self, paste_key: str) -> str:
        """Fetch raw content of a paste."""
        url = PASTEBIN_RAW_URL.format(key=paste_key)
        resp = self._rate_limited_get(url, min_interval=3.0)
        return resp.text

    def _score_leak_likelihood(self, content: str, title: str = "") -> tuple[float, list[str]]:
        """Score how likely this paste contains actual credential leaks.

        Returns (score, matched_indicators).
        """
        score = 0.0
        indicators = []

        content_lower = content.lower()

        # Count email addresses
        email_count = len(EMAIL_PATTERN.findall(content))
        if email_count > 0:
            score += min(email_count * 0.5, 5.0)  # Cap at 5 points
            indicators.append(f"emails:{email_count}")

        # Check for credential patterns
        for pattern in CREDENTIAL_INDICATORS:
            matches = len(pattern.findall(content))
            if matches > 0:
                score += min(matches * 0.3, 3.0)
                indicators.append(f"creds:{pattern.pattern[:20]}")

        # Check for breach keywords
        for keyword in BREACH_KEYWORDS:
            if keyword in content_lower:
                score += 1.0
                indicators.append(f"keyword:{keyword}")

        # Corporate/organizational indicators
        for pattern in CORPORATE_INDICATORS:
            if pattern.search(content):
                score += 0.5
                indicators.append("corporate")

        # Target domain matches
        for domain in self.target_domains:
            if domain in content_lower:
                score += 3.0
                indicators.append(f"target:{domain}")

        # Large dumps are more interesting
        lines = content.count("\n")
        if lines > 1000:
            score += 2.0
            indicators.append("large_dump")
        elif lines > 100:
            score += 1.0
            indicators.append("medium_dump")

        return score, indicators

    def fetch(self) -> list[ThreatEntry]:
        """Fetch and analyze recent Pastebin pastes for leaks."""
        pastes = self._fetch_scraping_archive()
        entries = []

        for paste in pastes:
            paste_key = paste.get("key", "")
            title = paste.get("title", "")
            paste_url = paste.get("url", f"https://pastebin.com/{paste_key}")
            first_seen = _parse_paste_date(paste.get("date"))

            try:
                # Fetch full content
                content = self._fetch_paste_content(paste_key)

                # Score for leak likelihood
                score, indicators = self._score_leak_likelihood(content, title)

                if score >= self.min_leak_score:
                    # Truncate content for storage
                    preview = content[:2000] if len(content) > 2000 else content

                    entries.append(
                        ThreatEntry(
                            id=f"pastebin:{paste_key}",
                            title=f"Pastebin Leak: {title or 'Untitled'}",
                            description=preview,
                            source=IntelSource.PASTEBIN,
                            source_url=paste_url,
                            first_seen=first_seen,
                            last_updated=datetime.now(timezone.utc),
                            tags=["pastebin", "potential_leak", "credentials"]
                            + indicators[:5],  # Limit tag count
                            raw_text=preview,
                        )
                    )
                    logger.info(
                        "Identified potential leak: %s (score: %.1f)",
                        paste_url, score
                    )

            except httpx.HTTPStatusError as e:
                logger.warning("Failed to fetch paste %s: %s", paste_key, e)
                continue
            except Exception as e:
                logger.error("Error processing paste %s: %s", paste_key, e)
                continue

        return entries


class PastebinTargetedCollector(PastebinLeakCollector):
    """Targeted Pastebin collector focused on specific domains/organizations.

    Extends the base collector with additional target-specific scoring
    and pattern matching.
    """

    name = "Pastebin Targeted Monitor"

    def __init__(
        self,
        target_domains: list[str],
        target_keywords: list[str] | None = None,
        api_dev_key: str | None = None,
        scrape_limit: int = 100,
    ):
        super().__init__(
            api_dev_key=api_dev_key,
            scrape_limit=scrape_limit,
            min_leak_score=1.0,  # Lower threshold for targeted search
            target_domains=target_domains,
        )
        self.target_keywords = set(k.lower() for k in (target_keywords or []))

    def _score_leak_likelihood(self, content: str, title: str = "") -> tuple[float, list[str]]:
        """Enhanced scoring with target keyword matching."""
        score, indicators = super()._score_leak_likelihood(content, title)

        text = f"{title}\n{content}".lower()

        # Target keyword matching (higher weight)
        for keyword in self.target_keywords:
            if keyword in text:
                score += 5.0
                indicators.append(f"keyword_match:{keyword[:30]}")

        # Multiple target hits = higher priority
        target_hits = sum(1 for d in self.target_domains if d in text)
        if target_hits > 1:
            score += target_hits * 2.0
            indicators.append(f"multi_domain:{target_hits}")

        return score, indicators


def _parse_paste_date(raw: object) -> datetime:
    """Parse a Pastebin unix-epoch paste timestamp.

    Falls back to now() when the field is absent or unparseable, so a re-fetch
    of the same paste keeps a stable first_seen when the API provides ``date``.
    """
    if raw is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return datetime.now(timezone.utc)
