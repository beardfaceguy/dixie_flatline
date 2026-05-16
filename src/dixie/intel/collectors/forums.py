"""Dark web and underground forum scraper.

Supports both clearnet and Tor (.onion) forums. When Tor is available,
routes requests through the local SOCKS5 proxy at 127.0.0.1:9050.

Forum configs are declarative: each forum specifies its URL, page structure,
and CSS/regex selectors for extracting posts.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

logger = logging.getLogger(__name__)

TOR_PROXY = "socks5h://127.0.0.1:9050"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8,zh;q=0.7",
}


@dataclass
class ForumConfig:
    name: str
    base_url: str
    pages: list[str]  # relative paths to scrape (e.g. recent exploit threads)
    language: str = "en"
    requires_tor: bool = False
    post_pattern: str = ""  # regex to extract post titles/content
    link_pattern: str = ""  # regex to extract post links
    encoding: str = "utf-8"
    tags: list[str] = field(default_factory=list)


FORUM_CONFIGS = [
    ForumConfig(
        name="DarkForums",
        base_url="https://darkforums.io",
        pages=[
            "/Forum-Leaks",
            "/Forum-Hacking",
            "/Forum-Programming",
        ],
        language="en",
        requires_tor=False,
        post_pattern=r'<span[^>]*class="subject_[^"]*"[^>]*>\s*<a[^>]*href="([^"]*)"[^>]*>([^<]+)</a>',
        tags=["darkforums", "leak", "exploit"],
    ),
    ForumConfig(
        name="cnblackhat",
        base_url="https://bbs.cnblackhat.com",
        pages=[
            "/forum.php?mod=forumdisplay&fid=2",  # network security
            "/forum.php?mod=forumdisplay&fid=6",  # exploit trading
        ],
        language="zh",
        requires_tor=False,
        post_pattern=r'<a[^>]*href="([^"]*)"[^>]*class="s xst"[^>]*>([^<]+)</a>',
        tags=["chinese", "blackhat"],
    ),
    ForumConfig(
        name="XSS.is",
        base_url="",  # .onion URL must be configured at runtime
        pages=[],
        language="ru",
        requires_tor=True,
        post_pattern=r'<a[^>]*href="([^"]*)"[^>]*data-preview-url[^>]*>([^<]+)</a>',
        tags=["russian", "xss_forum"],
    ),
    ForumConfig(
        name="Exploit.in",
        base_url="",  # .onion URL must be configured at runtime
        pages=[],
        language="ru",
        requires_tor=True,
        post_pattern=r'<a[^>]*href="([^"]*threads/[^"]*)"[^>]*>([^<]+)</a>',
        tags=["russian", "exploit_forum"],
    ),
]


class ForumCollector(Collector):
    source = IntelSource.FORUM
    name = "Underground Forums"

    def __init__(
        self,
        configs: list[ForumConfig] | None = None,
        use_tor: bool = False,
        onion_urls: dict[str, str] | None = None,
    ) -> None:
        self.configs = configs or [c for c in FORUM_CONFIGS if not c.requires_tor or use_tor]
        self.use_tor = use_tor
        self.onion_urls = onion_urls or {}

        # Apply runtime .onion URLs
        for config in self.configs:
            if config.name in self.onion_urls and config.requires_tor:
                config.base_url = self.onion_urls[config.name]

    def _get_client(self, requires_tor: bool) -> httpx.Client:
        kwargs: dict = {
            "headers": HEADERS,
            "timeout": 60,
            "follow_redirects": True,
        }
        if requires_tor and self.use_tor:
            kwargs["proxy"] = TOR_PROXY
        return httpx.Client(**kwargs)

    def fetch(self) -> list[ThreatEntry]:
        entries = []

        for config in self.configs:
            if not config.base_url:
                continue
            try:
                forum_entries = self._scrape_forum(config)
                entries.extend(forum_entries)
            except Exception as e:
                logger.warning("Forum collector failed for %s: %s", config.name, e)
                continue

        return entries

    def _scrape_forum(self, config: ForumConfig) -> list[ThreatEntry]:
        entries = []
        client = self._get_client(config.requires_tor)

        try:
            for page_path in config.pages:
                url = f"{config.base_url}{page_path}"
                resp = client.get(url)
                resp.raise_for_status()

                html = resp.text
                posts = self._extract_posts(html, config)
                entries.extend(posts)
        finally:
            client.close()

        return entries

    def _extract_posts(self, html: str, config: ForumConfig) -> list[ThreatEntry]:
        entries = []

        if not config.post_pattern:
            return self._extract_generic(html, config)

        matches = re.findall(config.post_pattern, html)

        for link, title in matches:
            title = _strip_html(title).strip()
            if not title or len(title) < 5:
                continue

            if link.startswith("/"):
                link = f"{config.base_url}{link}"

            entry_id = f"forum:{config.name}:{_slug(title)}"
            cve_match = re.search(r"CVE-\d{4}-\d+", title)

            maturity = ExploitMaturity.RUMORED
            lower = title.lower()
            if any(w in lower for w in ("exploit", "0day", "zero-day", "rce", "poc")):
                maturity = ExploitMaturity.POC

            entries.append(ThreatEntry(
                id=entry_id,
                cve_id=cve_match.group(0) if cve_match else None,
                title=title[:200],
                description=title,
                exploit_maturity=maturity,
                source=IntelSource.FORUM,
                source_url=link,
                language=config.language,
                raw_text=title if config.language != "en" else None,
                first_seen=datetime.now(timezone.utc),
                last_updated=datetime.now(timezone.utc),
                tags=config.tags,
            ))

        return entries

    def _extract_generic(self, html: str, config: ForumConfig) -> list[ThreatEntry]:
        """Fallback extraction: find all links with security-related keywords."""
        entries = []
        keywords = re.compile(
            r"(exploit|vuln|cve-\d{4}|0day|zero.?day|rce|sqli|xss|bypass|shell|backdoor|rootkit)",
            re.IGNORECASE,
        )

        links = re.findall(r'<a[^>]*href="([^"]*)"[^>]*>([^<]+)</a>', html)
        for link, title in links:
            title = _strip_html(title).strip()
            if not keywords.search(title):
                continue

            if link.startswith("/"):
                link = f"{config.base_url}{link}"

            entry_id = f"forum:{config.name}:{_slug(title)}"
            cve_match = re.search(r"CVE-\d{4}-\d+", title)

            entries.append(ThreatEntry(
                id=entry_id,
                cve_id=cve_match.group(0) if cve_match else None,
                title=title[:200],
                description=title,
                exploit_maturity=ExploitMaturity.RUMORED,
                source=IntelSource.FORUM,
                source_url=link,
                language=config.language,
                raw_text=title if config.language != "en" else None,
                first_seen=datetime.now(timezone.utc),
                last_updated=datetime.now(timezone.utc),
                tags=config.tags,
            ))

        return entries


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text).strip()


def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower().strip())[:80]
