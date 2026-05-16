"""Packet Storm Security collector via RSS feed."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

FEED_URLS = [
    "https://packetstormsecurity.com/feeds/currentexploits",
    "https://packetstormsecurity.com/feeds/current",
]


class PacketStormCollector(Collector):
    source = IntelSource.PACKETSTORM
    name = "Packet Storm Security"

    def fetch(self) -> list[ThreatEntry]:
        resp = None
        for url in FEED_URLS:
            try:
                resp = httpx.get(
                    url,
                    timeout=30,
                    follow_redirects=True,
                    headers={"User-Agent": "Dixie-Flatline/0.1 ThreatIntel"},
                )
                resp.raise_for_status()
                break
            except Exception:
                continue

        if resp is None:
            return []

        # Packet Storm feeds sometimes have malformed XML; try parsing
        # with recovery by stripping bad chars
        text = resp.text
        text = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;|#)", "&amp;", text)

        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            # Fall back to regex-based extraction
            return self._parse_fallback(text)
        entries = []

        for item in root.findall(".//item"):
            title = item.findtext("title", "").strip()
            link = item.findtext("link", "").strip()
            description = item.findtext("description", "").strip()
            pub_date = item.findtext("pubDate", "")

            file_id = re.search(r"/files/(\d+)/", link)
            entry_id = f"ps:{file_id.group(1)}" if file_id else f"ps:{_slug(title)}"

            cve_match = re.search(r"CVE-\d{4}-\d+", title + " " + description)
            cve_id = cve_match.group(0) if cve_match else None

            entries.append(ThreatEntry(
                id=entry_id,
                cve_id=cve_id,
                title=title,
                description=description[:2000],
                exploit_maturity=ExploitMaturity.POC,
                source=IntelSource.PACKETSTORM,
                source_url=link,
                exploit_url=link,
                first_seen=_parse_rfc822(pub_date),
                last_updated=_parse_rfc822(pub_date),
                tags=["exploit", "packetstorm"],
            ))

        return entries

    def _parse_fallback(self, text: str) -> list[ThreatEntry]:
        """Regex-based fallback for malformed XML feeds."""
        entries = []
        items = re.findall(
            r"<title>(.*?)</title>.*?<link>(.*?)</link>",
            text,
            re.DOTALL,
        )
        for title, link in items:
            title = title.strip()
            link = link.strip()
            if not title or "Packet Storm" in title:
                continue

            file_id = re.search(r"/files/(\d+)/", link)
            entry_id = f"ps:{file_id.group(1)}" if file_id else f"ps:{_slug(title)}"

            cve_match = re.search(r"CVE-\d{4}-\d+", title)
            cve_id = cve_match.group(0) if cve_match else None

            entries.append(ThreatEntry(
                id=entry_id,
                cve_id=cve_id,
                title=title,
                description=title,
                exploit_maturity=ExploitMaturity.POC,
                source=IntelSource.PACKETSTORM,
                source_url=link,
                exploit_url=link,
                first_seen=datetime.now(timezone.utc),
                last_updated=datetime.now(timezone.utc),
                tags=["exploit", "packetstorm"],
            ))

        return entries


def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower().strip())[:80]


def _parse_rfc822(date_str: str) -> datetime:
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(date_str).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
