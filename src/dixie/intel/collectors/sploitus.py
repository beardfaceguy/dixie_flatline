"""Sploitus exploit aggregator collector via RSS feed."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

FEED_URL = "https://sploitus.com/rss"


class SploitusCollector(Collector):
    source = IntelSource.SPLOITUS
    name = "Sploitus"

    def fetch(self) -> list[ThreatEntry]:
        resp = httpx.get(FEED_URL, timeout=30)
        resp.raise_for_status()

        root = ET.fromstring(resp.text)
        entries = []

        for item in root.findall(".//item"):
            title = item.findtext("title", "").strip()
            link = item.findtext("link", "").strip()
            guid = item.findtext("guid", "").strip()
            pub_date = item.findtext("pubDate", "")

            cve_match = re.search(r"CVE-\d{4}-\d+", title)
            cve_id = cve_match.group(0) if cve_match else None

            entries.append(ThreatEntry(
                id=f"sploitus:{guid}",
                cve_id=cve_id,
                title=title,
                description=title,
                exploit_maturity=ExploitMaturity.POC,
                source=IntelSource.SPLOITUS,
                source_url=link,
                exploit_url=link,
                first_seen=_parse_rfc822(pub_date),
                last_updated=_parse_rfc822(pub_date),
                tags=["exploit", "aggregated"],
            ))

        return entries


def _parse_rfc822(date_str: str) -> datetime:
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(date_str).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
