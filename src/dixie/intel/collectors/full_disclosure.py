"""Full Disclosure mailing list collector via seclists.org RSS."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

FEED_URL = "https://seclists.org/rss/fulldisclosure.rss"


class FullDisclosureCollector(Collector):
    source = IntelSource.FULL_DISCLOSURE
    name = "Full Disclosure Mailing List"

    def fetch(self) -> list[ThreatEntry]:
        resp = httpx.get(FEED_URL, timeout=30)
        resp.raise_for_status()

        root = ET.fromstring(resp.text)
        entries = []

        for item in root.findall(".//item"):
            title = item.findtext("title", "").strip()
            link = item.findtext("link", "").strip()
            description = item.findtext("description", "").strip()
            pub_date = item.findtext("pubDate", "")

            entry_id = f"fd:{_slug(title)}"

            cve_match = re.search(r"CVE-\d{4}-\d+", title + " " + description)
            cve_id = cve_match.group(0) if cve_match else None

            entries.append(ThreatEntry(
                id=entry_id,
                cve_id=cve_id,
                title=title,
                description=description[:2000],
                exploit_maturity=ExploitMaturity.POC if "exploit" in description.lower() else ExploitMaturity.RUMORED,
                source=IntelSource.FULL_DISCLOSURE,
                source_url=link,
                first_seen=_parse_rfc822(pub_date),
                last_updated=_parse_rfc822(pub_date),
                tags=["mailing_list", "disclosure"],
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
