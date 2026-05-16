"""CISA Known Exploited Vulnerabilities (KEV) catalog collector."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevCollector(Collector):
    source = IntelSource.CISA_KEV
    name = "CISA KEV"

    def fetch(self) -> list[ThreatEntry]:
        resp = httpx.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        entries = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            entries.append(ThreatEntry(
                id=f"kev:{cve_id}",
                cve_id=cve_id,
                title=f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}: {vuln.get('vulnerabilityName', '')}",
                description=vuln.get("shortDescription", ""),
                exploit_maturity=ExploitMaturity.ACTIVELY_EXPLOITED,
                affected_products=[
                    f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}".strip()
                ],
                source=IntelSource.CISA_KEV,
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                first_seen=_parse_date(vuln.get("dateAdded", "")),
                last_updated=_parse_date(vuln.get("dateAdded", "")),
                tags=["kev", "actively_exploited"],
            ))

        return entries


def _parse_date(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
