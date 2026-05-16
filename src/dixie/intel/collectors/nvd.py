"""NVD (National Vulnerability Database) CVE API collector.

Uses the NVD 2.0 API for delta updates: fetches CVEs modified since
the last successful run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdCollector(Collector):
    source = IntelSource.NVD
    name = "NVD CVE API"

    def __init__(self, api_key: str | None = None, days_back: int = 1) -> None:
        self.api_key = api_key
        self.days_back = days_back

    def fetch(self) -> list[ThreatEntry]:
        since = datetime.now(timezone.utc) - timedelta(days=self.days_back)
        params: dict = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "lastModEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "resultsPerPage": 200,
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        resp = httpx.get(NVD_API, params=params, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        entries = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            cvss = _extract_cvss(cve.get("metrics", {}))

            entries.append(ThreatEntry(
                id=f"nvd:{cve_id}",
                cve_id=cve_id,
                title=cve_id,
                description=desc,
                severity=cvss,
                exploit_maturity=ExploitMaturity.RUMORED,
                source=IntelSource.NVD,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                first_seen=_parse_iso(cve.get("published")),
                last_updated=_parse_iso(cve.get("lastModified")),
                tags=_extract_cwes(cve.get("weaknesses", [])),
            ))

        return entries


def _extract_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            return metric_list[0].get("cvssData", {}).get("baseScore")
    return None


def _extract_cwes(weaknesses: list) -> list[str]:
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return cwes


def _parse_iso(date_str: str | None) -> datetime:
    if not date_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
