"""Government breach notification collectors.

Fetches public breach data from government sources:
- HHS Breach Portal (Healthcare "Wall of Shame") - free, no auth
- State AG breach notifications (where available)

All sources are free public data with no API keys required.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import ClassVar

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import IntelSource, ThreatEntry

logger = logging.getLogger(__name__)

# HHS Breach Portal API endpoints
HHS_BREACH_REPORT_URL = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"
HHS_API_BASE = "https://ocrportal.hhs.gov/ocr/rest/breachreports"


class HHSBreachCollector(Collector):
    """Collect healthcare breach data from HHS OCR Breach Portal.

    The HHS Breach Portal ("Wall of Shame") tracks breaches affecting 500+
    individuals reported to HHS under HIPAA. All data is public.

    No API key required. Data includes:
    - Covered entity name and state
    - Breach submission date
    - Individuals affected
    - Breach type (hacking/IT incident, theft, loss, unauthorized access)
    - Location of breached information
    """

    source = IntelSource.GOV_BREACH
    name = "HHS Breach Portal"

    # HHS breach type mapping to tags
    BREACH_TYPE_TAGS: ClassVar[dict[str, str]] = {
        "Hacking/IT Incident": "hacking_it",
        "Theft": "theft",
        "Loss": "loss",
        "Improper Disposal": "improper_disposal",
        "Unauthorized Access/Disclosure": "unauthorized_access",
    }

    def fetch(self) -> list[ThreatEntry]:
        """Fetch breach reports from HHS OCR API."""
        # HHS uses a REST API that returns breach reports
        # Try multiple endpoints as the structure may vary
        endpoints = [
            HHS_API_BASE,
            f"{HHS_API_BASE}/active",
            f"{HHS_API_BASE}/archived",
        ]

        all_entries = []
        for endpoint in endpoints:
            try:
                entries = self._fetch_endpoint(endpoint)
                all_entries.extend(entries)
            except Exception as e:
                logger.warning("Failed to fetch from %s: %s", endpoint, e)

        # Deduplicate by ID
        seen = set()
        unique_entries = []
        for entry in all_entries:
            if entry.id not in seen:
                seen.add(entry.id)
                unique_entries.append(entry)

        return unique_entries

    def _fetch_endpoint(self, url: str) -> list[ThreatEntry]:
        """Fetch from a specific HHS endpoint."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "DixieFlatline-SecurityResearch/1.0",
        }

        resp = httpx.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        entries = []
        # Handle various response structures
        breaches = data if isinstance(data, list) else data.get("breaches", [])

        for breach in breaches:
            breach_id = str(breach.get("id", breach.get("report_number", "unknown")))
            entity = breach.get("covered_entity", breach.get("name", "Unknown"))

            # Parse affected count
            affected = breach.get("individuals_affected", 0)
            if isinstance(affected, str):
                try:
                    affected = int(affected.replace(",", ""))
                except ValueError:
                    affected = 0

            breach_type = breach.get("breach_type", "Unknown")
            tags = self._build_tags(breach_type, affected)

            entries.append(
                ThreatEntry(
                    id=f"hhs:{breach_id}",
                    title=f"Healthcare Breach: {entity}",
                    description=self._build_description(breach),
                    source=IntelSource.GOV_BREACH,
                    source_url=HHS_BREACH_REPORT_URL,
                    first_seen=self._parse_date(breach.get("breach_submission_date")),
                    last_updated=datetime.now(timezone.utc),
                    tags=tags,
                    affected_products=[
                        f"entity:{entity}",
                        f"state:{breach.get('state', 'Unknown')}",
                        f"affected:{affected}",
                        f"type:{breach_type}",
                    ],
                )
            )

        return entries

    def _build_tags(self, breach_type: str, affected: int) -> list[str]:
        """Build tags from breach metadata."""
        tags = ["healthcare", "hipaa", "government_source"]

        # Add breach type tag
        type_tag = self.BREACH_TYPE_TAGS.get(breach_type, "unknown_type")
        tags.append(type_tag)

        # Severity based on affected count
        if affected >= 500000:
            tags.append("massive_breach")
        elif affected >= 100000:
            tags.append("large_breach")
        elif affected >= 10000:
            tags.append("medium_breach")
        else:
            tags.append("small_breach")

        return tags

    def _build_description(self, breach: dict) -> str:
        """Build description from breach data."""
        parts = [
            f"Covered Entity: {breach.get('covered_entity', 'Unknown')}",
            f"Breach Type: {breach.get('breach_type', 'Unknown')}",
            f"Individuals Affected: {breach.get('individuals_affected', 'Unknown')}",
            f"Location: {breach.get('location', 'Unknown')}",
        ]
        if breach.get("description"):
            parts.append(f"Details: {breach['description'][:500]}")

        return "\n".join(parts)

    def _parse_date(self, date_str: str | None) -> datetime:
        """Parse various date formats from HHS."""
        if not date_str:
            return datetime.now(timezone.utc)

        formats = [
            "%Y-%m-%d",
            "%m/%d/%Y",
            "%m/%d/%y",
            "%B %d, %Y",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue

        return datetime.now(timezone.utc)


class GovernmentBreachAggregator(Collector):
    """Aggregate breach data from multiple government sources.

    Combines HHS healthcare breaches with other government sources
    as they become available (state AG portals, CISA notifications, etc.).
    """

    source = IntelSource.GOV_BREACH
    name = "Government Breach Aggregator"

    def __init__(self):
        self.collectors: list[Collector] = [
            HHSBreachCollector(),
            # Future collectors:
            # - StateAGBreachCollector()
            # - CSISABreachCollector()
        ]

    def fetch(self) -> list[ThreatEntry]:
        """Fetch from all government sources."""
        all_entries = []

        for collector in self.collectors:
            try:
                entries = collector.fetch()
                all_entries.extend(entries)
                logger.info(
                    "%s: fetched %d entries", collector.name, len(entries)
                )
            except Exception as e:
                logger.error("%s failed: %s", collector.name, e)

        return all_entries
