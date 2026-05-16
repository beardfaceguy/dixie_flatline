"""Data models for threat intelligence entries."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class IntelSource(str, Enum):
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    EXPLOIT_INTEL = "exploit_intel"
    MALWARE_PATROL = "malware_patrol"
    PACKETSTORM = "packetstorm"
    SPLOITUS = "sploitus"
    EXPLOIT_DB = "exploit_db"
    FULL_DISCLOSURE = "full_disclosure"
    TELEGRAM = "telegram"
    FORUM = "forum"
    REDDIT = "reddit"
    MANUAL = "manual"


class ExploitMaturity(str, Enum):
    RUMORED = "rumored"
    POC = "poc"
    WEAPONIZED = "weaponized"
    ACTIVELY_EXPLOITED = "actively_exploited"


class ThreatEntry(BaseModel):
    """A single piece of threat intelligence, normalized across all sources."""

    id: str  # internal dedup key: e.g. "nvd:CVE-2026-12345" or "packetstorm:218881"
    cve_id: str | None = None
    title: str
    description: str
    severity: float | None = None  # CVSS score
    epss_score: float | None = None
    exploit_maturity: ExploitMaturity = ExploitMaturity.RUMORED
    affected_products: list[str] = Field(default_factory=list)
    attack_technique: str | None = None  # MITRE ATT&CK ID
    exploit_url: str | None = None
    source: IntelSource
    source_url: str | None = None
    language: str = "en"
    raw_text: str | None = None  # original untranslated text for non-English sources
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list)


class FeedStatus(BaseModel):
    """Tracks health of each intelligence feed."""

    source: IntelSource
    last_success: datetime | None = None
    last_failure: datetime | None = None
    last_error: str | None = None
    entries_total: int = 0
    entries_last_run: int = 0
    consecutive_failures: int = 0
