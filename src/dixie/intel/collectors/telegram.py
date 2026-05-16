"""Telegram public channel collector via web preview scraping.

Uses Telegram's public web preview at t.me/s/{channel} to fetch
recent messages from public channels without requiring API credentials.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

DEFAULT_CHANNELS = [
    "zer0daylab",
    "malwr",
    "exploitin",
    "caboranobot",
    "ReverseEngineeringHQ",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class TelegramCollector(Collector):
    source = IntelSource.TELEGRAM
    name = "Telegram Channels"

    def __init__(self, channels: list[str] | None = None) -> None:
        self.channels = channels or DEFAULT_CHANNELS

    def fetch(self) -> list[ThreatEntry]:
        entries = []
        for channel in self.channels:
            try:
                channel_entries = self._fetch_channel(channel)
                entries.extend(channel_entries)
            except Exception:
                continue
        return entries

    def _fetch_channel(self, channel: str) -> list[ThreatEntry]:
        import time

        resp = None
        for attempt in range(3):
            try:
                resp = httpx.get(
                    f"https://t.me/s/{channel}",
                    headers=HEADERS,
                    timeout=30,
                    follow_redirects=True,
                )
                if resp.status_code == 429:
                    time.sleep(min(2 ** attempt * 5, 30))
                    continue
                resp.raise_for_status()
                break
            except httpx.HTTPStatusError:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise

        if resp is None or resp.status_code != 200:
            return []

        html = resp.text

        entries = []

        # Extract message blocks from the web preview HTML
        msg_pattern = re.compile(
            r'class="tgme_widget_message_wrap[^"]*"[^>]*data-post="([^"]+)"',
        )
        text_pattern = re.compile(
            r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
            re.DOTALL,
        )
        time_pattern = re.compile(
            r'<time[^>]*datetime="([^"]+)"',
        )

        post_ids = msg_pattern.findall(html)
        texts = text_pattern.findall(html)
        times = time_pattern.findall(html)

        for i, post_id in enumerate(post_ids):
            text = _strip_html(texts[i]) if i < len(texts) else ""
            if not text or len(text) < 10:
                continue

            timestamp = _parse_iso(times[i]) if i < len(times) else datetime.now(timezone.utc)

            cve_match = re.search(r"CVE-\d{4}-\d+", text)
            cve_id = cve_match.group(0) if cve_match else None

            maturity = ExploitMaturity.RUMORED
            lower = text.lower()
            if any(w in lower for w in ("exploit", "poc", "0day", "zero-day", "rce")):
                maturity = ExploitMaturity.POC
            if any(w in lower for w in ("actively exploited", "in the wild", "itw")):
                maturity = ExploitMaturity.ACTIVELY_EXPLOITED

            lang = _detect_language_hint(text)

            entries.append(ThreatEntry(
                id=f"tg:{post_id}",
                cve_id=cve_id,
                title=text[:120],
                description=text[:2000],
                exploit_maturity=maturity,
                source=IntelSource.TELEGRAM,
                source_url=f"https://t.me/{post_id}",
                language=lang,
                raw_text=text[:5000] if lang != "en" else None,
                first_seen=timestamp,
                last_updated=timestamp,
                tags=[f"channel:{channel}"],
            ))

        return entries


def _strip_html(html: str) -> str:
    text = re.sub(r"<br\s*/?>", "\n", html)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"&#39;", "'", text)
    return text.strip()


def _detect_language_hint(text: str) -> str:
    """Rough heuristic for language detection based on character ranges."""
    cyrillic = len(re.findall(r"[\u0400-\u04FF]", text))
    cjk = len(re.findall(r"[\u4E00-\u9FFF]", text))
    total = len(text)

    if total == 0:
        return "en"
    if cyrillic / total > 0.15:
        return "ru"
    if cjk / total > 0.10:
        return "zh"
    return "en"


def _parse_iso(date_str: str) -> datetime:
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)
