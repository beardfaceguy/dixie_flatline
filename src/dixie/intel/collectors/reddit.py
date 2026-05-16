"""Reddit /r/netsec and /r/exploitdev collector via public JSON API."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx

from dixie.intel.collectors.base import Collector
from dixie.intel.schema import ExploitMaturity, IntelSource, ThreatEntry

SUBREDDITS = ["netsec", "exploitdev", "ReverseEngineering"]
HEADERS = {
    "User-Agent": "Dixie-Flatline/0.1 (threat intel aggregator; +https://github.com/dixie-flatline)",
    "Accept": "application/json",
}


class RedditCollector(Collector):
    source = IntelSource.REDDIT
    name = "Reddit Security Subs"

    def __init__(self, subreddits: list[str] | None = None, limit: int = 50) -> None:
        self.subreddits = subreddits or SUBREDDITS
        self.limit = limit

    def fetch(self) -> list[ThreatEntry]:
        entries = []

        for sub in self.subreddits:
            try:
                sub_entries = self._fetch_subreddit(sub)
                entries.extend(sub_entries)
            except Exception:
                continue

        return entries

    def _fetch_subreddit(self, subreddit: str) -> list[ThreatEntry]:
        import time

        urls = [
            f"https://www.reddit.com/r/{subreddit}/new.json",
            f"https://old.reddit.com/r/{subreddit}/new.json",
        ]

        resp = None
        for url in urls:
            for attempt in range(3):
                try:
                    resp = httpx.get(
                        url,
                        params={"limit": self.limit, "raw_json": 1},
                        headers=HEADERS,
                        timeout=30,
                    )
                    if resp.status_code == 429:
                        wait = min(2 ** attempt * 5, 30)
                        time.sleep(wait)
                        continue
                    resp.raise_for_status()
                    break
                except httpx.HTTPStatusError:
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                    raise
            if resp and resp.status_code == 200:
                break

        if resp is None or resp.status_code != 200:
            return []

        data = resp.json()

        entries = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            post_id = post.get("id", "")
            title = post.get("title", "")
            selftext = post.get("selftext", "")
            url = post.get("url", "")
            created = post.get("created_utc", 0)
            score = post.get("score", 0)

            if score < 2:
                continue

            cve_match = re.search(r"CVE-\d{4}-\d+", title + " " + selftext)
            cve_id = cve_match.group(0) if cve_match else None

            maturity = ExploitMaturity.RUMORED
            lower = (title + " " + selftext).lower()
            if any(w in lower for w in ("exploit", "poc", "proof of concept", "0day", "zero-day")):
                maturity = ExploitMaturity.POC

            entries.append(ThreatEntry(
                id=f"reddit:{subreddit}:{post_id}",
                cve_id=cve_id,
                title=title,
                description=selftext[:2000] if selftext else title,
                exploit_maturity=maturity,
                source=IntelSource.REDDIT,
                source_url=f"https://reddit.com/r/{subreddit}/comments/{post_id}",
                exploit_url=url if url != f"https://www.reddit.com/r/{subreddit}/comments/{post_id}/" else None,
                first_seen=datetime.fromtimestamp(created, tz=timezone.utc),
                last_updated=datetime.fromtimestamp(created, tz=timezone.utc),
                tags=[f"r/{subreddit}", f"score:{score}"],
            ))

        return entries
