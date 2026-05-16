"""Base class for threat intelligence feed collectors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from dixie.intel.schema import FeedStatus, IntelSource, ThreatEntry
from dixie.intel.store import IntelStore

logger = logging.getLogger(__name__)


class Collector(ABC):
    """Base class for all feed collectors.

    Subclasses implement fetch() to pull entries from their source.
    The run() method handles error tracking, deduplication via the store,
    and feed status updates.
    """

    source: IntelSource
    name: str

    @abstractmethod
    def fetch(self) -> list[ThreatEntry]:
        """Fetch new entries from the source. May raise on failure."""

    def run(self, store: IntelStore) -> FeedStatus:
        """Execute the collector and update the store."""
        status = FeedStatus(source=self.source)

        try:
            entries = self.fetch()
            new, updated = store.bulk_upsert(entries)
            total = store._conn.execute(
                "SELECT COUNT(*) FROM threat_entries WHERE source = ?",
                (self.source.value,),
            ).fetchone()[0]

            status.last_success = datetime.now(timezone.utc)
            status.entries_last_run = new
            status.entries_total = total
            status.consecutive_failures = 0

            logger.info(
                "%s: %d new, %d updated, %d total",
                self.name, new, updated, total,
            )

        except Exception as e:
            status.last_failure = datetime.now(timezone.utc)
            status.last_error = f"{type(e).__name__}: {e}"
            status.consecutive_failures += 1
            logger.error("%s: failed: %s", self.name, e)

        store.update_feed_status(status)
        return status
