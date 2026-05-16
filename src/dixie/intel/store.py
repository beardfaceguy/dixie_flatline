"""SQLite-backed threat intelligence store with deduplication."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dixie.intel.schema import ExploitMaturity, FeedStatus, IntelSource, ThreatEntry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_entries (
    id TEXT PRIMARY KEY,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity REAL,
    epss_score REAL,
    exploit_maturity TEXT NOT NULL DEFAULT 'rumored',
    affected_products TEXT NOT NULL DEFAULT '[]',
    attack_technique TEXT,
    exploit_url TEXT,
    source TEXT NOT NULL,
    source_url TEXT,
    language TEXT NOT NULL DEFAULT 'en',
    raw_text TEXT,
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_cve_id ON threat_entries(cve_id);
CREATE INDEX IF NOT EXISTS idx_source ON threat_entries(source);
CREATE INDEX IF NOT EXISTS idx_severity ON threat_entries(severity);
CREATE INDEX IF NOT EXISTS idx_first_seen ON threat_entries(first_seen);
CREATE INDEX IF NOT EXISTS idx_exploit_maturity ON threat_entries(exploit_maturity);

CREATE TABLE IF NOT EXISTS feed_status (
    source TEXT PRIMARY KEY,
    last_success TEXT,
    last_failure TEXT,
    last_error TEXT,
    entries_total INTEGER NOT NULL DEFAULT 0,
    entries_last_run INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);
"""


class IntelStore:
    """Persistent threat intelligence database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def upsert(self, entry: ThreatEntry) -> bool:
        """Insert or update a threat entry. Returns True if new, False if updated."""
        existing = self._conn.execute(
            "SELECT id FROM threat_entries WHERE id = ?", (entry.id,)
        ).fetchone()

        self._conn.execute(
            """INSERT OR REPLACE INTO threat_entries
            (id, cve_id, title, description, severity, epss_score, exploit_maturity,
             affected_products, attack_technique, exploit_url, source, source_url,
             language, raw_text, first_seen, last_updated, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.id,
                entry.cve_id,
                entry.title,
                entry.description,
                entry.severity,
                entry.epss_score,
                entry.exploit_maturity.value,
                json.dumps(entry.affected_products),
                entry.attack_technique,
                entry.exploit_url,
                entry.source.value,
                entry.source_url,
                entry.language,
                entry.raw_text,
                entry.first_seen.isoformat(),
                entry.last_updated.isoformat(),
                json.dumps(entry.tags),
            ),
        )
        self._conn.commit()
        return existing is None

    def bulk_upsert(self, entries: list[ThreatEntry]) -> tuple[int, int]:
        """Bulk upsert entries. Returns (new_count, updated_count)."""
        new_count = 0
        updated_count = 0
        for entry in entries:
            if self.upsert(entry):
                new_count += 1
            else:
                updated_count += 1
        return new_count, updated_count

    def query(
        self,
        *,
        cve_id: str | None = None,
        product: str | None = None,
        min_severity: float | None = None,
        source: IntelSource | None = None,
        maturity: ExploitMaturity | None = None,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[ThreatEntry]:
        """Query the intelligence store with filters."""
        conditions = []
        params: list = []

        if cve_id:
            conditions.append("cve_id = ?")
            params.append(cve_id)
        if product:
            conditions.append("affected_products LIKE ?")
            params.append(f"%{product}%")
        if min_severity is not None:
            conditions.append("severity >= ?")
            params.append(min_severity)
        if source:
            conditions.append("source = ?")
            params.append(source.value)
        if maturity:
            conditions.append("exploit_maturity = ?")
            params.append(maturity.value)
        if since:
            conditions.append("first_seen >= ?")
            params.append(since.isoformat())

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self._conn.execute(
            f"SELECT * FROM threat_entries {where} ORDER BY first_seen DESC LIMIT ?",
            params + [limit],
        ).fetchall()

        return [self._row_to_entry(row) for row in rows]

    def get_critical_recent(self, hours: int = 24) -> list[ThreatEntry]:
        """Get critical findings from the last N hours (CVSS >= 9.0 or actively exploited)."""
        rows = self._conn.execute(
            """SELECT * FROM threat_entries
            WHERE (severity >= 9.0 OR exploit_maturity = 'actively_exploited')
            AND first_seen >= datetime('now', ?)
            ORDER BY severity DESC, first_seen DESC""",
            (f"-{hours} hours",),
        ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def stats(self) -> dict:
        """Summary statistics about the intelligence store."""
        total = self._conn.execute("SELECT COUNT(*) FROM threat_entries").fetchone()[0]
        by_source = dict(
            self._conn.execute(
                "SELECT source, COUNT(*) FROM threat_entries GROUP BY source"
            ).fetchall()
        )
        by_maturity = dict(
            self._conn.execute(
                "SELECT exploit_maturity, COUNT(*) FROM threat_entries GROUP BY exploit_maturity"
            ).fetchall()
        )
        critical = self._conn.execute(
            "SELECT COUNT(*) FROM threat_entries WHERE severity >= 9.0"
        ).fetchone()[0]
        return {
            "total_entries": total,
            "by_source": by_source,
            "by_maturity": by_maturity,
            "critical_count": critical,
        }

    def update_feed_status(self, status: FeedStatus) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO feed_status
            (source, last_success, last_failure, last_error,
             entries_total, entries_last_run, consecutive_failures)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                status.source.value,
                status.last_success.isoformat() if status.last_success else None,
                status.last_failure.isoformat() if status.last_failure else None,
                status.last_error,
                status.entries_total,
                status.entries_last_run,
                status.consecutive_failures,
            ),
        )
        self._conn.commit()

    def get_feed_statuses(self) -> list[FeedStatus]:
        rows = self._conn.execute("SELECT * FROM feed_status").fetchall()
        return [
            FeedStatus(
                source=IntelSource(row["source"]),
                last_success=datetime.fromisoformat(row["last_success"])
                if row["last_success"]
                else None,
                last_failure=datetime.fromisoformat(row["last_failure"])
                if row["last_failure"]
                else None,
                last_error=row["last_error"],
                entries_total=row["entries_total"],
                entries_last_run=row["entries_last_run"],
                consecutive_failures=row["consecutive_failures"],
            )
            for row in rows
        ]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> ThreatEntry:
        return ThreatEntry(
            id=row["id"],
            cve_id=row["cve_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            epss_score=row["epss_score"],
            exploit_maturity=ExploitMaturity(row["exploit_maturity"]),
            affected_products=json.loads(row["affected_products"]),
            attack_technique=row["attack_technique"],
            exploit_url=row["exploit_url"],
            source=IntelSource(row["source"]),
            source_url=row["source_url"],
            language=row["language"],
            raw_text=row["raw_text"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_updated=datetime.fromisoformat(row["last_updated"]),
            tags=json.loads(row["tags"]),
        )
