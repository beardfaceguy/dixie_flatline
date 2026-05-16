"""Tests for threat intelligence store and schema."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from dixie.intel.schema import ExploitMaturity, FeedStatus, IntelSource, ThreatEntry
from dixie.intel.store import IntelStore


def _make_entry(
    id: str = "test:1",
    cve_id: str = "CVE-2026-1234",
    title: str = "Test Vuln",
    severity: float = 7.5,
    maturity: ExploitMaturity = ExploitMaturity.POC,
    source: IntelSource = IntelSource.NVD,
    products: list[str] | None = None,
) -> ThreatEntry:
    return ThreatEntry(
        id=id,
        cve_id=cve_id,
        title=title,
        description="A test vulnerability",
        severity=severity,
        exploit_maturity=maturity,
        affected_products=products or [],
        source=source,
    )


class TestIntelStore:
    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self._tmpdir) / "test_intel.db"
        self.store = IntelStore(self.db_path)

    def teardown_method(self):
        self.store.close()

    def test_upsert_new(self):
        entry = _make_entry()
        is_new = self.store.upsert(entry)
        assert is_new is True

    def test_upsert_duplicate(self):
        entry = _make_entry()
        self.store.upsert(entry)
        is_new = self.store.upsert(entry)
        assert is_new is False

    def test_bulk_upsert(self):
        entries = [_make_entry(id=f"test:{i}") for i in range(5)]
        new, updated = self.store.bulk_upsert(entries)
        assert new == 5
        assert updated == 0

        new, updated = self.store.bulk_upsert(entries)
        assert new == 0
        assert updated == 5

    def test_query_by_cve(self):
        self.store.upsert(_make_entry(id="a", cve_id="CVE-2026-1111"))
        self.store.upsert(_make_entry(id="b", cve_id="CVE-2026-2222"))

        results = self.store.query(cve_id="CVE-2026-1111")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2026-1111"

    def test_query_by_product(self):
        self.store.upsert(_make_entry(id="a", products=["Apache httpd 2.4.52"]))
        self.store.upsert(_make_entry(id="b", products=["nginx 1.24"]))

        results = self.store.query(product="Apache")
        assert len(results) == 1
        assert "Apache" in results[0].affected_products[0]

    def test_query_by_severity(self):
        self.store.upsert(_make_entry(id="a", severity=9.8))
        self.store.upsert(_make_entry(id="b", severity=5.0))
        self.store.upsert(_make_entry(id="c", severity=3.0))

        results = self.store.query(min_severity=9.0)
        assert len(results) == 1
        assert results[0].severity == 9.8

    def test_query_by_source(self):
        self.store.upsert(_make_entry(id="a", source=IntelSource.NVD))
        self.store.upsert(_make_entry(id="b", source=IntelSource.CISA_KEV))

        results = self.store.query(source=IntelSource.CISA_KEV)
        assert len(results) == 1

    def test_query_by_maturity(self):
        self.store.upsert(_make_entry(id="a", maturity=ExploitMaturity.ACTIVELY_EXPLOITED))
        self.store.upsert(_make_entry(id="b", maturity=ExploitMaturity.POC))

        results = self.store.query(maturity=ExploitMaturity.ACTIVELY_EXPLOITED)
        assert len(results) == 1

    def test_stats(self):
        self.store.upsert(_make_entry(id="a", severity=9.8, source=IntelSource.NVD))
        self.store.upsert(_make_entry(id="b", severity=5.0, source=IntelSource.CISA_KEV))

        stats = self.store.stats()
        assert stats["total_entries"] == 2
        assert stats["critical_count"] == 1
        assert stats["by_source"]["nvd"] == 1
        assert stats["by_source"]["cisa_kev"] == 1

    def test_feed_status(self):
        status = FeedStatus(
            source=IntelSource.NVD,
            last_success=datetime.now(timezone.utc),
            entries_total=100,
            entries_last_run=5,
        )
        self.store.update_feed_status(status)

        statuses = self.store.get_feed_statuses()
        assert len(statuses) == 1
        assert statuses[0].source == IntelSource.NVD
        assert statuses[0].entries_total == 100

    def test_get_critical_recent(self):
        self.store.upsert(_make_entry(id="a", severity=9.8))
        self.store.upsert(_make_entry(id="b", severity=5.0))
        self.store.upsert(_make_entry(
            id="c", severity=7.0, maturity=ExploitMaturity.ACTIVELY_EXPLOITED
        ))

        critical = self.store.get_critical_recent(hours=24)
        assert len(critical) >= 1


class TestThreatEntry:
    def test_create_entry(self):
        entry = _make_entry()
        assert entry.cve_id == "CVE-2026-1234"
        assert entry.severity == 7.5

    def test_multilingual_entry(self):
        entry = ThreatEntry(
            id="forum:xss-12345",
            title="New RCE in FortiGate",
            description="Remote code execution vulnerability",
            source=IntelSource.FORUM,
            language="ru",
            raw_text="\u041d\u043e\u0432\u044b\u0439 RCE \u0432 FortiGate \u043e\u0431\u043d\u0430\u0440\u0443\u0436\u0435\u043d",
        )
        assert entry.language == "ru"
        assert entry.raw_text is not None
