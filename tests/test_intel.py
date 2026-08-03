"""Tests for threat intelligence store and schema."""

import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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

    def test_count_by_source(self):
        self.store.upsert(_make_entry(id="a", source=IntelSource.NVD))
        self.store.upsert(_make_entry(id="b", source=IntelSource.NVD))
        self.store.upsert(_make_entry(id="c", source=IntelSource.CISA_KEV))

        assert self.store.count_by_source(IntelSource.NVD) == 2
        assert self.store.count_by_source(IntelSource.CISA_KEV) == 1
        assert self.store.count_by_source(IntelSource.REDDIT) == 0

    def test_fetch_pending_translation(self):
        # Pending: non-English with no preserved original text yet.
        pending = _make_entry(id="ru", cve_id="CVE-2026-9001")
        pending.language = "ru"
        pending.raw_text = None
        self.store.upsert(pending)
        # Not pending: already English.
        self.store.upsert(_make_entry(id="en", cve_id="CVE-2026-9002"))
        # Not pending: non-English but original already preserved.
        done = _make_entry(id="de", cve_id="CVE-2026-9003")
        done.language = "de"
        done.raw_text = "original text"
        self.store.upsert(done)

        results = self.store.fetch_pending_translation(limit=50)

        assert [e.id for e in results] == ["ru"]
        assert all(isinstance(e, ThreatEntry) for e in results)

    def test_fetch_pending_translation_respects_limit(self):
        for i in range(3):
            e = _make_entry(id=f"ru{i}", cve_id=f"CVE-2026-70{i}")
            e.language = "ru"
            e.raw_text = None
            self.store.upsert(e)

        assert len(self.store.fetch_pending_translation(limit=2)) == 2

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


class TestSchedulerCronInvocation:
    def test_generate_crontab_uses_python_module_not_bare_dixie(self) -> None:
        import sys

        from dixie.intel.scheduler import generate_crontab

        cron = generate_crontab()
        assert "-m dixie" in cron
        assert sys.executable in cron
        assert "dixie-intel-managed" in cron

    @patch("dixie.intel.scheduler.subprocess")
    def test_install_crontab_strips_tagged_lines_even_if_log_path_differs(
        self,
        mock_subprocess: MagicMock,
    ) -> None:
        from dixie.intel.scheduler import CRON_TAG, generate_crontab, install_crontab

        legacy = (
            "0 */2 * * * /x/python -m dixie intel update --db /data/x.sqlite "
            f"--tier 1 >> /var/log/legacy-dixie.log 2>&1 {CRON_TAG}\n"
        )
        mock_subprocess.run.side_effect = [
            MagicMock(returncode=0, stdout=f"# keep\n0 * * * * /bin/true\n{legacy}"),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        assert install_crontab(generate_crontab()) is True
        written = mock_subprocess.run.call_args_list[1].kwargs["input"]
        assert "legacy-dixie.log" not in written
        assert "dixie-intel-managed" in written

    @patch("dixie.intel.scheduler.subprocess")
    def test_install_crontab_preserves_untagged_dixie_intel_lines(
        self,
        mock_subprocess: MagicMock,
    ) -> None:
        from dixie.intel.scheduler import generate_crontab, install_crontab

        custom = (
            "0 0 * * * python -m dixie intel update --db /custom/db.sqlite "
            "--tier 1 >> /tmp/operator.log 2>&1\n"
        )
        mock_subprocess.run.side_effect = [
            MagicMock(returncode=0, stdout=custom),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        assert install_crontab(generate_crontab()) is True
        written = mock_subprocess.run.call_args_list[1].kwargs["input"]
        assert "/custom/db.sqlite" in written
        assert "dixie-intel-managed" in written

    @patch("dixie.intel.scheduler.subprocess")
    def test_install_crontab_preserves_similar_header_comments(
        self,
        mock_subprocess: MagicMock,
    ) -> None:
        from dixie.intel.scheduler import generate_crontab, install_crontab

        note = "# dixie-flatline threat intel — operator notes\n"
        mock_subprocess.run.side_effect = [
            MagicMock(returncode=0, stdout=note),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        assert install_crontab(generate_crontab()) is True
        written = mock_subprocess.run.call_args_list[1].kwargs["input"]
        assert "operator notes" in written

    def test_generate_crontab_log_path_env_override(self, monkeypatch) -> None:
        from dixie.intel.scheduler import generate_crontab

        monkeypatch.setenv("DIXIE_INTEL_CRON_LOG_PATH", "/tmp/dixie-intel-test.log")
        try:
            cron = generate_crontab()
            assert ">> /tmp/dixie-intel-test.log" in cron
            assert "/var/log/dixie-intel.log" not in cron
        finally:
            monkeypatch.delenv("DIXIE_INTEL_CRON_LOG_PATH", raising=False)


class TestNvdCollectorSafetyCaps:
    def test_fetches_multiple_pages(self, monkeypatch):
        from dixie.intel.collectors.nvd import NvdCollector

        calls = {"n": 0}

        def fake_get(url, params=None, headers=None, timeout=None):
            calls["n"] += 1
            start = int((params or {}).get("startIndex", 0))

            class Resp:
                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict:
                    if start == 0:
                        return {
                            "totalResults": 3,
                            "vulnerabilities": [
                                {
                                    "cve": {
                                        "id": f"CVE-2026-{i:04d}",
                                        "descriptions": [{"lang": "en", "value": "x"}],
                                        "metrics": {},
                                        "published": "2026-01-01T00:00:00.000",
                                        "lastModified": "2026-01-01T00:00:00.000",
                                        "weaknesses": [],
                                    },
                                }
                                for i in range(2)
                            ],
                        }
                    return {
                        "totalResults": 3,
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2026-9999",
                                    "descriptions": [{"lang": "en", "value": "y"}],
                                    "metrics": {},
                                    "published": "2026-01-01T00:00:00.000",
                                    "lastModified": "2026-01-01T00:00:00.000",
                                    "weaknesses": [],
                                },
                            },
                        ],
                    }

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.nvd.httpx.get", fake_get)
        coll = NvdCollector()
        entries = coll.fetch()
        assert len(entries) == 3
        assert calls["n"] == 2

    def test_stops_after_max_api_pages(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from dixie.intel.collectors.nvd import NvdCollector

        calls = {"n": 0}

        def fake_get(url, params=None, headers=None, timeout=None):
            calls["n"] += 1
            start = int((params or {}).get("startIndex", 0))

            class Resp:
                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict:
                    return {
                        "totalResults": 500,
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": f"CVE-2026-{start + i:05d}",
                                    "descriptions": [{"lang": "en", "value": "x"}],
                                    "metrics": {},
                                    "published": "2026-01-01T00:00:00.000",
                                    "lastModified": "2026-01-01T00:00:00.000",
                                    "weaknesses": [],
                                },
                            }
                            for i in range(200)
                        ],
                    }

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.nvd.httpx.get", fake_get)
        with caplog.at_level(logging.WARNING):
            entries = NvdCollector(max_api_pages=1).fetch()
        assert len(entries) == 200
        assert calls["n"] == 1
        assert "max_api_pages cap" in caplog.text

    def test_paginates_when_total_results_absent_but_more_pages(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from dixie.intel.collectors.nvd import NvdCollector

        calls = {"n": 0}

        def _cve(i: int) -> dict:
            return {
                "cve": {
                    "id": f"CVE-2026-{i:04d}",
                    "descriptions": [{"lang": "en", "value": f"v{i}"}],
                    "metrics": {},
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-01T00:00:00.000",
                    "weaknesses": [],
                },
            }

        def fake_get(url, params=None, headers=None, timeout=None):
            calls["n"] += 1
            start = int((params or {}).get("startIndex", 0))

            class Resp:
                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict:
                    if start == 0:
                        return {"vulnerabilities": [_cve(1), _cve(2)]}
                    if start == 2:
                        return {"totalResults": None, "vulnerabilities": [_cve(3)]}
                    return {"vulnerabilities": []}

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.nvd.httpx.get", fake_get)
        entries = NvdCollector(max_api_pages=10).fetch()
        assert len(entries) == 3
        assert calls["n"] == 3


class TestEnvInt:
    def test_env_int_default_and_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from dixie.intel.envparse import env_int

        monkeypatch.delenv("DIXIE_TEST_INT", raising=False)
        assert env_int("DIXIE_TEST_INT", 7) == 7
        monkeypatch.setenv("DIXIE_TEST_INT", "42")
        assert env_int("DIXIE_TEST_INT", 7) == 42

    def test_env_int_invalid_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from dixie.intel.envparse import env_int

        monkeypatch.setenv("DIXIE_TEST_INT", "nan")
        assert env_int("DIXIE_TEST_INT", 99) == 99


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
