"""Tests for forum collector, translator, and scheduler."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from dixie.intel.collectors.forums import (
    ForumCollector,
    ForumConfig,
    _slug,
    _strip_html,
)
from dixie.intel.schema import ExploitMaturity, FeedStatus, IntelSource, ThreatEntry
from dixie.intel.store import IntelStore


def _store() -> tuple[IntelStore, Path]:
    tmp = tempfile.mkdtemp()
    db_path = Path(tmp) / "test.db"
    return IntelStore(db_path), db_path


class TestForumCollector:
    def test_strip_html(self):
        assert _strip_html("<b>hello</b>") == "hello"
        assert _strip_html('<a href="#">test</a>') == "test"

    def test_slug(self):
        assert _slug("CVE-2026-1234 RCE in Apache") == "cve-2026-1234-rce-in-apache"

    def test_extract_posts_from_html(self):
        config = ForumConfig(
            name="TestForum",
            base_url="https://example.com",
            pages=["/exploits"],
            post_pattern=r'<a href="([^"]*)"[^>]*>([^<]+)</a>',
            tags=["test"],
        )
        html = """
        <div>
            <a href="/thread/1">CVE-2026-9999 RCE in Router firmware</a>
            <a href="/thread/2">New zero-day exploit for Windows</a>
            <a href="/thread/3">Hi</a>
        </div>
        """
        collector = ForumCollector(configs=[config])
        entries = collector._extract_posts(html, config)

        assert len(entries) == 2
        assert entries[0].cve_id == "CVE-2026-9999"
        assert entries[0].source == IntelSource.FORUM
        assert "test" in entries[0].tags

    def test_extract_generic_fallback(self):
        config = ForumConfig(
            name="GenericForum",
            base_url="https://example.com",
            pages=["/"],
            tags=["generic"],
        )
        html = """
        <a href="/t/1">exploit for CVE-2026-5555</a>
        <a href="/t/2">Cooking recipes</a>
        <a href="/t/3">New SQLi vulnerability in PHP</a>
        """
        collector = ForumCollector(configs=[config])
        entries = collector._extract_generic(html, config)

        assert len(entries) == 2
        assert any("CVE-2026-5555" in (e.cve_id or "") for e in entries)
        assert all(e.source == IntelSource.FORUM for e in entries)

    def test_exploit_maturity_detection(self):
        config = ForumConfig(
            name="Test",
            base_url="https://example.com",
            pages=["/"],
            post_pattern=r'<a href="([^"]*)"[^>]*>([^<]+)</a>',
            tags=[],
        )
        html = '<a href="/1">0day RCE exploit for Cisco</a>'
        collector = ForumCollector(configs=[config])
        entries = collector._extract_posts(html, config)

        assert len(entries) == 1
        assert entries[0].exploit_maturity == ExploitMaturity.POC

    def test_language_tagging(self):
        config = ForumConfig(
            name="ZhForum",
            base_url="https://example.com",
            pages=["/"],
            language="zh",
            post_pattern=r'<a href="([^"]*)"[^>]*>([^<]+)</a>',
            tags=["chinese"],
        )
        html = '<a href="/1">exploit in router firmware</a>'
        collector = ForumCollector(configs=[config])
        entries = collector._extract_posts(html, config)

        assert len(entries) == 1
        assert entries[0].language == "zh"
        assert entries[0].raw_text is not None

    def test_collector_skips_unconfigured_forums(self):
        config = ForumConfig(
            name="Missing",
            base_url="",
            pages=["/exploits"],
        )
        collector = ForumCollector(configs=[config])
        entries = collector.fetch()
        assert entries == []

    def test_collector_handles_http_errors(self):
        config = ForumConfig(
            name="Broken",
            base_url="https://nonexistent.example.invalid",
            pages=["/"],
        )
        collector = ForumCollector(configs=[config])
        entries = collector.fetch()
        assert entries == []


class TestTranslate:
    def test_has_api_key_returns_false(self):
        from dixie.intel.translate import _has_api_key

        import os
        saved = {k: os.environ.pop(k, None) for k in
                 ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_API_BASE")}
        try:
            assert _has_api_key() is False
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_translate_entry_noop_english(self):
        from dixie.intel.translate import translate_entry

        entry = ThreatEntry(
            id="test:1", title="English title",
            description="English desc", source=IntelSource.NVD,
        )
        result = translate_entry(entry)
        assert result.title == "English title"

    def test_translate_batch_noop_without_key(self):
        from dixie.intel.translate import translate_batch

        entries = [
            ThreatEntry(
                id="test:1", title="Тест",
                description="Описание", source=IntelSource.FORUM,
                language="ru",
            )
        ]

        import os
        saved = {k: os.environ.pop(k, None) for k in
                 ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_API_BASE")}
        try:
            result = translate_batch(entries)
            assert result[0].title == "Тест"
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_translate_entry_calls_llm(self):
        import sys

        mock_litellm = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Translated text"
        mock_litellm.completion.return_value = mock_response

        sys.modules["litellm"] = mock_litellm
        try:
            import importlib
            import dixie.intel.translate as trans_mod
            importlib.reload(trans_mod)

            entry = ThreatEntry(
                id="test:ru", title="Новый эксплойт для Apache",
                description="Описание уязвимости в Apache httpd",
                source=IntelSource.FORUM, language="ru",
            )

            with patch.object(trans_mod, "_has_api_key", return_value=True):
                result = trans_mod.translate_entry(entry)

            assert result.raw_text is not None
            assert mock_litellm.completion.called
        finally:
            del sys.modules["litellm"]
            import importlib
            import dixie.intel.translate as trans_mod
            importlib.reload(trans_mod)


class TestScheduler:
    def test_generate_crontab(self):
        from dixie.intel.scheduler import generate_crontab

        cron = generate_crontab(alert_email="test@example.com")
        assert "*/2 * * *" in cron
        assert "*/6 * * *" in cron
        assert "0 6 * * *" in cron
        assert "dixie intel update" in cron
        assert "test@example.com" in cron
        assert "dixie-intel-managed" in cron

    def test_generate_crontab_with_webhook(self):
        from dixie.intel.scheduler import generate_crontab

        cron = generate_crontab(alert_webhook="https://hooks.slack.com/test")
        assert "hooks.slack.com" in cron

    def test_format_alert_text_empty(self):
        from dixie.intel.scheduler import format_alert_text

        assert format_alert_text([]) == ""

    def test_format_alert_text(self):
        from dixie.intel.scheduler import format_alert_text

        entries = [
            ThreatEntry(
                id="test:1", cve_id="CVE-2026-9999",
                title="Critical RCE in Everything",
                description="Bad stuff",
                severity=10.0,
                exploit_maturity=ExploitMaturity.ACTIVELY_EXPLOITED,
                source=IntelSource.NVD,
            )
        ]
        text = format_alert_text(entries)
        assert "CVE-2026-9999" in text
        assert "Critical" in text
        assert "CVSS 10.0" in text

    def test_build_alert_digest(self):
        from dixie.intel.scheduler import build_alert_digest

        store, _ = _store()
        store.upsert(ThreatEntry(
            id="crit:1", cve_id="CVE-2026-0001",
            title="Critical", description="Critical vuln",
            severity=10.0,
            exploit_maturity=ExploitMaturity.ACTIVELY_EXPLOITED,
            source=IntelSource.NVD,
        ))
        store.upsert(ThreatEntry(
            id="low:1", title="Low", description="Minor issue",
            severity=3.0, source=IntelSource.NVD,
        ))

        critical = build_alert_digest(store, hours=24)
        assert len(critical) >= 1
        assert all(
            e.severity >= 9.0 or e.exploit_maturity == ExploitMaturity.ACTIVELY_EXPLOITED
            for e in critical
        )
        store.close()

    @patch("dixie.intel.scheduler.subprocess")
    def test_install_crontab(self, mock_subprocess):
        from dixie.intel.scheduler import install_crontab

        mock_subprocess.run.side_effect = [
            MagicMock(returncode=0, stdout="# existing cron\n0 * * * * /bin/true\n"),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        ok = install_crontab("# dixie cron\n0 */2 * * * dixie intel update\n")
        assert ok is True
        assert mock_subprocess.run.call_count == 2
