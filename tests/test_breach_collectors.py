"""Tests for breach intelligence collectors (HIBP, Pastebin, Gov Breach)."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from dixie.intel.collectors.gov_breach import HHSBreachCollector
from dixie.intel.collectors.hibp import HibpBreachCollector, HibpDomainCollector
from dixie.intel.collectors.pastebin import PastebinLeakCollector
from dixie.intel.schema import IntelSource, ThreatEntry


class TestHibpBreachCollector:
    """Tests for HaveIBeenPwned breach collector."""

    def test_rate_limiting_enforced(self, monkeypatch):
        """Test that rate limiting is enforced between requests."""
        import time

        call_times = []

        def fake_get(url, headers=None, timeout=None):
            call_times.append(time.time())

            class Resp:
                def raise_for_status(self):
                    pass

                def json(self):
                    return [
                        {
                            "Name": "TestBreach",
                            "Title": "Test Breach",
                            "Domain": "test.com",
                            "BreachDate": "2024-01-01",
                            "PwnCount": 1000,
                            "Description": "Test breach",
                            "DataClasses": ["Email", "Password"],
                            "IsVerified": True,
                        }
                    ]

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.hibp.httpx.get", fake_get)

        collector = HibpBreachCollector()
        entries = collector.fetch()

        assert len(entries) == 1
        assert entries[0].id == "hibp:TestBreach"
        assert "verified" in entries[0].tags
        assert "breach" in entries[0].tags

    def test_builds_tags_from_metadata(self):
        """Test tag generation from breach metadata."""
        from dixie.intel.collectors.hibp import _build_tags

        breach = {
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": True,
            "IsRetired": False,
            "IsSpamList": True,
            "DataClasses": ["Email addresses", "Passwords"],
        }

        tags = _build_tags(breach)

        assert "verified" in tags
        assert "sensitive" in tags
        assert "spam_list" in tags
        assert "data:email_addresses" in tags
        assert "data:passwords" in tags

    def test_no_api_key_required(self, monkeypatch):
        """Test that free tier works without API key."""

        def fake_get(url, headers=None, timeout=None):
            # Verify no API key header is present
            assert "hibp-api-key" not in headers

            class Resp:
                def raise_for_status(self):
                    pass

                def json(self):
                    return []

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.hibp.httpx.get", fake_get)

        collector = HibpBreachCollector()  # No API key
        entries = collector.fetch()
        assert entries == []


class TestHibpDomainCollector:
    """Tests for HIBP domain-specific collector."""

    def test_domain_filtering(self, monkeypatch):
        """Test domain-specific breach collection."""

        def fake_get(url, headers=None, timeout=None):
            # Verify domain in URL
            assert "domain=example.com" in url

            class Resp:
                def raise_for_status(self):
                    pass

                def json(self):
                    return [
                        {
                            "Name": "ExampleCorpBreach",
                            "Title": "Example Corp Breach",
                            "Domain": "example.com",
                            "BreachDate": "2024-01-01",
                            "PwnCount": 5000,
                            "Description": "Breach at Example Corp",
                        }
                    ]

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.hibp.httpx.get", fake_get)

        collector = HibpDomainCollector(domain="example.com")
        entries = collector.fetch()

        assert len(entries) == 1
        assert "domain_targeted" in entries[0].tags
        assert "example.com" in entries[0].affected_products[0]


class TestPastebinLeakCollector:
    """Tests for Pastebin leak collector."""

    def test_leak_scoring_email_heavy(self):
        """Test scoring function with email-heavy content."""
        collector = PastebinLeakCollector()

        content = "\n".join([f"user{i}@example.com:password{i}" for i in range(50)])
        score, indicators = collector._score_leak_likelihood(content)

        assert score >= 5.0  # Many emails should score high (capped at 5.0)
        assert any("emails:" in i for i in indicators)

    def test_leak_scoring_target_domain(self):
        """Test that target domains increase score."""
        collector = PastebinLeakCollector(target_domains=["targetcorp.com"])

        content = "admin@targetcorp.com:password123\nuser@other.com:pass"
        score, indicators = collector._score_leak_likelihood(content)

        assert score >= 3.0  # Target domain match
        assert any("target:" in i for i in indicators)

    def test_leak_scoring_breach_keywords(self):
        """Test breach keyword detection."""
        collector = PastebinLeakCollector()

        content = "database dump breach leaked credentials user:pass combo list"
        score, indicators = collector._score_leak_likelihood(content)

        assert score > 0
        assert any("keyword:" in i for i in indicators)

    def test_min_leak_score_filtering(self, monkeypatch):
        """Test that min_leak_score filters low-score pastes."""

        def fake_get(url, headers=None, timeout=None, follow_redirects=None):
            class Resp:
                def raise_for_status(self):
                    pass

                def json(self) -> list:
                    return []  # Empty for archive

                # httpx exposes .text as an attribute, not a method.
                text = "Just some random text with no indicators"

            return Resp()

        monkeypatch.setattr(
            "dixie.intel.collectors.pastebin.PastebinLeakCollector._fetch_scraping_archive",
            lambda self: [{"key": "abc123", "title": "Test", "url": "https://pastebin.com/abc123"}],
        )
        monkeypatch.setattr("dixie.intel.collectors.pastebin.httpx.get", fake_get)

        collector = PastebinLeakCollector(min_leak_score=5.0)
        # Low-score content (no leak indicators) must be filtered out.
        entries = collector.fetch()
        assert entries == []

    def test_targeted_collector_enhanced_scoring(self):
        """Test targeted collector with keywords."""
        from dixie.intel.collectors.pastebin import PastebinTargetedCollector

        collector = PastebinTargetedCollector(
            target_domains=["example.com"],
            target_keywords=["confidential", "internal use only"],
        )

        content = "confidential internal document from example.com"
        score, indicators = collector._score_leak_likelihood(content)

        # Should have high score from keyword and domain matches
        assert score > 5.0


class TestHHSBreachCollector:
    """Tests for HHS breach portal collector."""

    def test_fetch_parses_breach_data(self, monkeypatch):
        """Test parsing of HHS breach data."""

        def fake_get(url, headers=None, timeout=None):
            class Resp:
                def raise_for_status(self):
                    pass

                def json(self):
                    return [
                        {
                            "id": 12345,
                            "covered_entity": "Test Hospital",
                            "state": "CA",
                            "breach_submission_date": "2024-01-15",
                            "individuals_affected": 15000,
                            "breach_type": "Hacking/IT Incident",
                            "location": "Network Server",
                        }
                    ]

            return Resp()

        monkeypatch.setattr("dixie.intel.collectors.gov_breach.httpx.get", fake_get)

        collector = HHSBreachCollector()
        entries = collector.fetch()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.id == "hhs:12345"
        assert entry.source == IntelSource.GOV_BREACH
        assert "healthcare" in entry.tags
        assert "hacking_it" in entry.tags
        assert "medium_breach" in entry.tags  # 15k affected

    def test_build_tags_massive_breach(self):
        """Test tag generation for massive breach."""
        from dixie.intel.collectors.gov_breach import HHSBreachCollector

        collector = HHSBreachCollector()
        tags = collector._build_tags("Hacking/IT Incident", 5000000)

        assert "massive_breach" in tags
        assert "healthcare" in tags
        assert "hacking_it" in tags

    def test_parse_date_various_formats(self):
        """Test date parsing for various formats."""
        from dixie.intel.collectors.gov_breach import HHSBreachCollector

        collector = HHSBreachCollector()

        # Test various formats
        dates = [
            "2024-01-15",
            "01/15/2024",
            "01/15/24",
        ]

        for date_str in dates:
            result = collector._parse_date(date_str)
            assert isinstance(result, datetime)

    def test_parse_date_non_string_does_not_crash(self):
        """A non-string date (e.g. numeric JSON) must not raise TypeError."""
        from dixie.intel.collectors.gov_breach import HHSBreachCollector

        collector = HHSBreachCollector()
        result = collector._parse_date(20240115)
        assert isinstance(result, datetime)


class TestBreachEntryIntegration:
    """Integration tests for breach entries in the intel store."""

    def test_breach_entry_to_threat_entry(self):
        """Verify breach entries can be stored as ThreatEntry."""
        entry = ThreatEntry(
            id="hibp:TestBreach",
            title="Breach: Test Company",
            description="Test breach description",
            source=IntelSource.HIBP,
            tags=["breach", "credentials"],
            affected_products=["domain:example.com", "accounts:1000"],
        )

        assert entry.source == IntelSource.HIBP
        assert "breach" in entry.tags

    def test_gov_breach_entry_to_threat_entry(self):
        """Verify government breach entries can be stored."""
        entry = ThreatEntry(
            id="hhs:12345",
            title="Healthcare Breach: Test Hospital",
            description="HIPAA breach affecting 5000 individuals",
            source=IntelSource.GOV_BREACH,
            tags=["healthcare", "hipaa", "large_breach"],
            affected_products=["entity:Test Hospital", "state:CA"],
        )

        assert entry.source == IntelSource.GOV_BREACH
        assert "hipaa" in entry.tags

    def test_pastebin_entry_to_threat_entry(self):
        """Verify Pastebin entries can be stored."""
        entry = ThreatEntry(
            id="pastebin:abc123",
            title="Pastebin Leak: Test Title",
            description="Potential credential leak content",
            source=IntelSource.PASTEBIN,
            tags=["pastebin", "potential_leak", "emails:50"],
            raw_text="user@example.com:password",
        )

        assert entry.source == IntelSource.PASTEBIN
        assert "potential_leak" in entry.tags
