"""Tests for shared library defaults."""

from dixie.constants import (
    DEFAULT_GOBUSTER_WORDLIST,
    DEFAULT_LLM_MODEL,
    DEFAULT_MASSCAN_MAX_RATE,
    DEFAULT_TRANSLATION_MODEL,
)


def test_default_llm_model_non_empty() -> None:
    assert DEFAULT_LLM_MODEL
    assert "/" in DEFAULT_LLM_MODEL


def test_default_translation_model_non_empty() -> None:
    assert DEFAULT_TRANSLATION_MODEL
    assert "/" in DEFAULT_TRANSLATION_MODEL


def test_defaults_are_distinct() -> None:
    assert DEFAULT_LLM_MODEL != DEFAULT_TRANSLATION_MODEL


def test_default_gobuster_wordlist_non_empty() -> None:
    assert DEFAULT_GOBUSTER_WORDLIST
    assert DEFAULT_GOBUSTER_WORDLIST.endswith(".txt")


def test_constants_module_doc_mentions_operational_yaml() -> None:
    import dixie.constants as c

    assert "YAML" in (c.__doc__ or "")
    assert "engagement" in (c.__doc__ or "").lower()
    assert "AGENTS.md" in (c.__doc__ or "")
    assert "DIXIE_DEFAULT_" in (c.__doc__ or "")
    assert "llm.model" in (c.__doc__ or "")
    assert "DIXIE_DEFAULT_GOBUSTER_WORDLIST" in (c.__doc__ or "")
    assert "EngagementConfig" in (c.__doc__ or "")


def test_default_masscan_max_rate_conservative_cap() -> None:
    """Library default scan-rate cap stays modest; YAML raises the ceiling."""
    assert DEFAULT_MASSCAN_MAX_RATE == 100_000


def test_default_masscan_max_rate_env_override(monkeypatch) -> None:
    import importlib

    import dixie.constants as c_mod

    monkeypatch.setenv("DIXIE_DEFAULT_MASSCAN_MAX_RATE", "5000")
    importlib.reload(c_mod)
    assert c_mod.DEFAULT_MASSCAN_MAX_RATE == 5000
    monkeypatch.delenv("DIXIE_DEFAULT_MASSCAN_MAX_RATE", raising=False)
    importlib.reload(c_mod)
    assert c_mod.DEFAULT_MASSCAN_MAX_RATE == 100_000


def test_default_masscan_max_rate_invalid_env_ignored(monkeypatch) -> None:
    import importlib

    import dixie.constants as c_mod

    monkeypatch.setenv("DIXIE_DEFAULT_MASSCAN_MAX_RATE", "bogus")
    importlib.reload(c_mod)
    assert c_mod.DEFAULT_MASSCAN_MAX_RATE == 100_000
    monkeypatch.delenv("DIXIE_DEFAULT_MASSCAN_MAX_RATE", raising=False)
    importlib.reload(c_mod)


def test_default_gobuster_wordlist_env_override(monkeypatch) -> None:
    import importlib

    import dixie.constants as c_mod

    monkeypatch.setenv("DIXIE_DEFAULT_GOBUSTER_WORDLIST", "/opt/lists/custom.txt")
    importlib.reload(c_mod)
    assert c_mod.DEFAULT_GOBUSTER_WORDLIST == "/opt/lists/custom.txt"
    monkeypatch.delenv("DIXIE_DEFAULT_GOBUSTER_WORDLIST", raising=False)
    importlib.reload(c_mod)
    assert c_mod.DEFAULT_GOBUSTER_WORDLIST.endswith(".txt")
