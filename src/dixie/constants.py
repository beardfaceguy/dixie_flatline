"""Shared default strings used across Dixie (single source for library fallbacks).

AGENTS.md requires that real engagements configure models via YAML, not baked-in
operational strings. The ``DEFAULT_*`` model IDs below are **not** production
policy: they exist only as Pydantic field defaults, library fallbacks when no
config is loaded, and deterministic test fixtures. These identifiers intentionally
mirror common LiteLLM route names so uninstantiated configs remain runnable in
tests and docs. Loaded ``EngagementConfig`` from YAML remains authoritative for
production runs (AGENTS.md).

Override env keys include ``DIXIE_DEFAULT_LLM_MODEL``,
``DIXIE_DEFAULT_TRANSLATION_MODEL``, ``DIXIE_DEFAULT_GOBUSTER_WORDLIST``,
and ``DIXIE_DEFAULT_MASSCAN_MAX_RATE``. Production engagements should still set
``llm.model``, paths, and limits via YAML where it matters.
"""

import os


def _env_positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        v = int(raw, 10)
    except ValueError:
        return default
    return v if v > 0 else default


DEFAULT_LLM_MODEL: str = os.environ.get("DIXIE_DEFAULT_LLM_MODEL", "openai/gpt-4o")
DEFAULT_TRANSLATION_MODEL: str = os.environ.get(
    "DIXIE_DEFAULT_TRANSLATION_MODEL",
    "openai/gpt-4o-mini",
)

# Gobuster default wordlist path inside the standard Kali-oriented sandbox image.
# Env ``DIXIE_DEFAULT_GOBUSTER_WORDLIST`` for hosts without that layout;
# override per engagement via `tool_defaults.gobuster_wordlist` in YAML.
DEFAULT_GOBUSTER_WORDLIST: str = os.environ.get(
    "DIXIE_DEFAULT_GOBUSTER_WORDLIST",
    "/usr/share/wordlists/dirb/common.txt",
)

# Upper bound for masscan ``--rate`` when ``tool_defaults.masscan_max_rate`` is unset.
# Env ``DIXIE_DEFAULT_MASSCAN_MAX_RATE``; raise via YAML when needed.
DEFAULT_MASSCAN_MAX_RATE: int = _env_positive_int(
    "DIXIE_DEFAULT_MASSCAN_MAX_RATE",
    100_000,
)
