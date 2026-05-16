"""Multilingual translation for non-English threat intelligence entries.

Uses LiteLLM to translate Russian, Chinese, and Ukrainian content into
English, preserving technical terms (CVE IDs, tool names, IP addresses).
Falls back gracefully when no LLM API key is configured.
"""

from __future__ import annotations

import logging
import os
import re

from dixie.intel.schema import ThreatEntry
from dixie.intel.store import IntelStore

logger = logging.getLogger(__name__)

TRANSLATE_PROMPT = """\
Translate the following cybersecurity text from {lang_name} to English.
Preserve all technical terms exactly as-is: CVE IDs, IP addresses, domain names,
tool names (nmap, sqlmap, etc.), protocol names, and code snippets.
Output ONLY the translation, nothing else.

Text:
{text}\
"""

LANG_NAMES = {
    "ru": "Russian",
    "zh": "Chinese",
    "uk": "Ukrainian",
    "ko": "Korean",
    "ja": "Japanese",
}


def translate_entry(entry: ThreatEntry, model: str = "openai/gpt-4o-mini") -> ThreatEntry:
    """Translate a non-English entry's title and description to English.

    Stores the original text in raw_text. Returns the entry unchanged if
    already English or if no API key is available.
    """
    if entry.language == "en":
        return entry

    if not _has_api_key():
        return entry

    import litellm

    lang_name = LANG_NAMES.get(entry.language, entry.language)

    try:
        translated_title = _translate_text(entry.title, lang_name, model)
        translated_desc = _translate_text(entry.description, lang_name, model)

        entry.raw_text = entry.raw_text or entry.description
        entry.title = translated_title or entry.title
        entry.description = translated_desc or entry.description

    except Exception as e:
        logger.debug("Translation failed for %s: %s", entry.id, e)

    return entry


def translate_batch(
    entries: list[ThreatEntry],
    model: str = "openai/gpt-4o-mini",
) -> list[ThreatEntry]:
    """Translate a batch of non-English entries."""
    if not _has_api_key():
        logger.info("No LLM API key found, skipping translation")
        return entries

    non_english = [e for e in entries if e.language != "en" and not e.raw_text]
    if not non_english:
        return entries

    logger.info("Translating %d non-English entries", len(non_english))
    for entry in non_english:
        translate_entry(entry, model)

    return entries


def translate_pending(
    store: IntelStore,
    model: str = "openai/gpt-4o-mini",
    limit: int = 50,
) -> int:
    """Translate entries in the store that haven't been translated yet.

    Looks for entries where language != 'en' and raw_text is NULL
    (meaning original text hasn't been preserved yet, so no translation
    has been attempted).
    """
    if not _has_api_key():
        logger.info("No LLM API key found, skipping translation")
        return 0

    rows = store._conn.execute(
        """SELECT * FROM threat_entries
        WHERE language != 'en' AND raw_text IS NULL
        ORDER BY first_seen DESC
        LIMIT ?""",
        (limit,),
    ).fetchall()

    if not rows:
        return 0

    count = 0
    for row in rows:
        entry = store._row_to_entry(row)
        translated = translate_entry(entry, model)
        store.upsert(translated)
        count += 1

    logger.info("Translated %d entries", count)
    return count


def _translate_text(text: str, lang_name: str, model: str) -> str | None:
    """Translate a single piece of text."""
    if not text or len(text.strip()) < 3:
        return None

    # Skip if already mostly ASCII/English
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii / max(len(text), 1) < 0.1:
        return None

    import litellm

    prompt = TRANSLATE_PROMPT.format(lang_name=lang_name, text=text[:3000])

    response = litellm.completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=1000,
    )

    result = response.choices[0].message.content
    return result.strip() if result else None


def _has_api_key() -> bool:
    return bool(
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OLLAMA_API_BASE")
    )
