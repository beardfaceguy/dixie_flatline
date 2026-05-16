"""Small helpers for parsing optional integer environment overrides."""

from __future__ import annotations

import os


def env_int(name: str, default: int) -> int:
    """Parse ``int(os.environ[name])`` or return ``default`` if missing or invalid."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default
