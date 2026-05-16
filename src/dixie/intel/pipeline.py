"""Threat intelligence pipeline: runs all collectors and produces a daily digest."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

from dixie.intel.collectors.base import Collector
from dixie.intel.collectors.cisa_kev import CisaKevCollector
from dixie.intel.collectors.exploit_intel import ExploitIntelCollector
from dixie.intel.collectors.exploitdb import ExploitDbCollector
from dixie.intel.collectors.forums import ForumCollector
from dixie.intel.collectors.full_disclosure import FullDisclosureCollector
from dixie.intel.collectors.nvd import NvdCollector
from dixie.intel.collectors.packetstorm import PacketStormCollector
from dixie.intel.collectors.reddit import RedditCollector
from dixie.intel.collectors.sploitus import SploitusCollector
from dixie.intel.collectors.telegram import TelegramCollector
from dixie.intel.schema import FeedStatus
from dixie.intel.store import IntelStore

logger = logging.getLogger(__name__)
console = Console()

DEFAULT_DB = Path.home() / ".dixie" / "intel.db"


def build_collectors(
    tier: int = 3,
    nvd_api_key: str | None = None,
    telegram_channels: list[str] | None = None,
    use_tor: bool = False,
    onion_urls: dict[str, str] | None = None,
) -> list[Collector]:
    """Build collectors up to the specified tier.

    Tier 1: Structured APIs (CISA KEV, EIP, NVD, Full Disclosure)
    Tier 2: Semi-structured feeds (Sploitus, Packet Storm, Exploit-DB)
    Tier 3: Unstructured/social (Reddit, Telegram, Forums)
    """
    collectors: list[Collector] = []

    # Tier 1: structured APIs
    collectors.extend([
        CisaKevCollector(),
        ExploitIntelCollector(days_back=1),
        NvdCollector(api_key=nvd_api_key, days_back=1),
        FullDisclosureCollector(),
    ])

    if tier >= 2:
        collectors.extend([
            SploitusCollector(),
            PacketStormCollector(),
            ExploitDbCollector(max_entries=200),
        ])

    if tier >= 3:
        collectors.extend([
            RedditCollector(),
            TelegramCollector(channels=telegram_channels),
            ForumCollector(use_tor=use_tor, onion_urls=onion_urls),
        ])

    return collectors


def run_pipeline(
    db_path: Path = DEFAULT_DB,
    tier: int = 3,
    nvd_api_key: str | None = None,
    telegram_channels: list[str] | None = None,
    use_tor: bool = False,
    onion_urls: dict[str, str] | None = None,
    translate: bool = False,
    translate_model: str = "openai/gpt-4o-mini",
) -> tuple[IntelStore, list[FeedStatus]]:
    """Run all collectors and return the store + feed statuses."""
    store = IntelStore(db_path)
    collectors = build_collectors(
        tier=tier,
        nvd_api_key=nvd_api_key,
        telegram_channels=telegram_channels,
        use_tor=use_tor,
        onion_urls=onion_urls,
    )
    statuses = []

    for collector in collectors:
        console.print(f"  [dim]Collecting from {collector.name}...[/dim]")
        status = collector.run(store)
        statuses.append(status)

    if translate:
        from dixie.intel.translate import translate_pending

        console.print("  [dim]Translating non-English entries...[/dim]")
        translated = translate_pending(store, model=translate_model)
        if translated:
            console.print(f"  [dim]Translated {translated} entries[/dim]")

    return store, statuses


def print_digest(store: IntelStore, statuses: list[FeedStatus]) -> None:
    """Print a summary of the pipeline run."""
    stats = store.stats()

    console.print(f"\n[bold]Total entries:[/bold] {stats['total_entries']}")
    console.print(f"[bold]Critical (CVSS >= 9.0):[/bold] {stats['critical_count']}")

    feed_table = Table(title="Feed Status")
    feed_table.add_column("Source")
    feed_table.add_column("New", justify="right")
    feed_table.add_column("Total", justify="right")
    feed_table.add_column("Status")

    for s in statuses:
        status_str = (
            "[green]OK[/green]" if s.last_success
            else f"[red]FAIL: {s.last_error}[/red]"
        )
        feed_table.add_row(
            s.source.value,
            str(s.entries_last_run),
            str(s.entries_total),
            status_str,
        )

    console.print(feed_table)

    critical = store.get_critical_recent(hours=24)
    if critical:
        console.print("\n[bold red]Critical findings in last 24h:[/bold red]")
        for entry in critical[:10]:
            sev = f"[red]{entry.severity}[/red]" if entry.severity else "N/A"
            console.print(f"  {sev} {entry.cve_id or ''} - {entry.title[:80]}")
