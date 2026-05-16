"""CLI entrypoint for Dixie Flatline."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

from dixie.constants import DEFAULT_TRANSLATION_MODEL
from dixie.core.agent import Agent
from dixie.core.config import EngagementConfig, EngagementMode
from dixie.core.sandbox import Sandbox
from dixie.models.llm import LLMClient
from dixie.tools import build_default_registry

console = Console()


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(debug: bool) -> None:
    """Dixie Flatline - LLM-driven red team penetration testing."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True)],
    )


@main.command()
@click.argument("config_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--mode", "-m",
    type=click.Choice(["recon", "full"], case_sensitive=False),
    default=None,
    help="Override engagement mode (recon = passive only, full = everything allowed)",
)
def engage(config_file: Path, mode: str | None) -> None:
    """Start a penetration testing engagement from a config file."""
    config = EngagementConfig.from_file(config_file)
    if mode:
        config.mode = EngagementMode(mode.lower())
    config.output_dir.mkdir(parents=True, exist_ok=True)

    tools = build_default_registry()
    sandbox = Sandbox(config.sandbox)
    llm = LLMClient(config.llm, tools, mode=config.mode)

    agent = Agent(config=config, llm=llm, tools=tools, sandbox=sandbox)
    state = agent.run()

    output_path = config.output_dir / "engagement.json"
    output_path.write_text(state.model_dump_json(indent=2))
    console.print(f"\n[green]Results written to {output_path}[/green]")

    from dixie.reporting.models import EngagementReport
    from dixie.reporting import markdown as md_renderer

    report = EngagementReport.from_engagement(state, title=f"Pentest Report: {config.target}")
    md_path = config.output_dir / "report.md"
    md_path.write_text(md_renderer.render(report))
    console.print(f"[green]Markdown report written to {md_path}[/green]")

    json_path = config.output_dir / "report.json"
    from dixie.reporting import json_report
    json_path.write_text(json_report.render(report))
    console.print(f"[green]JSON report written to {json_path}[/green]")


@main.command()
def tools() -> None:
    """List available pentesting tools."""
    registry = build_default_registry()
    for tool in registry.list_tools():
        console.print(f"[bold]{tool.name}[/bold]: {tool.description}")
        for param in tool.parameters:
            req = "[red]*[/red]" if param.required else " "
            console.print(f"  {req} {param.name}: {param.description}")


@main.group()
def report() -> None:
    """Report generation commands."""


@report.command("generate")
@click.argument("engagement_json", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["markdown", "json", "both"]),
              default="both", help="Output format")
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default=None,
              help="Output directory (defaults to same dir as input)")
@click.option("--title", default=None, help="Report title")
@click.option("--prepared-for", default=None, help="Client/audience name")
def report_generate(
    engagement_json: Path, fmt: str, output_dir: Path | None,
    title: str | None, prepared_for: str | None,
) -> None:
    """Generate a report from a saved engagement JSON file."""
    from dixie.core.schema import EngagementState
    from dixie.reporting import markdown as md_renderer
    from dixie.reporting import json_report
    from dixie.reporting.models import EngagementReport

    state = EngagementState.model_validate_json(engagement_json.read_text())
    out = output_dir or engagement_json.parent
    out.mkdir(parents=True, exist_ok=True)

    kwargs: dict = {}
    if title:
        kwargs["title"] = title
    if prepared_for:
        kwargs["prepared_for"] = prepared_for

    rpt = EngagementReport.from_engagement(state, **kwargs)

    if fmt in ("markdown", "both"):
        md_path = out / "report.md"
        md_path.write_text(md_renderer.render(rpt))
        console.print(f"[green]Markdown report: {md_path}[/green]")

    if fmt in ("json", "both"):
        json_path = out / "report.json"
        json_path.write_text(json_report.render(rpt))
        console.print(f"[green]JSON report: {json_path}[/green]")


@report.command("mitre")
@click.argument("engagement_json", type=click.Path(exists=True, path_type=Path))
def report_mitre(engagement_json: Path) -> None:
    """Show MITRE ATT&CK technique coverage from an engagement."""
    from dixie.core.schema import EngagementState
    from dixie.reporting.mitre import get_technique, TACTICS

    state = EngagementState.model_validate_json(engagement_json.read_text())

    all_techniques: set[str] = set()
    for f in state.findings:
        all_techniques.update(f.attack_techniques)

    if not all_techniques:
        console.print("[yellow]No MITRE ATT&CK techniques mapped in findings.[/yellow]")
        return

    tactic_techniques: dict[str, list[str]] = {}
    for tid in sorted(all_techniques):
        tech = get_technique(tid)
        if tech:
            for tac_id in tech.tactic_ids:
                tactic_techniques.setdefault(tac_id, []).append(tid)

    for tac_id, tactic in TACTICS.items():
        if tac_id not in tactic_techniques:
            continue
        console.print(f"\n[bold]{tactic.name}[/bold] ({tac_id})")
        for tid in tactic_techniques[tac_id]:
            tech = get_technique(tid)
            name = tech.name if tech else tid
            count = sum(1 for f in state.findings if tid in f.attack_techniques)
            console.print(f"  {tid}: {name} ({count} finding(s))")


@main.group()
def intel() -> None:
    """Threat intelligence commands."""


@intel.command()
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Database path")
@click.option("--nvd-key", envvar="NVD_API_KEY", default=None, help="NVD API key")
@click.option("--tier", type=click.IntRange(1, 3), default=3, help="Collector tier (1=APIs, 2=+feeds, 3=+social)")
@click.option("--tor", is_flag=True, help="Route Tier 3 forum requests through Tor")
@click.option("--translate", is_flag=True, help="Translate non-English entries via LLM")
@click.option(
    "--translate-model",
    default=None,
    help="LiteLLM model for --translate (else DIXIE_INTEL_TRANSLATE_MODEL or default)",
)
def update(
    db: Path | None,
    nvd_key: str | None,
    tier: int,
    tor: bool,
    translate: bool,
    translate_model: str | None,
) -> None:
    """Run threat intelligence collectors.

    Tier 1: Structured APIs (CISA KEV, NVD, EIP, Full Disclosure)
    Tier 2: + Semi-structured feeds (Sploitus, Packet Storm, Exploit-DB)
    Tier 3: + Social/OSINT (Reddit, Telegram, Underground Forums)
    """
    from dixie.intel.pipeline import DEFAULT_DB, print_digest, run_pipeline

    db_path = db or DEFAULT_DB
    console.print(f"[bold]Updating threat intelligence (tier {tier})...[/bold]")
    tw_model = translate_model or os.environ.get("DIXIE_INTEL_TRANSLATE_MODEL")
    store, statuses = run_pipeline(
        db_path=db_path, tier=tier, nvd_api_key=nvd_key,
        use_tor=tor, translate=translate,
        translate_model=tw_model or DEFAULT_TRANSLATION_MODEL,
    )
    print_digest(store, statuses)
    store.close()


@intel.command()
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Database path")
def status(db: Path | None) -> None:
    """Show intelligence database status and feed health."""
    from dixie.intel.pipeline import DEFAULT_DB
    from dixie.intel.store import IntelStore

    db_path = db or DEFAULT_DB
    if not db_path.exists():
        console.print("[yellow]No intelligence database found. Run 'dixie intel update' first.[/yellow]")
        return

    store = IntelStore(db_path)
    stats = store.stats()
    console.print(f"[bold]Total entries:[/bold] {stats['total_entries']}")
    console.print(f"[bold]Critical:[/bold] {stats['critical_count']}")
    console.print(f"[bold]By source:[/bold] {stats['by_source']}")
    console.print(f"[bold]By maturity:[/bold] {stats['by_maturity']}")

    for fs in store.get_feed_statuses():
        status_str = "OK" if fs.last_success else f"FAIL ({fs.consecutive_failures}x)"
        console.print(f"  {fs.source.value}: {status_str} | {fs.entries_total} entries")
    store.close()


@intel.command()
@click.argument("query")
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Database path")
@click.option("--min-severity", type=float, default=None, help="Minimum CVSS score")
def search(query: str, db: Path | None, min_severity: float | None) -> None:
    """Search the intelligence database for a product or CVE."""
    from dixie.intel.pipeline import DEFAULT_DB
    from dixie.intel.store import IntelStore

    db_path = db or DEFAULT_DB
    if not db_path.exists():
        console.print("[yellow]No intelligence database found. Run 'dixie intel update' first.[/yellow]")
        return

    store = IntelStore(db_path)

    if query.upper().startswith("CVE-"):
        results = store.query(cve_id=query.upper(), min_severity=min_severity)
    else:
        results = store.query(product=query, min_severity=min_severity)

    if not results:
        console.print(f"[yellow]No results for '{query}'[/yellow]")
    else:
        for entry in results:
            sev = f"[red]{entry.severity}[/red]" if entry.severity and entry.severity >= 9.0 else str(entry.severity or "N/A")
            console.print(f"  {sev} [{entry.exploit_maturity.value}] {entry.cve_id or ''} - {entry.title[:80]}")
            if entry.source_url:
                console.print(f"       [dim]{entry.source_url}[/dim]")
    store.close()


@intel.command()
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Database path")
@click.option("--hours", type=int, default=2, help="Look back N hours for critical findings")
@click.option("--email", default=None, help="Email address for alerts")
@click.option("--webhook", default=None, help="Webhook URL for alerts (Slack/Discord)")
def alert(db: Path | None, hours: int, email: str | None, webhook: str | None) -> None:
    """Check for critical findings and send alerts."""
    from dixie.intel.pipeline import DEFAULT_DB
    from dixie.intel.scheduler import (
        build_alert_digest,
        format_alert_text,
        send_email_alert,
        send_webhook_alert,
    )
    from dixie.intel.store import IntelStore

    db_path = db or DEFAULT_DB
    if not db_path.exists():
        console.print("[yellow]No intelligence database found.[/yellow]")
        return

    store = IntelStore(db_path)
    critical = build_alert_digest(store, hours=hours)

    if not critical:
        console.print(f"[green]No critical findings in the last {hours}h.[/green]")
        store.close()
        return

    text = format_alert_text(critical)
    console.print(text)

    if webhook:
        ok = send_webhook_alert(webhook, critical)
        console.print(f"Webhook: {'[green]sent[/green]' if ok else '[red]failed[/red]'}")
    if email:
        ok = send_email_alert(email, critical)
        console.print(f"Email: {'[green]sent[/green]' if ok else '[red]failed[/red]'}")

    store.close()


@intel.command()
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Database path")
@click.option("--model", default=DEFAULT_TRANSLATION_MODEL, help="LLM model for translation")
@click.option("--limit", type=int, default=50, help="Max entries to translate per run")
def translate(db: Path | None, model: str, limit: int) -> None:
    """Translate non-English entries in the intelligence database."""
    from dixie.intel.pipeline import DEFAULT_DB
    from dixie.intel.store import IntelStore
    from dixie.intel.translate import translate_pending

    db_path = db or DEFAULT_DB
    if not db_path.exists():
        console.print("[yellow]No intelligence database found.[/yellow]")
        return

    store = IntelStore(db_path)
    count = translate_pending(store, model=model, limit=limit)
    console.print(f"[bold]Translated {count} entries[/bold]")
    store.close()


@intel.command()
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Database path")
@click.option("--nvd-key", envvar="NVD_API_KEY", default=None, help="NVD API key")
@click.option("--email", default=None, help="Alert email address")
@click.option("--webhook", default=None, help="Alert webhook URL")
@click.option("--install", is_flag=True, help="Install to system crontab")
def schedule(db: Path | None, nvd_key: str | None, email: str | None, webhook: str | None, install: bool) -> None:
    """Generate or install crontab entries for automated collection."""
    from dixie.intel.scheduler import generate_crontab, install_crontab

    cron = generate_crontab(
        db_path=db, nvd_key=nvd_key,
        alert_email=email, alert_webhook=webhook,
    )

    if install:
        ok = install_crontab(cron)
        if ok:
            console.print("[green]Crontab installed successfully.[/green]")
        else:
            console.print("[red]Failed to install crontab.[/red]")
    else:
        console.print("[bold]Generated crontab entries:[/bold]")
        console.print(cron)
        console.print("[dim]Run with --install to add to system crontab[/dim]")
