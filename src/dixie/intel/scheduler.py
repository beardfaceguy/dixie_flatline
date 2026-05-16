"""Cron-based scheduling and alerting for the threat intelligence pipeline.

Generates crontab entries and produces alert digests for critical findings.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from dixie.intel.schema import ThreatEntry
from dixie.intel.store import IntelStore

logger = logging.getLogger(__name__)

CRON_COMMENT = "# dixie-flatline threat intel"
DIXIE_BIN = sys.executable.replace("python3", "dixie").replace("python", "dixie")


def generate_crontab(
    db_path: Path | None = None,
    nvd_key: str | None = None,
    alert_email: str | None = None,
    alert_webhook: str | None = None,
) -> str:
    """Generate crontab entries for the intel pipeline.

    Tier 1 (APIs): every 2 hours
    Tier 2 (feeds): every 6 hours
    Tier 3 (social): daily at 6am
    Alerts: every 2 hours after tier 1 runs
    """
    from dixie.intel.pipeline import DEFAULT_DB

    db = db_path or DEFAULT_DB
    base_cmd = f"{DIXIE_BIN} intel update --db {db}"
    if nvd_key:
        base_cmd += f" --nvd-key {nvd_key}"

    alert_cmd = f"{DIXIE_BIN} intel alert --db {db}"
    if alert_email:
        alert_cmd += f" --email {alert_email}"
    if alert_webhook:
        alert_cmd += f" --webhook {alert_webhook}"

    lines = [
        CRON_COMMENT,
        f"# Tier 1: structured APIs every 2 hours",
        f"0 */2 * * * {base_cmd} --tier 1 >> /var/log/dixie-intel.log 2>&1",
        f"# Tier 2: exploit feeds every 6 hours",
        f"0 */6 * * * {base_cmd} --tier 2 >> /var/log/dixie-intel.log 2>&1",
        f"# Tier 3: social/OSINT daily at 6am UTC",
        f"0 6 * * * {base_cmd} --tier 3 >> /var/log/dixie-intel.log 2>&1",
        f"# Check for critical alerts every 2 hours",
        f"15 */2 * * * {alert_cmd} >> /var/log/dixie-intel.log 2>&1",
    ]

    return "\n".join(lines) + "\n"


def install_crontab(cron_entries: str) -> bool:
    """Install crontab entries, preserving existing non-dixie entries."""
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True
        )
        existing = result.stdout if result.returncode == 0 else ""
    except FileNotFoundError:
        logger.error("crontab command not found")
        return False

    # Remove old dixie entries
    filtered = [
        line for line in existing.splitlines()
        if CRON_COMMENT not in line and "dixie intel" not in line
    ]

    new_crontab = "\n".join(filtered).strip() + "\n\n" + cron_entries

    result = subprocess.run(
        ["crontab", "-"], input=new_crontab, capture_output=True, text=True
    )

    if result.returncode != 0:
        logger.error("Failed to install crontab: %s", result.stderr)
        return False

    return True


def build_alert_digest(
    store: IntelStore,
    hours: int = 2,
) -> list[ThreatEntry]:
    """Find critical entries from the last N hours that need alerting.

    Critical = CVSS >= 9.0 OR actively exploited OR CISA KEV addition.
    """
    return store.get_critical_recent(hours=hours)


def format_alert_text(entries: list[ThreatEntry]) -> str:
    """Format alert entries as a text digest."""
    if not entries:
        return ""

    lines = [
        f"🚨 DIXIE FLATLINE - {len(entries)} Critical Finding(s)",
        f"   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    for entry in entries:
        sev = f"CVSS {entry.severity}" if entry.severity else "N/A"
        lines.append(f"  [{sev}] {entry.cve_id or 'N/A'}")
        lines.append(f"  {entry.title[:100]}")
        lines.append(f"  Maturity: {entry.exploit_maturity.value}")
        if entry.source_url:
            lines.append(f"  {entry.source_url}")
        lines.append("")

    return "\n".join(lines)


def send_webhook_alert(webhook_url: str, entries: list[ThreatEntry]) -> bool:
    """Send alert to a webhook (Slack, Discord, etc.)."""
    import httpx

    text = format_alert_text(entries)
    if not text:
        return True

    try:
        resp = httpx.post(
            webhook_url,
            json={"text": text, "content": text},  # text=Slack, content=Discord
            timeout=10,
        )
        return resp.status_code < 400
    except Exception as e:
        logger.error("Webhook alert failed: %s", e)
        return False


def send_email_alert(email: str, entries: list[ThreatEntry]) -> bool:
    """Send alert via local sendmail."""
    text = format_alert_text(entries)
    if not text:
        return True

    subject = f"Dixie Flatline: {len(entries)} Critical Finding(s)"
    message = f"Subject: {subject}\nTo: {email}\n\n{text}"

    try:
        result = subprocess.run(
            ["sendmail", email],
            input=message,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception as e:
        logger.error("Email alert failed: %s", e)
        return False
