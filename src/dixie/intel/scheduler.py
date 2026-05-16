"""Cron-based scheduling and alerting for the threat intelligence pipeline.

Generates crontab entries and produces alert digests for critical findings.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from dixie.intel.schema import ThreatEntry
from dixie.intel.store import IntelStore

logger = logging.getLogger(__name__)

CRON_COMMENT = "# dixie-flatline threat intel"
# Suffix on managed lines so install strips prior blocks even when log path env changes.
CRON_TAG = "# dixie-intel-managed"


def _intel_tier_schedule_rows(
    base_cmd: str,
    alert_cmd: str,
    logf: str,
) -> list[tuple[str, str]]:
    return [
        (
            "# Tier 1: structured APIs every 2 hours",
            f"0 */2 * * * {base_cmd} --tier 1 >> {logf} 2>&1",
        ),
        (
            "# Tier 2: exploit feeds every 6 hours",
            f"0 */6 * * * {base_cmd} --tier 2 >> {logf} 2>&1",
        ),
        (
            "# Tier 3: social/OSINT daily at 6am UTC",
            f"0 6 * * * {base_cmd} --tier 3 >> {logf} 2>&1",
        ),
        (
            "# Check for critical alerts every 2 hours",
            f"15 */2 * * * {alert_cmd} >> {logf} 2>&1",
        ),
    ]


def _tag_managed_line(line: str) -> str:
    return f"{line.rstrip()} {CRON_TAG}"


def _managed_dixie_intel_log_path() -> str:
    """Log path embedded in generator/install crontab lines Dixie owns and replaces.

    Set ``DIXIE_INTEL_CRON_LOG_PATH`` when ``/var/log`` is not writable.
    """
    return (
        os.environ.get("DIXIE_INTEL_CRON_LOG_PATH", "").strip()
        or "/var/log/dixie-intel.log"
    )


def _dixie_cli_invocation() -> str:
    override = (os.environ.get("DIXIE_CRON_CLI") or "").strip()
    if override:
        return override
    return f"{sys.executable} -m dixie"


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
    dixie_bin = _dixie_cli_invocation()
    base_cmd = f"{dixie_bin} intel update --db {db}"
    if nvd_key:
        base_cmd += f" --nvd-key {nvd_key}"

    alert_cmd = f"{dixie_bin} intel alert --db {db}"
    if alert_email:
        alert_cmd += f" --email {alert_email}"
    if alert_webhook:
        alert_cmd += f" --webhook {alert_webhook}"

    logf = _managed_dixie_intel_log_path()
    lines = [_tag_managed_line(CRON_COMMENT)]
    for comment, schedule in _intel_tier_schedule_rows(base_cmd, alert_cmd, logf):
        lines.append(_tag_managed_line(comment))
        lines.append(_tag_managed_line(schedule))

    return "\n".join(lines) + "\n"


def _is_managed_intel_cron_line(line: str) -> bool:
    """True only for Dixie-managed markers (tagged lines or legacy header)."""
    if CRON_TAG in line:
        return True
    return line.strip() == CRON_COMMENT


def install_crontab(cron_entries: str) -> bool:
    """Install crontab entries, preserving existing non-dixie entries.

    Removes only lines that include ``CRON_TAG`` (current generator output) or
    are exactly the legacy ``CRON_COMMENT`` header line. Other comments or
    custom ``dixie intel`` jobs are left untouched. Crontab rows from older
    Dixie builds without ``CRON_TAG`` may need a one-time manual delete before
    reinstalling to avoid duplicate schedules.
    """
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True
        )
        existing = result.stdout if result.returncode == 0 else ""
    except FileNotFoundError:
        logger.error("crontab command not found")
        return False

    filtered = [
        line for line in existing.splitlines() if not _is_managed_intel_cron_line(line)
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
