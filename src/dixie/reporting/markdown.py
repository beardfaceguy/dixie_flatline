"""Markdown report generator for engagement reports."""

from __future__ import annotations

from dixie.core.schema import Finding, Severity
from dixie.reporting.mitre import get_technique, tactics_for_technique, technique_url
from dixie.reporting.models import EngagementReport

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render(report: EngagementReport) -> str:
    sections = [
        _header(report),
        _table_of_contents(report),
        _executive_summary(report),
        _scope(report),
        _risk_summary(report),
        _findings(report),
        _mitre_matrix(report),
        _timeline(report),
        _methodology(report),
    ]
    return "\n\n---\n\n".join(s for s in sections if s)


def _header(report: EngagementReport) -> str:
    lines = [
        f"# {report.title}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Prepared by** | {report.prepared_by} |",
    ]
    if report.prepared_for:
        lines.append(f"| **Prepared for** | {report.prepared_for} |")
    lines.append(f"| **Date** | {report.report_date.strftime('%Y-%m-%d')} |")
    if report.engagement_id:
        lines.append(f"| **Engagement ID** | {report.engagement_id} |")
    lines.append(f"| **Version** | {report.version} |")
    return "\n".join(lines)


def _table_of_contents(report: EngagementReport) -> str:
    toc = [
        "## Table of Contents",
        "",
        "1. [Executive Summary](#executive-summary)",
        "2. [Scope](#scope)",
        "3. [Risk Summary](#risk-summary)",
        "4. [Findings](#findings)",
    ]
    for i, f in enumerate(report.findings, 1):
        slug = f.title.lower().replace(" ", "-").replace("/", "")
        toc.append(f"   - {i}. [{f.title}](#{slug})")
    toc.extend([
        "5. [MITRE ATT&CK Coverage](#mitre-attck-coverage)",
        "6. [Attack Timeline](#attack-timeline)",
        "7. [Methodology](#methodology)",
    ])
    return "\n".join(toc)


def _executive_summary(report: EngagementReport) -> str:
    return f"## Executive Summary\n\n{report.executive_summary}"


def _scope(report: EngagementReport) -> str:
    lines = ["## Scope", ""]
    if report.scope.targets:
        lines.append("**In-scope targets:**")
        for t in report.scope.targets:
            lines.append(f"- `{t}`")
        lines.append("")
    if report.scope.out_of_scope:
        lines.append("**Out of scope:**")
        for t in report.scope.out_of_scope:
            lines.append(f"- `{t}`")
        lines.append("")
    if report.scope.rules_of_engagement:
        lines.append("**Rules of engagement:**")
        for r in report.scope.rules_of_engagement:
            lines.append(f"- {r}")
        lines.append("")
    lines.append(f"**Methodology:** {report.scope.methodology}")
    return "\n".join(lines)


def _risk_summary(report: EngagementReport) -> str:
    r = report.risk_summary
    lines = [
        "## Risk Summary",
        "",
        f"**Overall risk rating: {r.overall_risk}**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {r.critical} |",
        f"| 🟠 High | {r.high} |",
        f"| 🟡 Medium | {r.medium} |",
        f"| 🔵 Low | {r.low} |",
        f"| ⚪ Informational | {r.info} |",
        f"| **Total** | **{r.total_findings}** |",
    ]
    if r.max_cvss is not None:
        lines.extend(["", f"**Highest CVSS:** {r.max_cvss:.1f}"])
    if r.unique_techniques:
        lines.extend(["", f"**MITRE ATT&CK techniques observed:** {len(r.unique_techniques)}"])
        lines.append(f"**Tactics covered:** {len(r.unique_tactics)}")
    return "\n".join(lines)


def _findings(report: EngagementReport) -> str:
    if not report.findings:
        return "## Findings\n\nNo findings identified."

    sections = ["## Findings"]
    for i, finding in enumerate(report.findings, 1):
        sections.append(_render_finding(i, finding))
    return "\n\n".join(sections)


def _render_finding(index: int, finding: Finding) -> str:
    emoji = SEVERITY_EMOJI.get(finding.severity, "")
    lines = [
        f"### {index}. {finding.title}",
        "",
        "| Property | Value |",
        "|----------|-------|",
        f"| **Severity** | {emoji} {finding.severity.value.upper()} |",
        f"| **Confidence** | {finding.confidence.value.title()} |",
    ]
    if finding.cvss_score is not None:
        cvss_line = f"{finding.cvss_score:.1f}"
        if finding.cvss_vector:
            cvss_line += f" ({finding.cvss_vector})"
        lines.append(f"| **CVSS** | {cvss_line} |")
    if finding.cve_ids:
        cves = ", ".join(f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in finding.cve_ids)
        lines.append(f"| **CVE(s)** | {cves} |")
    if finding.cwe_ids:
        cwes = ", ".join(f"[{c}](https://cwe.mitre.org/data/definitions/{c.split('-')[-1]}.html)"
                         for c in finding.cwe_ids)
        lines.append(f"| **CWE(s)** | {cwes} |")
    if finding.affected_assets:
        lines.append(f"| **Affected assets** | {', '.join(f'`{a}`' for a in finding.affected_assets)} |")

    lines.extend(["", "**Description:**", "", finding.description])

    if finding.evidence:
        lines.extend(["", "**Evidence:**", ""])
        for ev in finding.evidence:
            lines.append(f"```\n{ev}\n```")

    if finding.attack_techniques:
        lines.extend(["", "**MITRE ATT&CK:**", ""])
        for tid in finding.attack_techniques:
            tech = get_technique(tid)
            name = tech.name if tech else tid
            url = technique_url(tid)
            tactics = tactics_for_technique(tid)
            tactic_str = ", ".join(t.name for t in tactics) if tactics else "Unknown"
            lines.append(f"- [{tid}: {name}]({url}) ({tactic_str})")

    if finding.remediation:
        lines.extend(["", "**Remediation:**", "", finding.remediation])

    return "\n".join(lines)


def _mitre_matrix(report: EngagementReport) -> str:
    all_techniques: set[str] = set()
    for f in report.findings:
        all_techniques.update(f.attack_techniques)

    if not all_techniques:
        return ""

    tactic_techniques: dict[str, list[str]] = {}
    for tid in sorted(all_techniques):
        tech = get_technique(tid)
        if not tech:
            continue
        for tactic_id in tech.tactic_ids:
            tactic_techniques.setdefault(tactic_id, []).append(tid)

    lines = [
        "## MITRE ATT&CK Coverage",
        "",
        "Techniques observed during this engagement, organized by tactic:",
        "",
    ]

    from dixie.reporting.mitre import TACTICS
    for tactic_id in TACTICS:
        if tactic_id not in tactic_techniques:
            continue
        tactic = TACTICS[tactic_id]
        lines.append(f"### {tactic.name} ({tactic_id})")
        lines.append("")
        for tid in tactic_techniques[tactic_id]:
            tech = get_technique(tid)
            name = tech.name if tech else tid
            url = technique_url(tid)
            count = sum(
                1 for f in report.findings if tid in f.attack_techniques
            )
            lines.append(f"- [{tid}: {name}]({url}) — {count} finding(s)")
        lines.append("")

    return "\n".join(lines)


def _timeline(report: EngagementReport) -> str:
    if not report.timeline:
        return "## Attack Timeline\n\nNo timeline entries recorded."

    lines = [
        "## Attack Timeline",
        "",
        "| Time (UTC) | Phase | Action | Tool | Result |",
        "|------------|-------|--------|------|--------|",
    ]
    for entry in report.timeline:
        time_str = entry.timestamp.strftime("%H:%M:%S")
        result = "✅" if entry.success else "❌"
        summary = entry.result_summary[:60].replace("|", "\\|").replace("\n", " ")
        tool = entry.tool or "—"
        lines.append(f"| {time_str} | {entry.phase} | {entry.action} | {tool} | {result} {summary} |")

    return "\n".join(lines)


def _methodology(report: EngagementReport) -> str:
    lines = [
        "## Methodology",
        "",
        f"**Framework:** {report.scope.methodology}",
        "",
    ]
    if report.tools_used:
        lines.append("**Tools used:**")
        lines.append("")
        for tool in report.tools_used:
            lines.append(f"- {tool}")
        lines.append("")

    if report.methodology_notes:
        lines.extend(["**Notes:**", "", report.methodology_notes])

    hours = report.duration_seconds // 3600
    minutes = (report.duration_seconds % 3600) // 60
    duration_str = f"{hours}h {minutes}m" if hours else f"{minutes}m"
    lines.append(f"\n**Total engagement duration:** {duration_str}")

    return "\n".join(lines)
