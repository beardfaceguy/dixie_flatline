"""Report models for structured pentest engagement output.

Loosely follows the OWASP OPTRS (Offensive Penetration Testing Reporting Standard)
structure: metadata, scope, executive summary, findings, methodology, and appendices.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from dixie.core.schema import EngagementState, Finding, Severity
from dixie.reporting.mitre import resolve_technique_chain


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"


class TimelineEntry(BaseModel):
    """Single event in the attack timeline."""

    timestamp: datetime
    phase: str
    action: str
    tool: str | None = None
    technique_id: str | None = None
    result_summary: str = ""
    success: bool = True


class ScopeDefinition(BaseModel):
    """Engagement scope boundaries."""

    targets: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rules_of_engagement: list[str] = Field(default_factory=list)
    methodology: str = "PTES (Penetration Testing Execution Standard)"


class RiskSummary(BaseModel):
    """Aggregate risk metrics across all findings."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    max_cvss: float | None = None
    unique_cves: list[str] = Field(default_factory=list)
    unique_techniques: list[str] = Field(default_factory=list)
    unique_tactics: list[str] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> RiskSummary:
        severity_counts = {s: 0 for s in Severity}
        all_cves: set[str] = set()
        all_techniques: set[str] = set()
        all_tactics: set[str] = set()
        max_cvss: float | None = None

        for f in findings:
            severity_counts[f.severity] += 1
            all_cves.update(f.cve_ids)
            all_techniques.update(f.attack_techniques)
            if f.cvss_score is not None:
                max_cvss = max(max_cvss or 0.0, f.cvss_score)

        for tech, tactics in resolve_technique_chain(list(all_techniques)):
            for tactic in tactics:
                all_tactics.add(tactic.id)

        return cls(
            total_findings=len(findings),
            critical=severity_counts[Severity.CRITICAL],
            high=severity_counts[Severity.HIGH],
            medium=severity_counts[Severity.MEDIUM],
            low=severity_counts[Severity.LOW],
            info=severity_counts[Severity.INFO],
            max_cvss=max_cvss,
            unique_cves=sorted(all_cves),
            unique_techniques=sorted(all_techniques),
            unique_tactics=sorted(all_tactics),
        )

    @property
    def overall_risk(self) -> str:
        if self.critical > 0:
            return "Critical"
        if self.high > 0:
            return "High"
        if self.medium > 0:
            return "Medium"
        if self.low > 0:
            return "Low"
        return "Informational"


class EngagementReport(BaseModel):
    """Top-level engagement report following OWASP OPTRS structure."""

    title: str = "Penetration Test Report"
    engagement_id: str = ""
    prepared_by: str = "Dixie Flatline"
    prepared_for: str = ""
    report_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0"

    scope: ScopeDefinition = Field(default_factory=ScopeDefinition)
    executive_summary: str = ""
    risk_summary: RiskSummary = Field(default_factory=RiskSummary)
    findings: list[Finding] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    methodology_notes: str = ""
    tools_used: list[str] = Field(default_factory=list)
    duration_seconds: int = 0

    @classmethod
    def from_engagement(
        cls,
        state: EngagementState,
        *,
        title: str = "Penetration Test Report",
        prepared_for: str = "",
    ) -> EngagementReport:
        """Build a report from a completed engagement state."""
        sorted_findings = sorted(
            state.findings,
            key=lambda f: list(Severity).index(f.severity),
        )

        timeline = []
        for result in state.tool_history:
            timeline.append(TimelineEntry(
                timestamp=result.timestamp,
                phase="execution",
                action=f"Ran {result.tool}",
                tool=result.tool,
                result_summary=result.raw_output[:200] if result.raw_output else "",
                success=result.success,
            ))

        tools_used = sorted({r.tool for r in state.tool_history})

        duration = 0
        if state.tool_history:
            first = state.started_at
            last = state.tool_history[-1].timestamp
            duration = int((last - first).total_seconds())

        risk = RiskSummary.from_findings(sorted_findings)

        executive_summary = _generate_executive_summary(
            state.target, risk, tools_used, duration,
        )

        return cls(
            title=title,
            prepared_for=prepared_for,
            scope=ScopeDefinition(targets=[state.target]),
            executive_summary=executive_summary,
            risk_summary=risk,
            findings=sorted_findings,
            timeline=timeline,
            tools_used=tools_used,
            duration_seconds=duration,
        )


def _generate_executive_summary(
    target: str,
    risk: RiskSummary,
    tools: list[str],
    duration_s: int,
) -> str:
    hours = duration_s // 3600
    minutes = (duration_s % 3600) // 60
    duration_str = f"{hours}h {minutes}m" if hours else f"{minutes}m"

    lines = [
        f"A penetration test was conducted against **{target}** using automated "
        f"and manual techniques over a period of {duration_str}.",
        "",
        f"The assessment identified **{risk.total_findings} findings** with an "
        f"overall risk rating of **{risk.overall_risk}**:",
        "",
    ]

    if risk.critical:
        lines.append(f"- **{risk.critical} Critical** — immediate action required")
    if risk.high:
        lines.append(f"- **{risk.high} High** — remediate within 7 days")
    if risk.medium:
        lines.append(f"- **{risk.medium} Medium** — remediate within 30 days")
    if risk.low:
        lines.append(f"- **{risk.low} Low** — address during next maintenance cycle")
    if risk.info:
        lines.append(f"- **{risk.info} Informational** — no immediate action required")

    if risk.max_cvss is not None:
        lines.extend(["", f"The highest CVSS score observed was **{risk.max_cvss:.1f}**."])

    if risk.unique_cves:
        cve_list = ", ".join(risk.unique_cves[:10])
        suffix = f" (+{len(risk.unique_cves) - 10} more)" if len(risk.unique_cves) > 10 else ""
        lines.extend(["", f"CVEs identified: {cve_list}{suffix}"])

    if tools:
        lines.extend(["", f"Tools employed: {', '.join(tools)}."])

    return "\n".join(lines)
