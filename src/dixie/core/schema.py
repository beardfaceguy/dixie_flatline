"""Data models for engagement state, findings, and tool results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolResult(BaseModel):
    tool: str
    command: str
    raw_output: str
    structured: dict | None = None
    success: bool = True
    error: str | None = None
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"


class Finding(BaseModel):
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.TENTATIVE
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    found_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Backward compat: accept the old singular field
    @property
    def attack_technique(self) -> str | None:
        return self.attack_techniques[0] if self.attack_techniques else None


class EngagementState(BaseModel):
    """Tracks the full state of a penetration testing engagement."""

    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    iteration: int = 0
    phase: str = "reconnaissance"
    discoveries: list[dict] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    tool_history: list[ToolResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    termination_reason: str | None = None

    def add_result(self, result: ToolResult) -> None:
        self.tool_history.append(result)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> dict:
        return {
            "target": self.target,
            "phase": self.phase,
            "iteration": self.iteration,
            "findings_count": len(self.findings),
            "tools_run": len(self.tool_history),
            "severity_breakdown": {
                s.value: sum(1 for f in self.findings if f.severity == s) for s in Severity
            },
        }
