"""Pseudo-tool that lets the LLM register structured findings.

Unlike other tools that wrap CLI binaries, this tool is handled directly
by the agent loop -- it creates a Finding and adds it to EngagementState.
"""

from __future__ import annotations

from typing import Any

from dixie.tools.base import Tool, ToolParameter


class ReportFindingTool(Tool):
    name = "report_finding"
    description = (
        "Report a security finding discovered during the engagement. Call this "
        "whenever you identify a vulnerability, misconfiguration, or security issue. "
        "Provide structured details including severity, evidence, and remediation."
    )
    parameters = [
        ToolParameter(
            name="title",
            description="Short title for the finding (e.g. 'SQL Injection in Login Form')",
            required=True,
        ),
        ToolParameter(
            name="description",
            description="Detailed description of the vulnerability or issue",
            required=True,
        ),
        ToolParameter(
            name="severity",
            description="Severity level: critical, high, medium, low, or info",
            required=True,
        ),
        ToolParameter(
            name="confidence",
            description="Confidence level: confirmed, firm, or tentative",
            default="tentative",
        ),
        ToolParameter(
            name="evidence",
            description="Evidence supporting the finding (tool output, error messages, etc.)",
        ),
        ToolParameter(
            name="remediation",
            description="Recommended fix or mitigation",
        ),
        ToolParameter(
            name="affected_assets",
            description="Comma-separated list of affected hosts/ports/URLs",
        ),
        ToolParameter(
            name="cvss_score",
            description="CVSS v3.1 base score (0.0-10.0) if known",
            type="number",
        ),
        ToolParameter(
            name="cve_ids",
            description="Comma-separated CVE IDs if applicable (e.g. 'CVE-2024-1234,CVE-2024-5678')",
        ),
        ToolParameter(
            name="cwe_ids",
            description="Comma-separated CWE IDs if applicable (e.g. 'CWE-89,CWE-79')",
        ),
        ToolParameter(
            name="attack_techniques",
            description="Comma-separated MITRE ATT&CK technique IDs (e.g. 'T1190,T1068')",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        raise NotImplementedError("report_finding is handled by the agent, not the sandbox")

    def parse_output(self, raw_output: str) -> dict:
        raise NotImplementedError("report_finding is handled by the agent, not the sandbox")
