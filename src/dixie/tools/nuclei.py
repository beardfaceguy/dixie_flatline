"""Nuclei tool plugin for template-based vulnerability scanning."""

from __future__ import annotations

import json
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class NucleiTool(Tool):
    name = "nuclei"
    description = (
        "Run Nuclei vulnerability scanner with community templates. Detects "
        "known CVEs, misconfigurations, exposed panels, default credentials, "
        "and technology-specific issues."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target URL or host (e.g. 'http://192.168.1.1' or '192.168.1.1')",
            required=True,
        ),
        ToolParameter(
            name="templates",
            description=(
                "Template filter: tag names (e.g. 'cve,misconfig'), "
                "severity filter ('critical,high'), or template path"
            ),
        ),
        ToolParameter(
            name="severity",
            description="Filter by severity: critical, high, medium, low, info",
        ),
        ToolParameter(
            name="extra_args",
            description="Additional nuclei arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["nuclei", "-jsonl", "-silent"]

        target = kwargs["target"]
        cmd.extend(["-target", target])

        templates = kwargs.get("templates")
        if templates:
            if "/" in templates or templates.endswith(".yaml"):
                cmd.extend(["-t", templates])
            else:
                cmd.extend(["-tags", templates])

        severity = kwargs.get("severity")
        if severity:
            cmd.extend(["-severity", severity])

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        return cmd

    def parse_output(self, raw_output: str) -> dict:
        findings: list[dict[str, Any]] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            findings.append({
                "template_id": entry.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "matched_at": entry.get("matched-at", ""),
                "description": info.get("description", ""),
                "reference": info.get("reference", []),
                "tags": info.get("tags", []),
                "matcher_name": entry.get("matcher-name", ""),
                "extracted_results": entry.get("extracted-results", []),
            })

        severity_counts = {}
        for f in findings:
            s = f["severity"]
            severity_counts[s] = severity_counts.get(s, 0) + 1

        return {
            "findings": findings,
            "total": len(findings),
            "severity_breakdown": severity_counts,
        }
