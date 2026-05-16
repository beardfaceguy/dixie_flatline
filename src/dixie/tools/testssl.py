"""testssl.sh tool plugin for comprehensive SSL/TLS testing."""

from __future__ import annotations

import json
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class TestSSLTool(Tool):
    name = "testssl"
    description = (
        "Run comprehensive SSL/TLS analysis using testssl.sh. Checks for "
        "protocol support, cipher suites, known vulnerabilities (Heartbleed, "
        "POODLE, BEAST, CRIME, etc.), certificate details, and HTTP security "
        "headers."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target host:port (e.g. '192.168.1.1:443')",
            required=True,
        ),
        ToolParameter(
            name="checks",
            description=(
                "Specific checks to run: 'full' (default), 'protocols', "
                "'ciphers', 'vulnerabilities', 'headers'"
            ),
            default="full",
        ),
        ToolParameter(
            name="extra_args",
            description="Additional testssl.sh arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["testssl.sh", "--jsonfile=-", "--quiet", "--color", "0"]

        checks = kwargs.get("checks", "full")
        check_flags = {
            "protocols": "-p",
            "ciphers": "-E",
            "vulnerabilities": "-U",
            "headers": "-h",
        }
        if checks != "full" and checks in check_flags:
            cmd.append(check_flags[checks])

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        cmd.append(kwargs["target"])
        return cmd

    def parse_output(self, raw_output: str) -> dict:
        findings: list[dict[str, Any]] = []
        vulnerabilities: list[str] = []
        protocols: list[dict[str, Any]] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                if line.startswith("["):
                    try:
                        entries = json.loads(raw_output)
                        for e in entries:
                            self._process_entry(e, findings, vulnerabilities, protocols)
                        break
                    except json.JSONDecodeError:
                        pass
                continue
            self._process_entry(entry, findings, vulnerabilities, protocols)

        return {
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "protocols": protocols,
            "issues_count": len(vulnerabilities),
        }

    def _process_entry(
        self,
        entry: dict,
        findings: list[dict],
        vulnerabilities: list[str],
        protocols: list[dict],
    ) -> None:
        severity = entry.get("severity", "INFO")
        finding_id = entry.get("id", "")
        finding_text = entry.get("finding", "")

        if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"):
            findings.append({
                "id": finding_id,
                "severity": severity,
                "finding": finding_text,
            })
            if severity in ("CRITICAL", "HIGH"):
                vulnerabilities.append(f"{finding_id}: {finding_text}")

        if "protocol" in finding_id.lower() or finding_id.startswith("SSLv") or finding_id.startswith("TLS"):
            protocols.append({
                "name": finding_id,
                "status": finding_text,
                "severity": severity,
            })
