"""Nikto tool plugin for web server vulnerability scanning."""

from __future__ import annotations

import re
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class NiktoTool(Tool):
    name = "nikto_scan"
    description = (
        "Run nikto against a web server to identify known vulnerabilities, "
        "misconfigurations, outdated software, and dangerous files/programs."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target URL or host (e.g. 'http://target.com' or '192.168.1.1')",
            required=True,
        ),
        ToolParameter(
            name="port",
            description="Port to scan",
            type="integer",
            default=80,
        ),
        ToolParameter(
            name="ssl",
            description="Use SSL/TLS",
            type="boolean",
            default=False,
        ),
        ToolParameter(
            name="tuning",
            description=(
                "Scan tuning: 1=files, 2=misconfig, 3=info disclosure, "
                "4=injection, 5=file retrieval, 6=DoS, 7=remote file retrieval, "
                "8=command exec, 9=SQL injection, 0=file upload"
            ),
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        # Plain text (+ OSVDB / + header lines) so parse_output matches real runs.
        cmd = ["nikto", "-h", kwargs["target"]]

        port = kwargs.get("port", 80)
        cmd.extend(["-p", str(port)])

        if kwargs.get("ssl"):
            cmd.append("-ssl")

        tuning = kwargs.get("tuning")
        if tuning:
            cmd.extend(["-Tuning", tuning])

        return cmd

    def parse_output(self, raw_output: str) -> dict:
        vulnerabilities = []
        for line in raw_output.splitlines():
            if line.startswith('"') and "OSVDB" in line:
                parts = line.strip('"').split('","')
                if len(parts) >= 4:
                    vulnerabilities.append({
                        "id": parts[1] if len(parts) > 1 else "",
                        "method": parts[2] if len(parts) > 2 else "",
                        "path": parts[3] if len(parts) > 3 else "",
                        "description": parts[4] if len(parts) > 4 else "",
                    })
                continue

            osvdb_match = re.match(r"\+\s+(OSVDB-\d+):\s+(.+)", line)
            if osvdb_match:
                vulnerabilities.append({
                    "id": osvdb_match.group(1),
                    "method": "",
                    "path": "",
                    "description": osvdb_match.group(2),
                })
                continue

            plain_plus = re.match(r"\+\s+(.+?):\s+(.+)", line)
            if plain_plus:
                vulnerabilities.append({
                    "id": "",
                    "method": "",
                    "path": plain_plus.group(1).strip(),
                    "description": plain_plus.group(2).strip(),
                })

        return {
            "vulnerabilities": vulnerabilities,
            "total_found": len(vulnerabilities),
        }
