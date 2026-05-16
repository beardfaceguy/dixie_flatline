"""ARP scan tool plugin for local network host discovery."""

from __future__ import annotations

import re
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class ArpScanTool(Tool):
    name = "arp_scan"
    description = (
        "Discover hosts on the local network using ARP requests. "
        "Fast and reliable for LAN host discovery. Returns MAC addresses "
        "and vendor information."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target subnet (e.g. '192.168.1.0/24') or '--localnet' for auto-detect",
            required=True,
        ),
        ToolParameter(
            name="interface",
            description="Network interface to use (e.g. 'eth0'). Auto-detected if omitted.",
        ),
        ToolParameter(
            name="extra_args",
            description="Additional arp-scan arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["arp-scan"]

        interface = kwargs.get("interface")
        if interface:
            cmd.extend(["-I", interface])

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        cmd.append(kwargs["target"])
        return cmd

    def parse_output(self, raw_output: str) -> dict:
        hosts: list[dict[str, str]] = []

        for line in raw_output.splitlines():
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)", line
            )
            if match:
                hosts.append({
                    "ip": match.group(1),
                    "mac": match.group(2),
                    "vendor": match.group(3).strip(),
                })

        return {
            "hosts_found": len(hosts),
            "hosts": hosts,
        }
