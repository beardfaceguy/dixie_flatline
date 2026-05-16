"""Masscan tool plugin for high-speed port scanning."""

from __future__ import annotations

import json
import re
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class MasscanTool(Tool):
    name = "masscan"
    description = (
        "Run masscan for extremely fast port scanning of large networks. "
        "Best for initial discovery across subnets. Use nmap for deeper "
        "service enumeration after hosts are found."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target IP, CIDR range, or space-separated ranges",
            required=True,
        ),
        ToolParameter(
            name="ports",
            description="Port specification (e.g. '80,443', '0-1024', '0-65535')",
            required=True,
        ),
        ToolParameter(
            name="rate",
            description="Packets per second (default 1000, max 10000 for safe scanning)",
            type="number",
            default=1000,
        ),
        ToolParameter(
            name="extra_args",
            description="Additional masscan arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["masscan", "--output-format", "json", "--output-filename", "-"]

        cmd.append(kwargs["target"])
        cmd.extend(["-p", kwargs["ports"]])

        rate = kwargs.get("rate", 1000)
        cmd.extend(["--rate", str(int(rate))])

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        return cmd

    def parse_output(self, raw_output: str) -> dict:
        hosts: dict[str, list[dict]] = {}

        for line in raw_output.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = entry.get("ip", "unknown")
            for port_info in entry.get("ports", []):
                if ip not in hosts:
                    hosts[ip] = []
                hosts[ip].append({
                    "port": port_info.get("port"),
                    "protocol": port_info.get("proto", "tcp"),
                    "state": port_info.get("status", "open"),
                })

        return {
            "hosts_found": len(hosts),
            "hosts": {ip: {"ports": ports} for ip, ports in hosts.items()},
        }
