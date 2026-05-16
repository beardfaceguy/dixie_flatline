"""Nmap tool plugin for port scanning and service detection."""

from __future__ import annotations

import re
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class NmapTool(Tool):
    name = "nmap_scan"
    description = (
        "Run an nmap scan against a target to discover open ports, running services, "
        "and OS information. Supports TCP SYN, version detection, and script scanning."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target IP address, hostname, or CIDR range",
            required=True,
        ),
        ToolParameter(
            name="ports",
            description="Port specification (e.g. '22,80,443', '1-1024', '-' for all)",
            default="--top-ports 1000",
        ),
        ToolParameter(
            name="scan_type",
            description="Scan type: 'syn' (default, fast), 'connect', 'udp', 'version'",
            default="syn",
        ),
        ToolParameter(
            name="scripts",
            description="NSE scripts to run (e.g. 'default', 'vuln', 'http-enum')",
        ),
        ToolParameter(
            name="extra_args",
            description="Additional nmap arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["nmap", "-oX", "-"]  # XML output to stdout for parsing

        scan_type = kwargs.get("scan_type", "syn")
        scan_flags = {
            "syn": "-sS",
            "connect": "-sT",
            "udp": "-sU",
            "version": "-sV",
        }
        cmd.append(scan_flags.get(scan_type, "-sS"))

        ports = kwargs.get("ports")
        if ports and not ports.startswith("--"):
            cmd.extend(["-p", ports])
        elif ports:
            cmd.append(ports)

        scripts = kwargs.get("scripts")
        if scripts:
            cmd.extend(["--script", scripts])

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        cmd.append(kwargs["target"])
        return cmd

    def parse_output(self, raw_output: str) -> dict:
        """Parse nmap output into structured results.

        Handles both XML (-oX) and normal text output.
        """
        hosts = []
        current_host: dict[str, Any] | None = None
        current_ports: list[dict] = []

        for line in raw_output.splitlines():
            host_match = re.match(r"Nmap scan report for (.+?)(?:\s+\((.+?)\))?$", line)
            if host_match:
                if current_host:
                    current_host["ports"] = current_ports
                    hosts.append(current_host)
                hostname = host_match.group(1)
                ip = host_match.group(2) or hostname
                current_host = {"hostname": hostname, "ip": ip}
                current_ports = []
                continue

            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)?$", line
            )
            if port_match and current_host is not None:
                current_ports.append({
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "version": (port_match.group(5) or "").strip(),
                })

        if current_host:
            current_host["ports"] = current_ports
            hosts.append(current_host)

        return {
            "hosts": hosts,
            "open_ports": sum(
                len([p for p in h.get("ports", []) if p["state"] == "open"]) for h in hosts
            ),
        }
