"""Nmap tool plugin for port scanning and service detection."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
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
        # XML to stdout for stable parsing; greppable fallback still accepts old text logs.
        cmd = ["nmap", "-oX", "-"]

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
        stripped = raw_output.strip()
        if stripped.startswith("<?xml") or stripped.lstrip().startswith("<nmaprun"):
            try:
                return self._parse_xml_output(stripped)
            except ET.ParseError:
                pass
        return self._parse_greppable_output(raw_output)

    def _parse_xml_output(self, xml_text: str) -> dict:
        # Local nmap XML only; stdlib ElementTree does not expand external entities.
        root = ET.fromstring(xml_text)
        hosts: list[dict[str, Any]] = []

        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            if status_el is not None and status_el.get("state") == "down":
                continue

            ip = ""
            addrs = host_el.findall("address")
            for a in addrs:
                if a.get("addrtype") == "ipv4":
                    ip = a.get("addr") or ""
                    break
            if not ip:
                for a in addrs:
                    if a.get("addrtype") == "ipv6":
                        ip = a.get("addr") or ""
                        break

            hostname = ""
            hn_wrap = host_el.find("hostnames")
            if hn_wrap is not None:
                hn = hn_wrap.find("hostname")
                if hn is not None:
                    hostname = hn.get("name") or ""

            display_host = hostname or ip or "unknown"
            if not ip and hostname:
                ip = hostname

            current_ports: list[dict[str, Any]] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    portid = port_el.get("portid", "0")
                    protocol = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    service_el = port_el.find("service")
                    svc_name = "unknown"
                    version = ""
                    if service_el is not None:
                        svc_name = service_el.get("name") or "unknown"
                        parts = [
                            service_el.get(k) or ""
                            for k in ("product", "version", "extrainfo")
                        ]
                        version = " ".join(p for p in parts if p).strip()
                    try:
                        port_num = int(portid)
                    except ValueError:
                        port_num = 0
                    current_ports.append({
                        "port": port_num,
                        "protocol": protocol,
                        "state": state,
                        "service": svc_name,
                        "version": version,
                    })

            hosts.append({
                "hostname": display_host,
                "ip": ip or display_host,
                "ports": current_ports,
            })

        return {
            "hosts": hosts,
            "open_ports": sum(
                len([p for p in h.get("ports", []) if p["state"] == "open"]) for h in hosts
            ),
        }

    def _parse_greppable_output(self, raw_output: str) -> dict:
        """Parse traditional greppable nmap stdout (legacy / manual runs)."""
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
