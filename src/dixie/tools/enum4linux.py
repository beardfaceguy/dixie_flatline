"""Enum4linux-ng tool plugin for SMB/NetBIOS/LDAP enumeration."""

from __future__ import annotations

import re
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class Enum4linuxTool(Tool):
    name = "enum4linux"
    description = (
        "Enumerate Windows/Samba hosts for shares, users, groups, password "
        "policies, and OS information via SMB, NetBIOS, and LDAP. Non-intrusive "
        "information gathering tool."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target IP address or hostname",
            required=True,
        ),
        ToolParameter(
            name="scan_type",
            description=(
                "What to enumerate: 'all' (default), 'shares', 'users', "
                "'groups', 'os', 'policies'"
            ),
            default="all",
        ),
        ToolParameter(
            name="extra_args",
            description="Additional enum4linux arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["enum4linux"]

        scan_type = kwargs.get("scan_type", "all")
        type_flags = {
            "all": "-a",
            "shares": "-S",
            "users": "-U",
            "groups": "-G",
            "os": "-o",
            "policies": "-P",
        }
        cmd.append(type_flags.get(scan_type, "-a"))

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        cmd.append(kwargs["target"])
        return cmd

    def parse_output(self, raw_output: str) -> dict:
        result: dict[str, Any] = {
            "target": "",
            "os_info": "",
            "shares": [],
            "users": [],
            "groups": [],
            "password_policy": {},
            "notes": [],
        }

        section = ""
        for line in raw_output.splitlines():
            line_stripped = line.strip()

            if "Target Information" in line:
                section = "target"
            elif "Share Enumeration" in line:
                section = "shares"
            elif "Users on" in line or "User Enumeration" in line:
                section = "users"
            elif "Group Enumeration" in line:
                section = "groups"
            elif "Password Policy" in line:
                section = "policy"
            elif "OS Information" in line:
                section = "os"

            if section == "shares":
                share_match = re.match(r"\s*(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line)
                if share_match:
                    result["shares"].append({
                        "name": share_match.group(1),
                        "type": share_match.group(2),
                        "comment": share_match.group(3).strip(),
                    })
            elif section == "users":
                user_match = re.search(r"user:\[(.+?)\]", line)
                if user_match:
                    result["users"].append(user_match.group(1))
            elif section == "groups":
                group_match = re.search(r"group:\[(.+?)\]", line)
                if group_match:
                    result["groups"].append(group_match.group(1))
            elif section == "os" and "OS:" in line:
                result["os_info"] = line.split("OS:", 1)[1].strip()

            if "NULL session" in line_stripped.lower() and "allowed" in line_stripped.lower():
                result["notes"].append("NULL sessions allowed — anonymous enumeration possible")

        return result
