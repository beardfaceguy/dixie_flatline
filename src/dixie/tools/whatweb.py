"""WhatWeb tool plugin for web technology fingerprinting."""

from __future__ import annotations

import json
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class WhatWebTool(Tool):
    name = "whatweb"
    description = (
        "Identify web technologies including CMS, frameworks, JavaScript libraries, "
        "web servers, embedded devices, and version numbers. Non-intrusive web "
        "fingerprinting."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target URL or hostname (e.g. 'http://192.168.1.1' or '192.168.1.1')",
            required=True,
        ),
        ToolParameter(
            name="aggression",
            description="Aggression level: 1 (stealthy), 3 (aggressive). Default 1.",
            type="number",
            default=1,
        ),
        ToolParameter(
            name="extra_args",
            description="Additional whatweb arguments",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["whatweb", "--log-json=-", "--color=never"]

        aggression = kwargs.get("aggression", 1)
        cmd.extend(["-a", str(int(aggression))])

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        target = kwargs["target"]
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        cmd.append(target)

        return cmd

    def parse_output(self, raw_output: str) -> dict:
        results = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            parsed: dict[str, Any] = {
                "target": entry.get("target", ""),
                "status": entry.get("http_status"),
                "technologies": [],
            }

            plugins = entry.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                tech: dict[str, Any] = {"name": plugin_name}
                if isinstance(plugin_data, dict):
                    version = plugin_data.get("version")
                    if version:
                        tech["version"] = version[0] if isinstance(version, list) else version
                    string = plugin_data.get("string")
                    if string:
                        tech["detail"] = string[0] if isinstance(string, list) else string
                parsed["technologies"].append(tech)

            results.append(parsed)

        return {"scans": results, "total_technologies": sum(len(r["technologies"]) for r in results)}
