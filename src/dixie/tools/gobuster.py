"""Gobuster tool plugin for directory and DNS brute-forcing."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from dixie.tools.base import Tool, ToolParameter


class GobusterTool(Tool):
    recon_blocked: ClassVar[bool] = True
    name = "gobuster_dir"
    description = (
        "Run gobuster in directory brute-force mode to discover hidden paths, "
        "files, and directories on a web server."
    )
    parameters = [
        ToolParameter(
            name="url",
            description="Target URL (e.g. 'http://target.com')",
            required=True,
        ),
        ToolParameter(
            name="wordlist",
            description="Wordlist to use for brute-forcing",
            default="/usr/share/wordlists/dirb/common.txt",
        ),
        ToolParameter(
            name="extensions",
            description="File extensions to search for (e.g. 'php,html,txt')",
        ),
        ToolParameter(
            name="status_codes",
            description="Status codes to consider valid (e.g. '200,204,301,302')",
            default="200,204,301,302,307,401,403",
        ),
        ToolParameter(
            name="threads",
            description="Number of concurrent threads",
            type="integer",
            default=10,
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["gobuster", "dir", "-u", kwargs["url"]]

        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd.extend(["-w", wordlist])

        extensions = kwargs.get("extensions")
        if extensions:
            cmd.extend(["-x", extensions])

        status_codes = kwargs.get("status_codes", "200,204,301,302,307,401,403")
        cmd.extend(["-s", status_codes])

        threads = kwargs.get("threads", 10)
        cmd.extend(["-t", str(threads)])

        cmd.append("-q")  # quiet mode, cleaner output
        return cmd

    def parse_output(self, raw_output: str) -> dict:
        paths = []
        for line in raw_output.splitlines():
            match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
            if match:
                paths.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)),
                })
        return {
            "paths": paths,
            "total_found": len(paths),
        }
