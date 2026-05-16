"""SSLScan tool plugin for SSL/TLS configuration assessment."""

from __future__ import annotations

import re
from typing import Any

from dixie.tools.base import Tool, ToolParameter


class SSLScanTool(Tool):
    name = "sslscan"
    description = (
        "Scan SSL/TLS configuration of a host to identify weak ciphers, "
        "expired certificates, protocol support issues, and other TLS "
        "misconfigurations."
    )
    parameters = [
        ToolParameter(
            name="target",
            description="Target host:port (e.g. '192.168.1.1:443' or just hostname for port 443)",
            required=True,
        ),
        ToolParameter(
            name="extra_args",
            description="Additional sslscan arguments (e.g. '--no-colour')",
        ),
    ]

    def build_command(self, **kwargs: Any) -> list[str]:
        cmd = ["sslscan", "--no-colour"]

        extra = kwargs.get("extra_args")
        if extra:
            cmd.extend(extra.split())

        cmd.append(kwargs["target"])
        return cmd

    def parse_output(self, raw_output: str) -> dict:
        result: dict[str, Any] = {
            "protocols": [],
            "ciphers": [],
            "certificate": {},
            "issues": [],
        }

        for line in raw_output.splitlines():
            line = line.strip()

            proto_match = re.match(
                r"(SSLv[23]|TLSv1\.[0-3])\s+(enabled|disabled)", line
            )
            if proto_match:
                proto = proto_match.group(1)
                enabled = proto_match.group(2) == "enabled"
                result["protocols"].append({"name": proto, "enabled": enabled})
                if enabled and proto in ("SSLv2", "SSLv3", "TLSv1.0"):
                    result["issues"].append(f"Insecure protocol enabled: {proto}")
                continue

            cipher_match = re.match(
                r"(Accepted|Preferred)\s+(\S+)\s+(\d+)\s+bits\s+(\S+)", line
            )
            if cipher_match:
                cipher = {
                    "status": cipher_match.group(1).lower(),
                    "version": cipher_match.group(2),
                    "bits": int(cipher_match.group(3)),
                    "name": cipher_match.group(4),
                }
                result["ciphers"].append(cipher)
                if cipher["bits"] < 128:
                    result["issues"].append(
                        f"Weak cipher ({cipher['bits']} bits): {cipher['name']}"
                    )
                continue

            if "Subject:" in line:
                result["certificate"]["subject"] = line.split("Subject:", 1)[1].strip()
            elif "Issuer:" in line:
                result["certificate"]["issuer"] = line.split("Issuer:", 1)[1].strip()
            elif "Not valid after:" in line:
                expiry = line.split("Not valid after:", 1)[1].strip()
                result["certificate"]["expires"] = expiry

        return result
