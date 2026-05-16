"""Tests for passive scan features: recon mode, report_finding, new tool plugins."""

import json
from unittest.mock import MagicMock

import pytest

from dixie.core.agent import Agent, _is_subnet
from dixie.core.recon_policy import RECON_BLOCKED_TOOLS
from dixie.core.config import (
    AgentConfig,
    EngagementConfig,
    EngagementMode,
    SandboxConfig,
    ToolDefaultsConfig,
)
from dixie.core.schema import Confidence, EngagementState, Finding, Severity, ToolResult
from dixie.constants import DEFAULT_MASSCAN_MAX_RATE
from dixie.tools import build_default_registry
from dixie.tools.arp_scan import ArpScanTool
from dixie.tools.enum4linux import Enum4linuxTool
from dixie.tools.finding import ReportFindingTool
from dixie.tools.masscan import MasscanTool
from dixie.tools.nuclei import NucleiTool
from dixie.tools.sslscan import SSLScanTool
from dixie.tools.testssl import TestSSLTool
from dixie.tools.whatweb import WhatWebTool


class TestEngagementMode:
    def test_recon_mode_exists(self):
        assert EngagementMode.RECON == "recon"
        assert EngagementMode.FULL == "full"

    def test_config_default_mode(self):
        config = EngagementConfig(target="192.168.1.1")
        assert config.mode == EngagementMode.FULL

    def test_config_recon_mode(self):
        config = EngagementConfig(target="192.168.1.0/24", mode=EngagementMode.RECON)
        assert config.mode == EngagementMode.RECON

    def test_config_from_yaml_with_mode(self, tmp_path):
        cfg_file = tmp_path / "test.yaml"
        cfg_file.write_text("target: 192.168.1.0/24\nmode: recon\n")
        config = EngagementConfig.from_file(cfg_file)
        assert config.mode == EngagementMode.RECON


class TestSubnetDetection:
    def test_single_host_not_subnet(self):
        assert not _is_subnet("192.168.1.1")

    def test_cidr_24_is_subnet(self):
        assert _is_subnet("192.168.1.0/24")

    def test_ipv6_subnet(self):
        assert _is_subnet("2001:db8::/64")

    def test_ipv6_slash128_not_subnet(self):
        assert not _is_subnet("2001:db8::1/128")

    def test_cidr_16_is_subnet(self):
        assert _is_subnet("10.0.0.0/16")

    def test_slash_32_not_subnet(self):
        assert not _is_subnet("192.168.1.1/32")

    def test_hostname_not_subnet(self):
        assert not _is_subnet("router.local")

    def test_invalid_not_subnet(self):
        assert not _is_subnet("not-an-ip")


class TestReconModeBlocking:
    """Test that dangerous tools are blocked in recon mode."""

    def test_blocked_tools_defined(self):
        assert "hydra" in RECON_BLOCKED_TOOLS
        assert "medusa" in RECON_BLOCKED_TOOLS
        assert "sqlmap" in RECON_BLOCKED_TOOLS
        assert "gobuster_dir" in RECON_BLOCKED_TOOLS

    def test_gobuster_dir_blocked_in_recon_matches_registry_name(self):
        """Regression: GobusterTool.name is gobuster_dir — must be blocked in recon."""
        config = EngagementConfig(target="192.168.1.1", mode=EngagementMode.RECON)
        tools = build_default_registry()
        assert tools.get("gobuster_dir") is not None
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=sandbox)
        assert not agent._is_tool_allowed("gobuster_dir")
        assert agent._is_tool_allowed("nmap_scan")
        assert agent._is_tool_allowed("report_finding")

    def test_safe_tools_not_blocked(self):
        assert "nmap_scan" not in RECON_BLOCKED_TOOLS
        assert "sslscan" not in RECON_BLOCKED_TOOLS
        assert "whatweb" not in RECON_BLOCKED_TOOLS
        assert "report_finding" not in RECON_BLOCKED_TOOLS


class TestAgentToolRetries:
    def test_retries_until_success(self) -> None:
        config = EngagementConfig(
            target="192.168.1.1",
            agent=AgentConfig(max_tool_retries=2, max_iterations=5),
            sandbox=SandboxConfig(timeout=30),
        )
        tools = build_default_registry()
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        sandbox.run_local.side_effect = [
            ToolResult(
                tool="nmap_scan",
                command="nmap",
                raw_output="",
                success=False,
                error="transient",
            ),
            ToolResult(
                tool="nmap_scan",
                command="nmap",
                raw_output=(
                    "Nmap scan report for 192.168.1.1\n"
                    "22/tcp   open  ssh     OpenSSH 8.9\n"
                ),
                success=True,
                error=None,
            ),
        ]
        calls: dict[str, int] = {"n": 0}

        def chat(prompt: str) -> dict:
            calls["n"] += 1
            if calls["n"] == 1:
                return {
                    "content": "scan",
                    "tool_calls": [{
                        "id": "1",
                        "name": "nmap_scan",
                        "arguments": {"target": "192.168.1.1"},
                    }],
                }
            return {"content": "done", "tool_calls": []}

        llm = MagicMock()
        llm.chat.side_effect = chat
        llm.total_tokens = 0
        llm.total_cost = 0.0
        llm.submit_tool_result = MagicMock()

        agent = Agent(config=config, llm=llm, tools=tools, sandbox=sandbox)
        agent.run()

        assert sandbox.run_local.call_count == 2


class TestGobusterToolDefaultsMerge:
    def test_yaml_wordlist_fills_missing(self) -> None:
        config = EngagementConfig(
            target="192.168.1.1",
            tool_defaults=ToolDefaultsConfig(gobuster_wordlist="/engagement/custom.txt"),
        )
        tools = build_default_registry()
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=sandbox)
        merged = agent._merge_engagement_tool_defaults("gobuster_dir", {"url": "http://x/"})
        assert merged["wordlist"] == "/engagement/custom.txt"
        assert merged["url"] == "http://x/"

    def test_explicit_wordlist_wins(self) -> None:
        config = EngagementConfig(
            target="192.168.1.1",
            tool_defaults=ToolDefaultsConfig(gobuster_wordlist="/yaml/wl.txt"),
        )
        tools = build_default_registry()
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=sandbox)
        merged = agent._merge_engagement_tool_defaults(
            "gobuster_dir",
            {"url": "http://x/", "wordlist": "/llm/picked.txt"},
        )
        assert merged["wordlist"] == "/llm/picked.txt"

    def test_empty_string_wordlist_replaced(self) -> None:
        config = EngagementConfig(
            target="192.168.1.1",
            tool_defaults=ToolDefaultsConfig(gobuster_wordlist="/yaml/wl.txt"),
        )
        agent = Agent(
            config=config,
            llm=MagicMock(),
            tools=build_default_registry(),
            sandbox=MagicMock(),
        )
        merged = agent._merge_engagement_tool_defaults(
            "gobuster_dir",
            {"url": "http://x/", "wordlist": "  "},
        )
        assert merged["wordlist"] == "/yaml/wl.txt"


class TestReportFindingTool:
    def test_schema(self):
        tool = ReportFindingTool()
        schema = tool.tool_schema()
        assert schema["function"]["name"] == "report_finding"
        params = schema["function"]["parameters"]["properties"]
        assert "title" in params
        assert "severity" in params
        assert "confidence" in params
        assert "attack_techniques" in params

    def test_required_fields(self):
        tool = ReportFindingTool()
        schema = tool.tool_schema()
        required = schema["function"]["parameters"]["required"]
        assert "title" in required
        assert "description" in required
        assert "severity" in required

    def test_build_command_raises(self):
        tool = ReportFindingTool()
        with pytest.raises(NotImplementedError):
            tool.build_command()

    def test_parse_output_raises(self):
        tool = ReportFindingTool()
        with pytest.raises(NotImplementedError):
            tool.parse_output("")


class TestMasscanTool:
    def test_build_command(self):
        tool = MasscanTool()
        cmd = tool.build_command(target="192.168.1.0/24", ports="80,443", rate=5000)
        assert "masscan" in cmd
        assert "192.168.1.0/24" in cmd
        assert "80,443" in cmd
        assert "5000" in cmd

    def test_build_command_rate_floor_and_caps_high_rate_to_library_default(self):
        tool = MasscanTool()
        hi = tool.build_command(target="10.0.0.0/24", ports="80", rate=1_000_000)
        assert "--rate" in hi
        rate_idx = hi.index("--rate") + 1
        assert hi[rate_idx] == str(DEFAULT_MASSCAN_MAX_RATE)

        hi_cap = tool.build_command(
            target="10.0.0.0/24",
            ports="80",
            rate=1_000_000,
            _masscan_rate_cap=250_000,
        )
        rate_idx2 = hi_cap.index("--rate") + 1
        assert hi_cap[rate_idx2] == "250000"

        lo = tool.build_command(target="10.0.0.0/24", ports="80", rate=-5)
        lo_idx = lo.index("--rate") + 1
        assert lo[lo_idx] == "1"

    def test_extra_args_second_rate_does_not_bypass_cap(self) -> None:
        tool = MasscanTool()
        cmd = tool.build_command(
            target="10.0.0.0/24",
            ports="80",
            rate=3000,
            _masscan_rate_cap=5000,
            extra_args="--rate 999999",
        )
        assert cmd[-2] == "--rate"
        assert cmd[-1] == "3000"

    def test_extra_args_output_format_does_not_override_json_lines(self) -> None:
        tool = MasscanTool()
        cmd = tool.build_command(
            target="10.0.0.0/24",
            ports="80",
            rate=1000,
            extra_args="--output-format list",
        )
        idx = max(i for i, t in enumerate(cmd) if t == "--output-format")
        assert cmd[idx + 1] == "json"

    def test_build_command_leaves_rate_cap_key_in_kwargs(self) -> None:
        tool = MasscanTool()
        args: dict = {
            "target": "10.0.0.1",
            "ports": "80",
            "rate": 3000,
            "_masscan_rate_cap": 2500,
        }
        tool.build_command(**args)
        assert "_masscan_rate_cap" in args

    def test_parse_output(self):
        tool = MasscanTool()
        output = '{"ip": "192.168.1.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}\n'
        result = tool.parse_output(output)
        assert result["hosts_found"] == 1
        assert "192.168.1.1" in result["hosts"]

    def test_parse_empty(self):
        tool = MasscanTool()
        result = tool.parse_output("")
        assert result["hosts_found"] == 0


class TestSSLScanTool:
    def test_build_command(self):
        tool = SSLScanTool()
        cmd = tool.build_command(target="192.168.1.1:443")
        assert "sslscan" in cmd
        assert "--no-colour" in cmd
        assert "192.168.1.1:443" in cmd

    def test_parse_protocols(self):
        tool = SSLScanTool()
        output = "SSLv3    enabled\nTLSv1.0  enabled\nTLSv1.2  enabled\nTLSv1.3  disabled\n"
        result = tool.parse_output(output)
        assert len(result["protocols"]) == 4
        assert any(p["name"] == "SSLv3" and p["enabled"] for p in result["protocols"])
        assert "Insecure protocol enabled: SSLv3" in result["issues"]
        assert "Insecure protocol enabled: TLSv1.0" in result["issues"]

    def test_parse_weak_cipher(self):
        tool = SSLScanTool()
        output = "Accepted  TLSv1.2  56 bits   DES-CBC3-SHA\n"
        result = tool.parse_output(output)
        assert len(result["ciphers"]) == 1
        assert result["ciphers"][0]["bits"] == 56
        assert any("Weak cipher" in i for i in result["issues"])


class TestEnum4linuxTool:
    def test_build_command_all(self):
        tool = Enum4linuxTool()
        cmd = tool.build_command(target="192.168.1.1", scan_type="all")
        assert "enum4linux" in cmd
        assert "-a" in cmd
        assert "192.168.1.1" in cmd

    def test_build_command_shares(self):
        tool = Enum4linuxTool()
        cmd = tool.build_command(target="192.168.1.1", scan_type="shares")
        assert "-S" in cmd

    def test_parse_shares(self):
        tool = Enum4linuxTool()
        output = (
            "==============================\n"
            " Share Enumeration on 192.168.1.1\n"
            "==============================\n"
            "\tIPC$          IPC  IPC Service\n"
            "\tprint$        Disk Printer Drivers\n"
            "\tshare         Disk Public share\n"
        )
        result = tool.parse_output(output)
        assert len(result["shares"]) >= 1


class TestWhatWebTool:
    def test_build_command(self):
        tool = WhatWebTool()
        cmd = tool.build_command(target="192.168.1.1", aggression=1)
        assert "whatweb" in cmd
        assert "http://192.168.1.1" in cmd
        assert "-a" in cmd
        assert "1" in cmd

    def test_build_command_with_protocol(self):
        tool = WhatWebTool()
        cmd = tool.build_command(target="https://example.com")
        assert "https://example.com" in cmd

    def test_parse_output(self):
        tool = WhatWebTool()
        output = json.dumps({
            "target": "http://192.168.1.1",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.41"]},
                "PHP": {"version": ["7.4.3"]},
            },
        }) + "\n"
        result = tool.parse_output(output)
        assert result["total_technologies"] == 2
        assert result["scans"][0]["status"] == 200


class TestTestSSLTool:
    def test_build_command_full(self):
        tool = TestSSLTool()
        cmd = tool.build_command(target="192.168.1.1:443", checks="full")
        assert "testssl.sh" in cmd
        assert "192.168.1.1:443" in cmd
        assert "-p" not in cmd  # full doesn't add a specific flag

    def test_build_command_vulnerabilities(self):
        tool = TestSSLTool()
        cmd = tool.build_command(target="192.168.1.1:443", checks="vulnerabilities")
        assert "-U" in cmd

    def test_parse_output(self):
        tool = TestSSLTool()
        entry = {
            "id": "heartbleed",
            "severity": "CRITICAL",
            "finding": "VULNERABLE -- bugass heartbleed",
        }
        output = json.dumps(entry) + "\n"
        result = tool.parse_output(output)
        assert result["issues_count"] == 1
        assert "heartbleed" in result["vulnerabilities"][0]

    def test_parse_output_json_array_indented(self):
        tool = TestSSLTool()
        raw = '  [\n    {"id": "weak", "severity": "HIGH", "finding": "weak cipher"}\n  ]\n'
        result = tool.parse_output(raw)
        assert result["issues_count"] == 1


class TestArpScanTool:
    def test_build_command(self):
        tool = ArpScanTool()
        cmd = tool.build_command(target="--localnet")
        assert "arp-scan" in cmd
        assert "--localnet" in cmd

    def test_build_command_with_interface(self):
        tool = ArpScanTool()
        cmd = tool.build_command(target="192.168.1.0/24", interface="eth0")
        assert "-I" in cmd
        assert "eth0" in cmd

    def test_parse_output(self):
        tool = ArpScanTool()
        output = (
            "Interface: eth0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.1.100\n"
            "Starting arp-scan 1.9.7\n"
            "192.168.1.1\t00:11:22:33:44:55\tNetgear Inc.\n"
            "192.168.1.10\taa:bb:cc:dd:ee:ff\tIntel Corporate\n"
            "\n"
            "2 packets received by filter, 0 packets dropped by kernel\n"
        )
        result = tool.parse_output(output)
        assert result["hosts_found"] == 2
        assert result["hosts"][0]["ip"] == "192.168.1.1"
        assert result["hosts"][0]["vendor"] == "Netgear Inc."


class TestNucleiTool:
    def test_build_command(self):
        tool = NucleiTool()
        cmd = tool.build_command(target="http://192.168.1.1", severity="critical,high")
        assert "nuclei" in cmd
        assert "-target" in cmd
        assert "-severity" in cmd
        assert "critical,high" in cmd

    def test_build_command_with_tags(self):
        tool = NucleiTool()
        cmd = tool.build_command(target="http://192.168.1.1", templates="cve,misconfig")
        assert "-tags" in cmd
        assert "cve,misconfig" in cmd

    def test_parse_output(self):
        tool = NucleiTool()
        entry = {
            "template-id": "CVE-2021-44228",
            "info": {
                "name": "Log4Shell RCE",
                "severity": "critical",
                "description": "Apache Log4j2 RCE",
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "tags": ["cve", "rce", "log4j"],
            },
            "matched-at": "http://192.168.1.1:8080",
        }
        output = json.dumps(entry) + "\n"
        result = tool.parse_output(output)
        assert result["total"] == 1
        assert result["findings"][0]["severity"] == "critical"
        assert result["severity_breakdown"]["critical"] == 1


class TestDefaultRegistry:
    def test_all_tools_registered(self):
        registry = build_default_registry()
        tools = registry.list_tools()
        names = {t.name for t in tools}
        assert "nmap_scan" in names
        assert "masscan" in names
        assert "arp_scan" in names
        assert "sslscan" in names
        assert "testssl" in names
        assert "enum4linux" in names
        assert "whatweb" in names
        assert "nuclei" in names
        assert "report_finding" in names

    def test_tool_count(self):
        registry = build_default_registry()
        assert len(registry.list_tools()) >= 10


class TestSystemPrompts:
    def test_recon_prompt_has_strict_rules(self):
        from dixie.core.config import EngagementMode
        from dixie.models.llm import SYSTEM_PROMPT_RECON, get_system_prompt

        assert "STRICT RULES" in SYSTEM_PROMPT_RECON
        assert "Do NOT attempt exploitation" in SYSTEM_PROMPT_RECON
        assert "hydra" in SYSTEM_PROMPT_RECON
        assert "gobuster_dir" in SYSTEM_PROMPT_RECON
        assert get_system_prompt(EngagementMode.RECON) == SYSTEM_PROMPT_RECON

    def test_full_prompt_allows_exploitation(self):
        from dixie.models.llm import SYSTEM_PROMPT_FULL
        assert "chain exploits" in SYSTEM_PROMPT_FULL

    def test_get_system_prompt(self):
        from dixie.models.llm import get_system_prompt
        assert "STRICT" in get_system_prompt(EngagementMode.RECON)
        assert "exploit" in get_system_prompt(EngagementMode.FULL).lower()
