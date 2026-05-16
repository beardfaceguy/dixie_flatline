"""Tests for tool plugins: command building and output parsing."""

from dixie.tools.base import ToolRegistry
from dixie.tools.gobuster import GobusterTool
from dixie.tools.nikto import NiktoTool
from dixie.tools.nmap import NmapTool


class TestNmapTool:
    def setup_method(self):
        self.tool = NmapTool()

    def test_build_command_basic(self):
        cmd = self.tool.build_command(target="192.168.1.1")
        assert cmd[0] == "nmap"
        assert "192.168.1.1" in cmd
        assert "-sS" in cmd

    def test_build_command_version_scan(self):
        cmd = self.tool.build_command(target="10.0.0.1", scan_type="version", ports="80,443")
        assert "-sV" in cmd
        assert "-p" in cmd
        assert "80,443" in cmd

    def test_build_command_with_scripts(self):
        cmd = self.tool.build_command(target="10.0.0.1", scripts="vuln")
        assert "--script" in cmd
        assert "vuln" in cmd

    def test_parse_output(self):
        raw = (
            "Nmap scan report for 192.168.1.1\n"
            "22/tcp   open  ssh     OpenSSH 8.9p1\n"
            "80/tcp   open  http    Apache httpd 2.4.52\n"
            "443/tcp  open  https\n"
            "3306/tcp closed mysql\n"
        )
        result = self.tool.parse_output(raw)
        assert len(result["hosts"]) == 1
        assert result["open_ports"] == 3
        ports = result["hosts"][0]["ports"]
        assert ports[0]["port"] == 22
        assert ports[0]["service"] == "ssh"
        assert ports[1]["version"] == "Apache httpd 2.4.52"
        assert ports[3]["state"] == "closed"

    def test_parse_output_multiple_hosts(self):
        raw = (
            "Nmap scan report for host1.local (192.168.1.1)\n"
            "22/tcp open ssh\n"
            "Nmap scan report for host2.local (192.168.1.2)\n"
            "80/tcp open http\n"
        )
        result = self.tool.parse_output(raw)
        assert len(result["hosts"]) == 2
        assert result["hosts"][0]["ip"] == "192.168.1.1"
        assert result["hosts"][1]["ip"] == "192.168.1.2"

    def test_parse_empty_output(self):
        result = self.tool.parse_output("")
        assert result["hosts"] == []
        assert result["open_ports"] == 0

    def test_tool_schema(self):
        schema = self.tool.tool_schema()
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "nmap_scan"
        assert "target" in schema["function"]["parameters"]["required"]


class TestGobusterTool:
    def setup_method(self):
        self.tool = GobusterTool()

    def test_build_command_basic(self):
        cmd = self.tool.build_command(url="http://target.com")
        assert cmd[0] == "gobuster"
        assert "dir" in cmd
        assert "http://target.com" in cmd

    def test_build_command_with_extensions(self):
        cmd = self.tool.build_command(url="http://target.com", extensions="php,html")
        assert "-x" in cmd
        assert "php,html" in cmd

    def test_parse_output(self):
        raw = (
            "/admin                (Status: 301) [Size: 312]\n"
            "/login                (Status: 200) [Size: 1543]\n"
            "/api                  (Status: 403) [Size: 278]\n"
        )
        result = self.tool.parse_output(raw)
        assert result["total_found"] == 3
        assert result["paths"][0]["path"] == "/admin"
        assert result["paths"][0]["status"] == 301
        assert result["paths"][1]["size"] == 1543

    def test_parse_empty_output(self):
        result = self.tool.parse_output("")
        assert result["paths"] == []
        assert result["total_found"] == 0

    def test_tool_schema(self):
        schema = self.tool.tool_schema()
        assert schema["function"]["name"] == "gobuster_dir"
        assert "url" in schema["function"]["parameters"]["required"]


class TestNiktoTool:
    def setup_method(self):
        self.tool = NiktoTool()

    def test_build_command_basic(self):
        cmd = self.tool.build_command(target="http://target.com")
        assert cmd[0] == "nikto"
        assert "http://target.com" in cmd

    def test_build_command_ssl(self):
        cmd = self.tool.build_command(target="https://target.com", ssl=True, port=443)
        assert "-ssl" in cmd
        assert "443" in cmd

    def test_parse_output_osvdb(self):
        raw = (
            "+ OSVDB-3092: /admin/: This might be interesting...\n"
            "+ OSVDB-3268: /icons/: Directory indexing found.\n"
        )
        result = self.tool.parse_output(raw)
        assert result["total_found"] == 2
        assert result["vulnerabilities"][0]["id"] == "OSVDB-3092"

    def test_parse_empty_output(self):
        result = self.tool.parse_output("")
        assert result["vulnerabilities"] == []
        assert result["total_found"] == 0

    def test_tool_schema(self):
        schema = self.tool.tool_schema()
        assert schema["function"]["name"] == "nikto_scan"


class TestToolRegistry:
    def test_register_and_list(self):
        registry = ToolRegistry()
        registry.register(NmapTool())
        registry.register(GobusterTool())
        assert len(registry.list_tools()) == 2

    def test_get_by_name(self):
        registry = ToolRegistry()
        registry.register(NmapTool())
        tool = registry.get("nmap_scan")
        assert tool is not None
        assert tool.name == "nmap_scan"

    def test_get_unknown(self):
        registry = ToolRegistry()
        assert registry.get("nonexistent") is None

    def test_tool_schemas(self):
        registry = ToolRegistry()
        registry.register(NmapTool())
        registry.register(GobusterTool())
        schemas = registry.tool_schemas()
        assert len(schemas) == 2
        assert all(s["type"] == "function" for s in schemas)
