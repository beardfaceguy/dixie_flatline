"""Tool plugins for Dixie Flatline pentesting agent."""

from dixie.tools.arp_scan import ArpScanTool
from dixie.tools.base import Tool, ToolParameter, ToolRegistry
from dixie.tools.enum4linux import Enum4linuxTool
from dixie.tools.finding import ReportFindingTool
from dixie.tools.gobuster import GobusterTool
from dixie.tools.masscan import MasscanTool
from dixie.tools.nikto import NiktoTool
from dixie.tools.nmap import NmapTool
from dixie.tools.nuclei import NucleiTool
from dixie.tools.sslscan import SSLScanTool
from dixie.tools.testssl import TestSSLTool
from dixie.tools.whatweb import WhatWebTool


def build_default_registry() -> ToolRegistry:
    """Create a registry with all available tool plugins."""
    registry = ToolRegistry()
    registry.register(NmapTool())
    registry.register(MasscanTool())
    registry.register(ArpScanTool())
    registry.register(NiktoTool())
    registry.register(GobusterTool())
    registry.register(SSLScanTool())
    registry.register(TestSSLTool())
    registry.register(Enum4linuxTool())
    registry.register(WhatWebTool())
    registry.register(NucleiTool())
    registry.register(ReportFindingTool())
    return registry
