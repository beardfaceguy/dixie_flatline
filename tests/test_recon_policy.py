"""Tests for recon-mode tool blocklist (single source in recon_policy)."""

from dixie.core import agent as agent_module
from dixie.core.recon_policy import (
    RECON_BLOCKED_ALIASES,
    RECON_BLOCKED_TOOLS,
    RECON_BLOCKED_UNREGISTERED,
    build_recon_blocked_tool_names,
    recon_blocked_tools_prompt_fragment,
)
from dixie.tools.gobuster import GobusterTool


class TestReconPolicy:
    def test_agent_uses_same_blocklist_object(self) -> None:
        assert agent_module.RECON_BLOCKED_TOOLS is RECON_BLOCKED_TOOLS

    def test_snapshot_matches_expected_names(self) -> None:
        expected = frozenset(
            RECON_BLOCKED_UNREGISTERED
            | RECON_BLOCKED_ALIASES
            | {"gobuster_dir"},
        )
        assert RECON_BLOCKED_TOOLS == expected

    def test_idempotent_build(self) -> None:
        assert build_recon_blocked_tool_names() == RECON_BLOCKED_TOOLS

    def test_gobuster_plugin_declares_blocked(self) -> None:
        assert GobusterTool.recon_blocked is True
        assert GobusterTool.name in RECON_BLOCKED_TOOLS

    def test_prompt_fragment_lists_all_blocked_sorted(self) -> None:
        frag = recon_blocked_tools_prompt_fragment()
        for name in sorted(RECON_BLOCKED_TOOLS):
            assert name in frag
