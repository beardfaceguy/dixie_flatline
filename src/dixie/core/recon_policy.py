"""Recon mode: which tool names are blocked at the agent layer.

Policy is merged from:

1. :attr:`Tool.recon_blocked` on classes in the default registry (single source for
   implemented plugins — names always match :attr:`Tool.name`).
2. :data:`RECON_BLOCKED_UNREGISTERED` — tools the LLM might still name that are not
   (yet) Dixie plugins.
3. :data:`RECON_BLOCKED_ALIASES` — legacy or alternate names to deny (e.g. old prompts).
"""

from __future__ import annotations

from dixie.tools.base import Tool


# Names not backed by a Tool subclass but commonly invoked — still block in recon.
RECON_BLOCKED_UNREGISTERED: frozenset[str] = frozenset({
    "hydra",
    "medusa",
    "sqlmap",
    "wfuzz",
    "john",
    "hashcat",
    "msfconsole",
    "metasploit",
})

# Alternate spellings / historical ids that should not bypass recon checks.
RECON_BLOCKED_ALIASES: frozenset[str] = frozenset({
    "gobuster_brute",
})


def build_recon_blocked_tool_names() -> frozenset[str]:
    """Compute the full blocklist from registry flags + unregistered + aliases."""
    from dixie.tools import build_default_registry

    names: set[str] = set(RECON_BLOCKED_UNREGISTERED) | set(RECON_BLOCKED_ALIASES)
    for tool in build_default_registry().list_tools():
        cls: type[Tool] = type(tool)
        if getattr(cls, "recon_blocked", False):
            names.add(tool.name)
    return frozenset(names)


RECON_BLOCKED_TOOLS: frozenset[str] = build_recon_blocked_tool_names()


def recon_blocked_tools_prompt_fragment() -> str:
    """Comma-separated sorted tool ids for the recon system prompt (single source)."""
    return ", ".join(sorted(RECON_BLOCKED_TOOLS))
