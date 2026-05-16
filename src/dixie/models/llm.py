"""Model-agnostic LLM interface via LiteLLM."""

from __future__ import annotations

import json
import logging
from typing import Any

import litellm

from dixie.core.config import EngagementMode, LLMConfig
from dixie.tools.base import ToolRegistry

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_FULL = """\
You are Dixie Flatline, an expert penetration tester conducting an authorized \
red team engagement. You methodically enumerate attack surfaces, identify \
vulnerabilities, and chain exploits to achieve objectives.

You have access to pentesting tools. Use them strategically:
1. Start with reconnaissance (nmap, masscan for discovery)
2. Enumerate services and identify potential vulnerabilities
3. Probe deeper with targeted scans (nikto, nuclei, specific NSE scripts)
4. Test for exploitable conditions where authorized
5. Document ALL findings with severity, evidence, and remediation

Always think step-by-step. Explain your reasoning before choosing a tool. \
After each tool result, analyze what you learned and decide the next action.

When you have enough evidence for a finding, call report_finding with \
structured details including MITRE ATT&CK technique IDs where applicable.

Current engagement context will be provided in each message.\
"""

_SYSTEM_PROMPT_RECON_TEMPLATE = """\
You are Dixie Flatline, an expert network security assessor conducting an \
authorized passive reconnaissance engagement. Your goal is to discover hosts, \
identify services, assess configurations, and report potential vulnerabilities \
WITHOUT any active exploitation or intrusive testing.

STRICT RULES:
- Do NOT attempt exploitation, brute-forcing, or credential testing
- Do NOT use tools blocked in recon mode, including: {blocked_tools}
- Do NOT send malicious payloads or injection attempts
- ONLY use non-intrusive scanning: service detection, banner grabbing, \
  version identification, SSL/TLS analysis, DNS enumeration
- Treat this as a vulnerability ASSESSMENT, not a penetration TEST

Workflow:
1. If given a subnet, start with host discovery (nmap -sn or arp-scan)
2. For each live host, run service/version detection (nmap -sV --script=safe)
3. Check SSL/TLS configurations on HTTPS services (sslscan, testssl.sh)
4. Enumerate exposed services (SMB, SNMP, DNS) with safe enumeration tools
5. Fingerprint web technologies (whatweb)
6. Cross-reference discovered versions against known CVEs
7. Document ALL findings with report_finding including severity, evidence, \
   MITRE ATT&CK technique IDs, and remediation guidance

Always think step-by-step. Explain your reasoning before choosing a tool. \
After each tool result, analyze what you learned and decide the next action.

Current engagement context will be provided in each message.\
"""


def _format_recon_system_prompt() -> str:
    from dixie.core.recon_policy import recon_blocked_tools_prompt_fragment

    return _SYSTEM_PROMPT_RECON_TEMPLATE.format(
        blocked_tools=recon_blocked_tools_prompt_fragment(),
    )


def get_system_prompt(mode: EngagementMode = EngagementMode.FULL) -> str:
    if mode == EngagementMode.RECON:
        return _format_recon_system_prompt()
    return SYSTEM_PROMPT_FULL


# Populated at import so prompt text stays aligned with `RECON_BLOCKED_TOOLS`.
SYSTEM_PROMPT_RECON = _format_recon_system_prompt()


class LLMClient:
    """Wraps LiteLLM for multi-provider model access with tool calling."""

    def __init__(
        self,
        config: LLMConfig,
        tool_registry: ToolRegistry,
        mode: EngagementMode = EngagementMode.FULL,
    ) -> None:
        self.config = config
        self.tool_registry = tool_registry
        self.mode = mode
        self._system_prompt = get_system_prompt(mode)
        self.messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system_prompt}
        ]
        self.total_tokens = 0
        self.total_cost = 0.0

        if config.api_base:
            litellm.api_base = config.api_base

    def reset(self) -> None:
        self.messages = [{"role": "system", "content": self._system_prompt}]

    def chat(self, user_message: str) -> dict:
        """Send a message and get a response, potentially with tool calls.

        Returns a dict with keys:
        - content: str | None (text response)
        - tool_calls: list[dict] (tool invocations requested by the model)
        - raw: the full response object
        """
        self.messages.append({"role": "user", "content": user_message})

        response = litellm.completion(
            model=self.config.model,
            messages=self.messages,
            tools=self.tool_registry.tool_schemas(),
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )

        choice = response.choices[0]
        assistant_msg = choice.message

        self.messages.append(assistant_msg.model_dump())

        usage = response.usage
        if usage:
            self.total_tokens += usage.total_tokens

        try:
            added = litellm.completion_cost(completion_response=response)
            if added is not None:
                self.total_cost += float(added)
        except Exception:
            logger.debug("completion_cost failed for model=%s", self.config.model, exc_info=True)

        tool_calls = []
        if assistant_msg.tool_calls:
            for tc in assistant_msg.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": json.loads(tc.function.arguments),
                })

        return {
            "content": assistant_msg.content,
            "tool_calls": tool_calls,
        }

    def submit_tool_result(self, tool_call_id: str, result: str) -> None:
        """Add a tool result to the conversation history."""
        self.messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        })
