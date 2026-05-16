"""ReAct agent loop for orchestrating pentesting engagements."""

from __future__ import annotations

import json
import logging
import time
import ipaddress

from rich.console import Console
from rich.panel import Panel

from dixie.core.config import EngagementConfig, EngagementMode
from dixie.core.recon_policy import RECON_BLOCKED_TOOLS
from dixie.core.sandbox import Sandbox
from dixie.core.schema import (
    Confidence,
    EngagementState,
    Finding,
    Severity,
    ToolResult,
)
from dixie.constants import DEFAULT_MASSCAN_MAX_RATE
from dixie.models.llm import LLMClient
from dixie.tools.base import ToolRegistry

logger = logging.getLogger(__name__)
console = Console()


def _is_subnet(target: str) -> bool:
    """Check if target is a CIDR subnet rather than a single host (IPv4 or IPv6)."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.num_addresses > 1
    except (ValueError, TypeError):
        return False


def _tool_error_retry_fruitless(error: str) -> bool:
    """True when repeating the same command is unlikely to fix the failure."""
    e = error.lower()
    return any(
        needle in e
        for needle in (
            "usage:",
            "need root",
            "needs root",
            "command not found",
            "not permitted",
            "invalid option",
        )
    )


class Agent:
    """ReAct-style pentesting agent.

    Observe -> Think -> Act -> Observe loop with tool dispatch.
    """

    def __init__(
        self,
        config: EngagementConfig,
        llm: LLMClient,
        tools: ToolRegistry,
        sandbox: Sandbox,
    ) -> None:
        self.config = config
        self.llm = llm
        self.tools = tools
        self.sandbox = sandbox
        self.state = EngagementState(target=config.target)
        self.use_docker = sandbox.ensure_image()

    @property
    def is_recon_mode(self) -> bool:
        return self.config.mode == EngagementMode.RECON

    def _build_context(self) -> str:
        """Build the engagement context message for the LLM."""
        summary = self.state.summary()
        recent_results = self.state.tool_history[-5:] if self.state.tool_history else []
        recent = [
            {"tool": r.tool, "success": r.success, "output_preview": r.raw_output[:500]}
            for r in recent_results
        ]

        context: dict = {
            "engagement": summary,
            "mode": self.config.mode.value,
            "scope": self.config.scope,
            "out_of_scope": self.config.out_of_scope,
            "available_tools": [t.name for t in self.tools.list_tools()],
            "recent_results": recent,
        }

        if self.state.findings:
            context["findings_so_far"] = [
                {"title": f.title, "severity": f.severity.value}
                for f in self.state.findings
            ]

        if _is_subnet(self.config.target):
            context["target_type"] = "subnet"
            context["note"] = (
                "Target is a subnet. Start with host discovery (nmap -sn or arp-scan) "
                "before scanning individual hosts."
            )

        return json.dumps(context, indent=2)

    def _engagement_limit_reason(self, wall_start: float) -> str | None:
        """Return a short reason string if a configured budget cap is exhausted."""
        cfg = self.config.agent
        if cfg.max_wall_clock_seconds is not None:
            elapsed = time.monotonic() - wall_start
            if elapsed >= cfg.max_wall_clock_seconds:
                return (
                    f"wall_clock_limit ({cfg.max_wall_clock_seconds}s elapsed, "
                    f"{elapsed:.1f}s)"
                )
        if cfg.max_llm_total_tokens is not None:
            if self.llm.total_tokens >= cfg.max_llm_total_tokens:
                return (
                    f"llm_token_limit ({self.llm.total_tokens}/"
                    f"{cfg.max_llm_total_tokens} total_tokens)"
                )
        if cfg.max_llm_cost_usd is not None:
            if self.llm.total_cost >= cfg.max_llm_cost_usd:
                return (
                    f"llm_cost_limit (${self.llm.total_cost:.4f}/"
                    f"${cfg.max_llm_cost_usd} estimated)"
                )
        return None

    def _handle_report_finding(self, arguments: dict) -> str:
        """Handle the report_finding pseudo-tool call."""
        try:
            severity = Severity(arguments.get("severity", "info").lower())
        except ValueError:
            severity = Severity.INFO

        try:
            confidence = Confidence(arguments.get("confidence", "tentative").lower())
        except ValueError:
            confidence = Confidence.TENTATIVE

        evidence_raw = arguments.get("evidence", "")
        evidence = [evidence_raw] if evidence_raw else []

        affected_raw = arguments.get("affected_assets", "")
        affected = [a.strip() for a in affected_raw.split(",") if a.strip()] if affected_raw else []

        cve_raw = arguments.get("cve_ids", "")
        cve_ids = [c.strip() for c in cve_raw.split(",") if c.strip()] if cve_raw else []

        cwe_raw = arguments.get("cwe_ids", "")
        cwe_ids = [c.strip() for c in cwe_raw.split(",") if c.strip()] if cwe_raw else []

        techniques_raw = arguments.get("attack_techniques", "")
        techniques = [t.strip() for t in techniques_raw.split(",") if t.strip()] if techniques_raw else []

        cvss_score = arguments.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        finding = Finding(
            title=arguments.get("title", "Untitled Finding"),
            description=arguments.get("description", ""),
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            remediation=arguments.get("remediation", ""),
            affected_assets=affected,
            cvss_score=cvss_score,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            attack_techniques=techniques,
        )

        self.state.add_finding(finding)
        console.print(
            f"  [bold magenta]Finding #{len(self.state.findings)}:[/bold magenta] "
            f"[{severity.value.upper()}] {finding.title}"
        )

        return json.dumps({
            "status": "recorded",
            "finding_number": len(self.state.findings),
            "title": finding.title,
            "severity": severity.value,
        })

    def _is_tool_allowed(self, name: str) -> bool:
        """Check if tool is allowed in current engagement mode."""
        if not self.is_recon_mode:
            return True
        return name not in RECON_BLOCKED_TOOLS

    def _merge_engagement_tool_defaults(self, name: str, arguments: dict) -> dict:
        """Apply engagement YAML tool defaults for missing or empty tool arguments."""
        merged = dict(arguments)
        if name == "gobuster_dir":
            override = self.config.tool_defaults.gobuster_wordlist
            if override:
                cur = merged.get("wordlist")
                if cur is None or (isinstance(cur, str) and cur.strip() == ""):
                    merged["wordlist"] = override
        if name == "masscan":
            cap = self.config.tool_defaults.masscan_max_rate
            if cap is None:
                cap = DEFAULT_MASSCAN_MAX_RATE
            merged["_masscan_rate_cap"] = cap
            r = merged.get("rate")
            if r is not None:
                try:
                    rv = int(r)
                    merged["rate"] = max(1, min(rv, cap))
                except (TypeError, ValueError):
                    pass
        return merged

    def _execute_tool(self, name: str, arguments: dict) -> str:
        """Execute a tool and return the result as a string."""
        if name == "report_finding":
            return self._handle_report_finding(arguments)

        if not self._is_tool_allowed(name):
            msg = (
                f"Tool '{name}' is not permitted in recon mode. "
                f"Use non-intrusive alternatives only."
            )
            console.print(f"  [bold red]BLOCKED:[/bold red] {msg}")
            return json.dumps({"error": msg})

        tool = self.tools.get(name)
        if not tool:
            return json.dumps({"error": f"Unknown tool: {name}"})

        arguments = self._merge_engagement_tool_defaults(name, arguments)
        command = tool.build_command(**arguments)
        console.print(f"  [dim]$ {' '.join(command)}[/dim]")

        max_retry = self.config.agent.max_tool_retries
        result: ToolResult | None = None
        prev_error: str | None = None
        for attempt in range(max_retry + 1):
            if self.use_docker:
                result = self.sandbox.run_command(command, name)
            else:
                result = self.sandbox.run_local(command, name)

            if result.success:
                break
            err = result.error or ""
            if attempt < max_retry:
                if (
                    prev_error is not None
                    and err == prev_error
                    and _tool_error_retry_fruitless(err)
                ):
                    break
                prev_error = err
                console.print(
                    f"  [yellow]Tool failed (attempt {attempt + 1}/{max_retry + 1}), "
                    f"retrying…[/yellow]"
                )
                time.sleep(min(2.0, 0.25 * (2**attempt)))

        if result is None:
            logger.error("Tool execution loop produced no result")
            return json.dumps({"error": "Internal error: missing tool result"})

        self.state.add_result(result)

        if result.success:
            parsed = tool.parse_output(result.raw_output)
            result.structured = parsed
            return json.dumps(parsed, indent=2)

        return json.dumps({"error": result.error, "output": result.raw_output[:1000]})

    def _initial_prompt(self) -> str:
        """Build the initial engagement prompt, adapted for subnet vs single host."""
        context = self._build_context()

        if self.is_recon_mode and _is_subnet(self.config.target):
            return (
                f"Begin the passive network security assessment.\n\n"
                f"Engagement context:\n{context}\n\n"
                f"The target is a subnet ({self.config.target}). Start by discovering "
                f"live hosts using arp-scan or nmap ping sweep (-sn). Then enumerate "
                f"services on each discovered host. Report findings as you go."
            )
        elif self.is_recon_mode:
            return (
                f"Begin the passive network security assessment.\n\n"
                f"Engagement context:\n{context}\n\n"
                f"Start with service discovery and version detection on {self.config.target}. "
                f"Report any vulnerabilities or misconfigurations you identify."
            )
        else:
            return (
                f"Begin the penetration testing engagement.\n\n"
                f"Engagement context:\n{context}\n\n"
                f"Start with reconnaissance. What's your first move?"
            )

    def run(self) -> EngagementState:
        """Run the agent loop until completion or max iterations."""
        mode_label = "Passive Recon" if self.is_recon_mode else "Full Pentest"
        console.print(Panel(
            f"[bold red]Dixie Flatline[/bold red]\n"
            f"Target: [cyan]{self.config.target}[/cyan]\n"
            f"Mode: [yellow]{mode_label}[/yellow]\n"
            f"Model: [green]{self.config.llm.model}[/green]",
            title="Engagement Started",
        ))

        prompt = self._initial_prompt()
        wall_start = time.monotonic()
        agent_stopped_voluntarily = False

        while self.state.iteration < self.config.agent.max_iterations:
            limit_reason = self._engagement_limit_reason(wall_start)
            if limit_reason is not None:
                self.state.termination_reason = limit_reason
                console.print(
                    f"[yellow]Engagement stopped — budget cap: {limit_reason}[/yellow]"
                )
                break

            self.state.iteration += 1
            console.print(f"\n[bold]--- Iteration {self.state.iteration} ---[/bold]")

            response = self.llm.chat(prompt)

            if response.get("error"):
                err = response["error"]
                console.print(f"[red]LLM error: {err}[/red]")
                self.state.termination_reason = f"llm_error ({err})"
                break

            if response.get("tool_json_error"):
                tje = response["tool_json_error"]
                console.print(f"[red]LLM tool JSON error: {tje}[/red]")
                self.state.termination_reason = f"llm_tool_json_error ({tje})"
                break

            if response["content"]:
                console.print(Panel(response["content"], title="[yellow]Thinking[/yellow]"))

            budget_hit = self._engagement_limit_reason(wall_start)

            if not response["tool_calls"]:
                if budget_hit is not None:
                    self.state.termination_reason = budget_hit
                    console.print(
                        f"[yellow]Engagement stopped — budget cap after LLM response: "
                        f"{budget_hit}[/yellow]"
                    )
                else:
                    console.print("[green]Agent has no more actions. Engagement complete.[/green]")
                    agent_stopped_voluntarily = True
                break

            for tc in response["tool_calls"]:
                console.print(
                    f"  [bold blue]Tool:[/bold blue] {tc['name']}({json.dumps(tc['arguments'])})"
                )
                result_str = self._execute_tool(tc["name"], tc["arguments"])
                self.llm.submit_tool_result(tc["id"], result_str)

                preview = result_str[:200]
                suffix = "..." if len(result_str) > 200 else ""
                console.print(f"  [dim]Result: {preview}{suffix}[/dim]")

            context = self._build_context()
            prompt = (
                f"Updated engagement context:\n{context}\n\n"
                f"Analyze the results and decide your next action."
            )

            limit_reason = self._engagement_limit_reason(wall_start)
            if limit_reason is not None:
                self.state.termination_reason = limit_reason
                console.print(
                    f"[yellow]Engagement stopped — budget cap after tools: "
                    f"{limit_reason}[/yellow]"
                )
                break

        if (
            self.state.termination_reason is None
            and not agent_stopped_voluntarily
            and self.state.iteration >= self.config.agent.max_iterations
        ):
            self.state.termination_reason = (
                f"max_iterations ({self.config.agent.max_iterations})"
            )

        summary_lines = (
            f"Iterations: {self.state.iteration}\n"
            f"Findings: {len(self.state.findings)}\n"
            f"Tools run: {len(self.state.tool_history)}\n"
            f"LLM total_tokens: {self.llm.total_tokens}\n"
            f"LLM est. cost USD: {self.llm.total_cost:.6f}"
        )
        if self.state.termination_reason:
            summary_lines += f"\nStop reason: {self.state.termination_reason}"

        console.print(Panel(
            summary_lines,
            title="[bold red]Engagement Complete[/bold red]",
        ))

        return self.state
