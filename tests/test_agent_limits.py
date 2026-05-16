"""Tests for Agent engagement budgets (P4: token, cost, wall-clock caps)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dixie.core.agent import Agent
from dixie.core.config import AgentConfig, EngagementConfig
from dixie.tools import build_default_registry


def _make_agent(
    agent_cfg: AgentConfig | None = None,
    llm: object | None = None,
) -> Agent:
    config = EngagementConfig(target="192.168.1.1", agent=agent_cfg or AgentConfig())
    tools = build_default_registry()
    sandbox = MagicMock()
    sandbox.ensure_image.return_value = False
    llm = llm or MagicMock()
    return Agent(config=config, llm=llm, tools=tools, sandbox=sandbox)


class TestEngagementLimitReason:
    def test_no_limits_configured(self) -> None:
        agent = _make_agent()
        assert agent._engagement_limit_reason(0.0) is None

    def test_token_limit(self) -> None:
        cfg = AgentConfig(max_llm_total_tokens=100)
        agent = _make_agent(cfg)
        agent.llm.total_tokens = 100
        agent.llm.total_cost = 0.0
        r = agent._engagement_limit_reason(0.0)
        assert r is not None
        assert "llm_token_limit" in r
        assert "100" in r

    def test_cost_limit(self) -> None:
        cfg = AgentConfig(max_llm_cost_usd=0.05)
        agent = _make_agent(cfg)
        agent.llm.total_tokens = 0
        agent.llm.total_cost = 0.05
        r = agent._engagement_limit_reason(0.0)
        assert r is not None
        assert "llm_cost_limit" in r

    def test_wall_clock_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = AgentConfig(max_wall_clock_seconds=30)
        agent = _make_agent(cfg)
        agent.llm.total_tokens = 0
        agent.llm.total_cost = 0.0

        class _Clock:
            t = 0.0

        def mono() -> float:
            return _Clock.t

        monkeypatch.setattr("dixie.core.agent.time.monotonic", mono)
        assert agent._engagement_limit_reason(0.0) is None
        _Clock.t = 31.0
        r = agent._engagement_limit_reason(0.0)
        assert r is not None
        assert "wall_clock_limit" in r


class FakeBudgetLLM:
    """Minimal LLM stub for Agent.run budget tests."""

    def __init__(self) -> None:
        self.total_tokens = 0
        self.total_cost = 0.0
        self.calls = 0

    def chat(self, prompt: str) -> dict:
        self.calls += 1
        self.total_tokens += 1000
        if self.calls < 3:
            return {
                "content": "step",
                "tool_calls": [{
                    "id": str(self.calls),
                    "name": "report_finding",
                    "arguments": {
                        "title": "Note",
                        "description": "d",
                        "severity": "info",
                    },
                }],
            }
        return {"content": "done", "tool_calls": []}

    def submit_tool_result(self, tool_call_id: str, result: str) -> None:
        pass


class TestAgentRunBudgets:
    def test_stops_after_token_budget_post_tools(self) -> None:
        cfg = AgentConfig(max_iterations=20, max_llm_total_tokens=2500)
        llm = FakeBudgetLLM()
        agent = _make_agent(cfg, llm=llm)
        state = agent.run()
        assert llm.calls == 3
        assert state.termination_reason is not None
        assert "llm_token_limit" in state.termination_reason

    def test_max_iterations_reason_when_exhausted(self) -> None:
        cfg = AgentConfig(max_iterations=2)
        llm = FakeBudgetLLM()
        agent = _make_agent(cfg, llm=llm)
        state = agent.run()
        assert state.iteration == cfg.max_iterations
        assert state.termination_reason is not None
        assert "max_iterations" in state.termination_reason

    def test_voluntary_stop_no_max_iter_reason(self) -> None:
        cfg = AgentConfig(max_iterations=50, max_llm_total_tokens=50_000)
        llm = FakeBudgetLLM()
        agent = _make_agent(cfg, llm=llm)
        state = agent.run()
        assert llm.calls == 3
        assert state.termination_reason is None
