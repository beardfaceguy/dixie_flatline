"""Tests for configuration loading."""

import tempfile
from pathlib import Path

import yaml

from dixie.core.config import EngagementConfig, LLMConfig, SandboxConfig


class TestEngagementConfig:
    def test_defaults(self):
        config = EngagementConfig(target="192.168.1.1")
        assert config.target == "192.168.1.1"
        assert config.llm.model == "openai/gpt-4o"
        assert config.sandbox.timeout == 300
        assert config.agent.max_iterations == 50

    def test_from_file(self):
        data = {
            "target": "10.0.0.1",
            "scope": ["10.0.0.0/24"],
            "llm": {"model": "anthropic/claude-sonnet-4-20250514", "temperature": 0.1},
            "agent": {"max_iterations": 20},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            path = Path(f.name)

        config = EngagementConfig.from_file(path)
        assert config.target == "10.0.0.1"
        assert config.llm.model == "anthropic/claude-sonnet-4-20250514"
        assert config.llm.temperature == 0.1
        assert config.agent.max_iterations == 20
        assert config.sandbox.timeout == 300  # default preserved

        path.unlink()

    def test_custom_sandbox(self):
        config = EngagementConfig(
            target="192.168.1.1",
            sandbox=SandboxConfig(image="custom:v2", timeout=60),
        )
        assert config.sandbox.image == "custom:v2"
        assert config.sandbox.timeout == 60

    def test_agent_budget_fields_from_file(self):
        data = {
            "target": "10.0.0.1",
            "agent": {
                "max_iterations": 5,
                "max_llm_total_tokens": 10000,
                "max_llm_cost_usd": 2.5,
                "max_wall_clock_seconds": 600,
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            path = Path(f.name)

        config = EngagementConfig.from_file(path)
        assert config.agent.max_iterations == 5
        assert config.agent.max_llm_total_tokens == 10000
        assert config.agent.max_llm_cost_usd == 2.5
        assert config.agent.max_wall_clock_seconds == 600

        path.unlink()


class TestLLMConfig:
    def test_defaults(self):
        config = LLMConfig()
        assert config.model == "openai/gpt-4o"
        assert config.temperature == 0.2
        assert config.api_base is None

    def test_ollama_config(self):
        config = LLMConfig(
            model="ollama/whiterabbitneo-v3",
            api_base="http://localhost:11434",
        )
        assert "ollama" in config.model
        assert config.api_base is not None
