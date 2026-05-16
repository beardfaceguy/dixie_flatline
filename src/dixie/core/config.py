"""Configuration management for Dixie Flatline."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class EngagementMode(str, Enum):
    RECON = "recon"
    FULL = "full"


class LLMConfig(BaseModel):
    model: str = "openai/gpt-4o"
    temperature: float = 0.2
    max_tokens: int = 4096
    api_base: str | None = None


class SandboxConfig(BaseModel):
    image: str = "dixie-sandbox:latest"
    timeout: int = 300
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    network_mode: str = "bridge"


class AgentConfig(BaseModel):
    max_iterations: int = Field(default=50, ge=1)
    max_tool_retries: int = Field(default=2, ge=0)
    # Optional engagement caps (None = disabled). Checked between LLM rounds.
    max_llm_total_tokens: int | None = Field(
        default=None,
        ge=1,
        description="Stop before the next LLM call when cumulative usage meets or exceeds this.",
    )
    max_llm_cost_usd: float | None = Field(
        default=None,
        gt=0,
        description="Stop before the next LLM call when estimated cumulative spend meets or exceeds this (LiteLLM).",
    )
    max_wall_clock_seconds: int | None = Field(
        default=None,
        ge=1,
        description="Stop before the next LLM call when wall time since engagement start meets or exceeds this.",
    )


class EngagementConfig(BaseModel):
    """Top-level configuration for a penetration testing engagement."""

    target: str
    mode: EngagementMode = EngagementMode.FULL
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    output_dir: Path = Path("./output")
    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)

    @classmethod
    def from_file(cls, path: Path) -> EngagementConfig:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
