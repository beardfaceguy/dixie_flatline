"""Data models for reproducible Dixie model bakeoffs."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from dixie.core.config import LLMConfig


class CandidateConfig(BaseModel):
    """One model endpoint participating in a bakeoff."""

    id: str = Field(min_length=1)
    model: str = Field(min_length=1)
    api_base: str | None = None
    api_base_env: str | None = None
    temperature: float = 0.2
    max_tokens: int = Field(default=4096, ge=1)
    enabled: bool = True
    notes: str = ""

    @model_validator(mode="after")
    def exclusive_api_base(self) -> CandidateConfig:
        if self.api_base and self.api_base_env:
            raise ValueError("set only one of api_base or api_base_env")
        return self

    def llm_config(self) -> LLMConfig:
        """Resolve endpoint configuration without putting credentials in manifests."""
        api_base = self.api_base
        if self.api_base_env:
            api_base = os.environ.get(self.api_base_env)
            if not api_base:
                raise ValueError(
                    f"candidate '{self.id}' requires environment variable {self.api_base_env}"
                )
        return LLMConfig(
            model=self.model,
            api_base=api_base,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )


class TurnExpectation(BaseModel):
    """Deterministic expectations for one model turn."""

    prompt: str = Field(min_length=1)
    expected_tools: list[str] | None = None
    expected_arguments: dict[str, Any] = Field(default_factory=dict)
    content_contains: list[str] = Field(default_factory=list)
    tool_results: dict[str, Any] = Field(default_factory=dict)


class Scenario(BaseModel):
    """A versioned, controlled interaction evaluated for every candidate."""

    id: str = Field(min_length=1)
    category: str = "general"
    description: str = ""
    turns: list[TurnExpectation] = Field(min_length=1)


class BakeoffSuite(BaseModel):
    """Candidate and scenario manifest loaded from YAML."""

    version: int = Field(default=1, ge=1)
    name: str = Field(min_length=1)
    candidates: list[CandidateConfig] = Field(min_length=1)
    scenarios: list[Scenario] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_ids(self) -> BakeoffSuite:
        candidate_ids = [candidate.id for candidate in self.candidates]
        scenario_ids = [scenario.id for scenario in self.scenarios]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate ids must be unique")
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("scenario ids must be unique")
        return self

    @classmethod
    def from_file(cls, path: Path) -> BakeoffSuite:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return cls.model_validate(data)


class CheckResult(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class TurnResult(BaseModel):
    turn: int
    latency_seconds: float = Field(ge=0)
    response: dict[str, Any]
    checks: list[CheckResult]
    passed_checks: int = Field(ge=0)
    total_checks: int = Field(ge=0)

    @property
    def score(self) -> float:
        return self.passed_checks / self.total_checks if self.total_checks else 0.0


class ScenarioResult(BaseModel):
    scenario_id: str
    category: str
    turns: list[TurnResult]

    @property
    def passed_checks(self) -> int:
        return sum(turn.passed_checks for turn in self.turns)

    @property
    def total_checks(self) -> int:
        return sum(turn.total_checks for turn in self.turns)

    @property
    def score(self) -> float:
        return self.passed_checks / self.total_checks if self.total_checks else 0.0


class CandidateResult(BaseModel):
    candidate_id: str
    model: str
    scenarios: list[ScenarioResult]
    total_tokens: int = Field(ge=0)
    total_cost_usd: float = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)

    @property
    def passed_checks(self) -> int:
        return sum(scenario.passed_checks for scenario in self.scenarios)

    @property
    def total_checks(self) -> int:
        return sum(scenario.total_checks for scenario in self.scenarios)

    @property
    def score(self) -> float:
        return self.passed_checks / self.total_checks if self.total_checks else 0.0


class BakeoffReport(BaseModel):
    suite_name: str
    suite_version: int
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    results: list[CandidateResult]

    def ranked_results(self) -> list[CandidateResult]:
        """Return a stable best-first ranking by score, then latency and id."""
        return sorted(
            self.results,
            key=lambda result: (-result.score, result.elapsed_seconds, result.candidate_id),
        )
