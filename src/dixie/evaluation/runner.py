"""Execution and deterministic scoring for Dixie model bakeoffs."""

from __future__ import annotations

import json
from collections.abc import Callable
from time import perf_counter
from typing import Any, Protocol

from dixie.models.llm import LLMClient
from dixie.tools.base import ToolRegistry

from .models import (
    BakeoffReport,
    BakeoffSuite,
    CandidateConfig,
    CandidateResult,
    CheckResult,
    Scenario,
    ScenarioResult,
    TurnExpectation,
    TurnResult,
)


class BakeoffClient(Protocol):
    """Minimal client surface required by the bakeoff runner."""

    total_tokens: int
    total_cost: float

    def reset(self) -> None: ...

    def chat(self, user_message: str) -> dict[str, Any]: ...

    def submit_tool_result(self, tool_call_id: str, result: str) -> None: ...


ClientFactory = Callable[[CandidateConfig, ToolRegistry], BakeoffClient]


def default_client_factory(candidate: CandidateConfig, tools: ToolRegistry) -> BakeoffClient:
    """Create the normal LiteLLM-backed client for a candidate endpoint."""
    return LLMClient(candidate.llm_config(), tools)


class BakeoffRunner:
    """Run every selected candidate against the exact same scenario suite."""

    def __init__(
        self,
        tools: ToolRegistry,
        client_factory: ClientFactory = default_client_factory,
    ) -> None:
        self.tools = tools
        self.client_factory = client_factory

    def run(
        self,
        suite: BakeoffSuite,
        selected_candidates: set[str] | None = None,
    ) -> BakeoffReport:
        candidates = [candidate for candidate in suite.candidates if candidate.enabled]
        if selected_candidates is not None:
            known = {candidate.id for candidate in suite.candidates}
            unknown = selected_candidates - known
            if unknown:
                raise ValueError(f"unknown candidate id(s): {', '.join(sorted(unknown))}")
            candidates = [
                candidate for candidate in candidates if candidate.id in selected_candidates
            ]
        if not candidates:
            raise ValueError("no enabled candidates selected")

        return BakeoffReport(
            suite_name=suite.name,
            suite_version=suite.version,
            results=[self._run_candidate(candidate, suite.scenarios) for candidate in candidates],
        )

    def _run_candidate(
        self,
        candidate: CandidateConfig,
        scenarios: list[Scenario],
    ) -> CandidateResult:
        client = self.client_factory(candidate, self.tools)
        started = perf_counter()
        scenario_results = [self._run_scenario(client, scenario) for scenario in scenarios]
        return CandidateResult(
            candidate_id=candidate.id,
            model=candidate.model,
            scenarios=scenario_results,
            total_tokens=max(0, int(client.total_tokens)),
            total_cost_usd=max(0.0, float(client.total_cost)),
            elapsed_seconds=perf_counter() - started,
        )

    def _run_scenario(
        self,
        client: BakeoffClient,
        scenario: Scenario,
    ) -> ScenarioResult:
        client.reset()
        turns: list[TurnResult] = []
        for index, expectation in enumerate(scenario.turns, start=1):
            started = perf_counter()
            response = client.chat(expectation.prompt)
            latency = perf_counter() - started
            checks = self._score_turn(response, expectation)
            turns.append(
                TurnResult(
                    turn=index,
                    latency_seconds=latency,
                    response=response,
                    checks=checks,
                    passed_checks=sum(check.passed for check in checks),
                    total_checks=len(checks),
                )
            )
            self._submit_scripted_results(client, response, expectation)
        return ScenarioResult(scenario_id=scenario.id, category=scenario.category, turns=turns)

    def _score_turn(
        self,
        response: dict[str, Any],
        expectation: TurnExpectation,
    ) -> list[CheckResult]:
        checks = [
            CheckResult(
                name="provider_response",
                passed="error" not in response,
                detail=str(response.get("error", "")),
            ),
            CheckResult(
                name="tool_json_valid",
                passed="tool_json_error" not in response,
                detail=str(response.get("tool_json_error", "")),
            ),
        ]

        tool_calls = response.get("tool_calls") or []
        if not isinstance(tool_calls, list):
            tool_calls = []
            checks.append(
                CheckResult(
                    name="tool_calls_list",
                    passed=False,
                    detail="response.tool_calls was not a list",
                )
            )

        for position, tool_call in enumerate(tool_calls):
            name = tool_call.get("name") if isinstance(tool_call, dict) else None
            arguments = tool_call.get("arguments") if isinstance(tool_call, dict) else None
            tool = self.tools.get(name) if isinstance(name, str) else None
            checks.append(
                CheckResult(
                    name=f"known_tool[{position}]",
                    passed=tool is not None,
                    detail=f"tool={name!r}",
                )
            )
            valid_arguments = isinstance(arguments, dict)
            detail = "arguments must be an object"
            if valid_arguments and tool is not None:
                validation_error = tool.validate_arguments(arguments)
                valid_arguments = validation_error is None
                detail = validation_error or ""
            checks.append(
                CheckResult(
                    name=f"valid_arguments[{position}]",
                    passed=valid_arguments,
                    detail=detail,
                )
            )

        if expectation.expected_tools is not None:
            actual_tools = [
                call.get("name")
                for call in tool_calls
                if isinstance(call, dict) and isinstance(call.get("name"), str)
            ]
            if expectation.expected_tools:
                passed = any(name in expectation.expected_tools for name in actual_tools)
                detail = (
                    f"expected one of {expectation.expected_tools!r}; got {actual_tools!r}"
                )
            else:
                passed = not actual_tools
                detail = f"expected no tool call; got {actual_tools!r}"
            checks.append(CheckResult(name="expected_tool", passed=passed, detail=detail))

        if expectation.expected_arguments:
            matching_calls = [
                call
                for call in tool_calls
                if isinstance(call, dict)
                and isinstance(call.get("arguments"), dict)
                and all(
                    call["arguments"].get(key) == value
                    for key, value in expectation.expected_arguments.items()
                )
            ]
            checks.append(
                CheckResult(
                    name="expected_arguments",
                    passed=bool(matching_calls),
                    detail=f"expected subset {expectation.expected_arguments!r}",
                )
            )

        content = response.get("content") or ""
        for expected in expectation.content_contains:
            checks.append(
                CheckResult(
                    name=f"content_contains:{expected}",
                    passed=expected.casefold() in str(content).casefold(),
                    detail=f"content did not contain {expected!r}",
                )
            )
        return checks

    @staticmethod
    def _submit_scripted_results(
        client: BakeoffClient,
        response: dict[str, Any],
        expectation: TurnExpectation,
    ) -> None:
        for tool_call in response.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            name = tool_call.get("name")
            call_id = tool_call.get("id")
            if name not in expectation.tool_results or not call_id:
                continue
            result = expectation.tool_results[name]
            if not isinstance(result, str):
                result = json.dumps(result)
            client.submit_tool_result(str(call_id), result)
