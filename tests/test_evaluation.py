"""Tests for the deterministic multi-model bakeoff harness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from dixie.evaluation import BakeoffRunner, BakeoffSuite, render_markdown
from dixie.evaluation.models import CandidateConfig, TurnExpectation
from dixie.tools import build_default_registry


class FakeClient:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.total_tokens = 0
        self.total_cost = 0.0
        self.submitted: list[tuple[str, str]] = []
        self.reset_count = 0

    def reset(self) -> None:
        self.reset_count += 1

    def chat(self, user_message: str) -> dict[str, Any]:
        del user_message
        self.total_tokens += 10
        self.total_cost += 0.001
        return self.responses.pop(0)

    def submit_tool_result(self, tool_call_id: str, result: str) -> None:
        self.submitted.append((tool_call_id, result))


def _suite() -> BakeoffSuite:
    return BakeoffSuite.model_validate(
        {
            "version": 1,
            "name": "unit-suite",
            "candidates": [
                {"id": "good", "model": "openai/good"},
                {"id": "bad", "model": "openai/bad"},
            ],
            "scenarios": [
                {
                    "id": "enumerate",
                    "category": "tool-selection",
                    "turns": [
                        {
                            "prompt": "Enumerate authorized lab host 192.0.2.1",
                            "expected_tools": ["nmap_scan"],
                            "expected_arguments": {"target": "192.0.2.1"},
                            "tool_results": {"nmap_scan": {"hosts": []}},
                        }
                    ],
                }
            ],
        }
    )


def test_suite_requires_unique_ids() -> None:
    data = _suite().model_dump()
    data["candidates"].append(data["candidates"][0])
    with pytest.raises(ValueError, match="candidate ids must be unique"):
        BakeoffSuite.model_validate(data)


def test_candidate_resolves_api_base_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = CandidateConfig(
        id="qwen",
        model="openai/qwen",
        api_base_env="DIXIE_TEST_API_BASE",
    )
    with pytest.raises(ValueError, match="DIXIE_TEST_API_BASE"):
        candidate.llm_config()
    monkeypatch.setenv("DIXIE_TEST_API_BASE", "http://127.0.0.1:8000/v1")
    assert candidate.llm_config().api_base == "http://127.0.0.1:8000/v1"


def test_runner_scores_and_ranks_candidates() -> None:
    clients = {
        "good": FakeClient(
            [
                {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "name": "nmap_scan",
                            "arguments": {"target": "192.0.2.1"},
                        }
                    ],
                }
            ]
        ),
        "bad": FakeClient([{"content": "I found port 80", "tool_calls": []}]),
    }

    def factory(candidate: CandidateConfig, tools: Any) -> FakeClient:
        del tools
        return clients[candidate.id]

    report = BakeoffRunner(build_default_registry(), factory).run(_suite())
    assert [result.candidate_id for result in report.ranked_results()] == ["good", "bad"]
    assert report.results[0].score == 1.0
    assert report.results[0].total_tokens == 10
    assert report.results[0].total_cost_usd == pytest.approx(0.001)
    assert report.results[1].score < report.results[0].score
    assert clients["good"].submitted == [("call-1", '{"hosts": []}')]


def test_runner_detects_unknown_tool_and_missing_required_argument() -> None:
    client = FakeClient(
        [
            {
                "content": None,
                "tool_calls": [
                    {"id": "x", "name": "invented_scanner", "arguments": {}},
                    {"id": "y", "name": "nmap_scan", "arguments": {}},
                ],
            }
        ]
    )

    report = BakeoffRunner(
        build_default_registry(),
        lambda candidate, tools: client,
    ).run(_suite(), selected_candidates={"good"})
    checks = report.results[0].scenarios[0].turns[0].checks
    failures = {check.name: check.detail for check in checks if not check.passed}
    assert "known_tool[0]" in failures
    assert "valid_arguments[1]" in failures
    assert "target" in failures["valid_arguments[1]"]


def test_runner_submits_scripted_results_between_turns() -> None:
    suite = _suite()
    suite.scenarios[0].turns.append(
        TurnExpectation(
            prompt="Continue",
            expected_tools=[],
            content_contains=["complete"],
        )
    )
    client = FakeClient(
        [
            {
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-2",
                        "name": "nmap_scan",
                        "arguments": {"target": "192.0.2.1"},
                    }
                ],
            },
            {"content": "Enumeration complete", "tool_calls": []},
        ]
    )
    report = BakeoffRunner(
        build_default_registry(), lambda candidate, tools: client
    ).run(suite, selected_candidates={"good"})
    assert len(report.results[0].scenarios[0].turns) == 2
    assert report.results[0].score == 1.0
    assert client.submitted


def test_unknown_candidate_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown candidate"):
        BakeoffRunner(build_default_registry(), lambda candidate, tools: FakeClient([])).run(
            _suite(), selected_candidates={"missing"}
        )


def test_markdown_contains_ranking_and_failures() -> None:
    clients = {
        "good": FakeClient(
            [
                {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "name": "nmap_scan",
                            "arguments": {"target": "192.0.2.1"},
                        }
                    ],
                }
            ]
        ),
        "bad": FakeClient([{"content": "guessed", "tool_calls": []}]),
    }
    report = BakeoffRunner(
        build_default_registry(), lambda candidate, tools: clients[candidate.id]
    ).run(_suite())
    markdown = render_markdown(report)
    assert "# Dixie Model Bakeoff" in markdown
    assert "`good`" in markdown
    assert "FAIL `expected_tool`" in markdown


def test_repository_manifest_parses() -> None:
    path = Path(__file__).resolve().parents[1] / "configs" / "model_bakeoff.yaml"
    suite = BakeoffSuite.from_file(path)
    assert suite.version == 1
    assert len(suite.candidates) == 5
    assert len(suite.scenarios) == 4
