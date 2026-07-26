"""Regression tests for Cursor review findings (Vikunja Phase 1).

Guards against regressions for malformed tool JSON, Nikto parsing, masscan rate,
agent retries, intel env parsing, NVD totals, agent invariants, and review rounds 3+.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dixie.core import agent as agent_module
from dixie.core.agent import Agent
from dixie.core.config import AgentConfig, EngagementConfig, LLMConfig
from dixie.core.schema import ToolResult
from dixie.intel.collectors.exploit_intel import ExploitIntelCollector, _parse_iso
from dixie.intel.collectors.nvd import NvdCollector
from dixie.intel.collectors.reddit import RedditCollector
from dixie.intel.pipeline import build_collectors
from dixie.intel.store import IntelStore
from dixie.intel.translate import translate_pending
from dixie.models.llm import LLMClient
from dixie.tools import build_default_registry
from dixie.tools.base import ToolRegistry
from dixie.tools.masscan import MasscanTool
from dixie.tools.nikto import NiktoTool


class TestMalformedToolCallJson:
    """Review: invalid tool JSON must not become {} and break required parameters."""

    def test_malformed_arguments_include_target_or_calls_omitted(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)

        fake_fn = SimpleNamespace(name="nikto_scan", arguments="{not json")
        fake_tc = SimpleNamespace(id="tc1", function=fake_fn)
        fake_message = MagicMock()
        fake_message.content = None
        fake_message.tool_calls = [fake_tc]
        fake_message.model_dump.return_value = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "tc1",
                "type": "function",
                "function": {"name": "nikto_scan", "arguments": "{not json"},
            }],
        }

        fake_choice = SimpleNamespace(message=fake_message)
        fake_usage = SimpleNamespace(total_tokens=5)
        fake_resp = SimpleNamespace(choices=[fake_choice], usage=fake_usage)

        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = fake_resp
            litellm_mock.completion_cost.return_value = 0.0
            out = client.chat("scan")

        nikto_calls = [tc for tc in out["tool_calls"] if tc["name"] == "nikto_scan"]
        assert not nikto_calls or "target" in nikto_calls[0]["arguments"]
        assert client.messages[-1].get("tool_calls") in (None, [])
        assert out.get("tool_json_error")

    def test_tool_calls_without_function_attr_are_skipped(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)
        tc = SimpleNamespace(id="no-fn", type="function")
        fake_message = MagicMock()
        fake_message.content = "x"
        fake_message.tool_calls = [tc]
        fake_message.model_dump.return_value = {"role": "assistant", "content": "x", "tool_calls": []}

        fake_choice = SimpleNamespace(message=fake_message)
        fake_resp = SimpleNamespace(choices=[fake_choice], usage=SimpleNamespace(total_tokens=1))

        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = fake_resp
            litellm_mock.completion_cost.return_value = 0.0
            out = client.chat("z")

        assert out["tool_calls"] == []
        assert out.get("tool_json_error")

    def test_assistant_history_keeps_only_valid_tool_calls_when_mixed(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)

        bad_fn = SimpleNamespace(name="nikto_scan", arguments="{not json")
        bad_tc = SimpleNamespace(id="bad", type="function", function=bad_fn)
        good_fn = SimpleNamespace(name="nikto_scan", arguments='{"target": "http://x"}')
        good_tc = SimpleNamespace(id="good", type="function", function=good_fn)

        fake_message = MagicMock()
        fake_message.content = "ok"
        fake_message.tool_calls = [bad_tc, good_tc]
        fake_message.model_dump.return_value = {
            "role": "assistant",
            "content": "ok",
            "tool_calls": [],
        }

        fake_choice = SimpleNamespace(message=fake_message)
        fake_usage = SimpleNamespace(total_tokens=3)
        fake_resp = SimpleNamespace(choices=[fake_choice], usage=fake_usage)

        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = fake_resp
            litellm_mock.completion_cost.return_value = 0.0
            out = client.chat("go")

        assert len(out["tool_calls"]) == 1
        assert out["tool_calls"][0]["id"] == "good"
        dumped = client.messages[-1].get("tool_calls") or []
        assert len(dumped) == 1
        assert dumped[0]["id"] == "good"

    def test_all_invalid_tool_calls_surfaces_tool_json_error(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)

        fn = SimpleNamespace(name="nikto_scan", arguments="[]")
        tc = SimpleNamespace(id="tc1", type="function", function=fn)
        fake_message = MagicMock()
        fake_message.content = None
        fake_message.tool_calls = [tc]
        fake_message.model_dump.return_value = {"role": "assistant", "content": None, "tool_calls": []}

        fake_choice = SimpleNamespace(message=fake_message)
        fake_resp = SimpleNamespace(choices=[fake_choice], usage=SimpleNamespace(total_tokens=1))

        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = fake_resp
            litellm_mock.completion_cost.return_value = 0.0
            out = client.chat("x")

        assert out["tool_calls"] == []
        assert client.messages[-1].get("tool_calls") in (None, [])
        assert out.get("tool_json_error")

    def test_tool_arguments_as_dict_is_accepted(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)

        fn = SimpleNamespace(name="nikto_scan", arguments={"target": "http://ex"})
        tc = SimpleNamespace(id="d1", type="function", function=fn)
        fake_message = MagicMock()
        fake_message.content = "ok"
        fake_message.tool_calls = [tc]
        fake_message.model_dump.return_value = {
            "role": "assistant",
            "content": "ok",
            "tool_calls": [],
        }

        fake_choice = SimpleNamespace(message=fake_message)
        fake_resp = SimpleNamespace(
            choices=[fake_choice], usage=SimpleNamespace(total_tokens=2)
        )

        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = fake_resp
            litellm_mock.completion_cost.return_value = 0.0
            out = client.chat("go")

        assert len(out["tool_calls"]) == 1
        assert out["tool_calls"][0]["arguments"]["target"] == "http://ex"

    def test_tool_arguments_non_json_serializable_does_not_crash(self) -> None:
        class _Opaque:
            pass

        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)

        fn = SimpleNamespace(name="nikto_scan", arguments=_Opaque())
        tc = SimpleNamespace(id="w1", type="function", function=fn)
        fake_message = MagicMock()
        fake_message.content = "ok"
        fake_message.tool_calls = [tc]
        fake_message.model_dump.return_value = {
            "role": "assistant",
            "content": "ok",
            "tool_calls": [],
        }

        fake_choice = SimpleNamespace(message=fake_message)
        fake_resp = SimpleNamespace(
            choices=[fake_choice], usage=SimpleNamespace(total_tokens=1)
        )

        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = fake_resp
            litellm_mock.completion_cost.return_value = 0.0
            out = client.chat("go")

        assert out["tool_calls"] == []


class TestNiktoFormatAlignment:
    """Review: plain-text Nikto findings should appear in structured output where expected."""

    def test_typical_plaintext_item_line_is_captured(self) -> None:
        tool = NiktoTool()
        raw = "+ /cgi-bin/: CGI Directory found (403).\n"
        result = tool.parse_output(raw)
        assert result["total_found"] >= 1


class TestMasscanRateConfig:
    """Review: rate limits should not be an undisclosed literal clamp in the tool."""

    def test_high_rate_is_not_silently_capped_without_config(self) -> None:
        cmd = MasscanTool().build_command(target="10.0.0.0/24", ports="80", rate=50_000)
        rate_idx = cmd.index("--rate") + 1
        assert int(cmd[rate_idx]) == 50_000

    def test_engagement_clamps_masscan_rate_to_config_cap(self) -> None:
        from dixie.core.config import ToolDefaultsConfig

        config = EngagementConfig(
            target="192.168.1.1",
            tool_defaults=ToolDefaultsConfig(masscan_max_rate=8000),
        )
        tools = build_default_registry()
        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=MagicMock())
        merged = agent._merge_engagement_tool_defaults(
            "masscan",
            {"target": "10.0.0.1", "ports": "80", "rate": 50_000},
        )
        assert merged["rate"] == 8000
        assert merged["_masscan_rate_cap"] == 8000

    def test_engagement_clamps_to_default_max_above_library_cap(self) -> None:
        from dixie.constants import DEFAULT_MASSCAN_MAX_RATE

        config = EngagementConfig(target="192.168.1.1")
        agent = Agent(config=config, llm=MagicMock(), tools=build_default_registry(), sandbox=MagicMock())
        merged = agent._merge_engagement_tool_defaults(
            "masscan",
            {"target": "10.0.0.1", "ports": "80", "rate": DEFAULT_MASSCAN_MAX_RATE * 2},
        )
        assert merged["rate"] == DEFAULT_MASSCAN_MAX_RATE
        assert merged["_masscan_rate_cap"] == DEFAULT_MASSCAN_MAX_RATE


class TestBuildCommandRequiredArgs:
    """Review #301 (BLOCKER): empty/partial tool JSON must not KeyError in build_command.

    The model can emit a tool call whose arguments parse to a valid JSON object
    that is missing a required parameter (e.g. ``{}`` for nmap, which needs
    ``target``). Previously ``Tool.build_command`` did ``kwargs["target"]`` and
    raised an uncaught ``KeyError`` that crashed the engagement loop. The agent
    must instead return a structured error the LLM can recover from.
    """

    def test_missing_required_param_reported_by_schema(self) -> None:
        from dixie.tools.nmap import NmapTool

        tool = NmapTool()
        assert tool.name == "nmap_scan"
        assert tool.missing_required_parameters({}) == ["target"]
        assert tool.validate_arguments({}) is not None
        assert "target" in tool.validate_arguments({})
        # A satisfied required param validates clean.
        assert tool.validate_arguments({"target": "10.0.0.1"}) is None

    def test_execute_tool_empty_args_returns_error_not_keyerror(self) -> None:
        config = EngagementConfig(target="192.168.1.1")
        sandbox = MagicMock()
        agent = Agent(
            config=config,
            llm=MagicMock(),
            tools=build_default_registry(),
            sandbox=sandbox,
        )

        # Empty JSON object for a required-param tool must NOT raise.
        result_str = agent._execute_tool("nmap_scan", {})
        payload = json.loads(result_str)
        assert "error" in payload
        assert "target" in payload["error"]
        # The loop must never have reached command execution.
        sandbox.run_command.assert_not_called()
        sandbox.run_local.assert_not_called()

    def test_execute_tool_valid_args_still_builds(self) -> None:
        config = EngagementConfig(target="192.168.1.1")
        sandbox = MagicMock()
        sandbox.run_local.return_value = ToolResult(
            tool="nmap_scan", command="nmap 10.0.0.1", success=True, raw_output="", error=None
        )
        agent = Agent(
            config=config,
            llm=MagicMock(),
            tools=build_default_registry(),
            sandbox=sandbox,
        )
        # Force the non-docker path deterministically (ensure_image() on a
        # MagicMock returns a truthy mock otherwise).
        agent.use_docker = False
        result_str = agent._execute_tool("nmap_scan", {"target": "10.0.0.1"})
        json.loads(result_str)  # valid JSON, no crash
        assert sandbox.run_local.called
        sandbox.run_command.assert_not_called()


class TestScriptSftRemoteRegion:
    def test_script_requires_dixie_sft_aws_region(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "scripts" / "dixie_sft_remote.sh").read_text(encoding="utf-8")
        assert ': "${DIXIE_SFT_AWS_REGION:?' in text
        assert "REGION=\"${DIXIE_SFT_AWS_REGION:-us-east-1" not in text


class TestAgentToolRetries:
    """Review: blind identical-command retries on deterministic failures."""

    def test_repeated_identical_failure_does_not_max_out_retries(self) -> None:
        config = EngagementConfig(
            target="192.168.1.1",
            agent=AgentConfig(max_tool_retries=3),
        )
        tools = build_default_registry()
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        fail = ToolResult(
            tool="masscan",
            command="masscan --output-format json",
            success=False,
            raw_output="",
            error="usage: masscan needs root",
        )
        sandbox.run_local.return_value = fail

        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=sandbox)
        with patch("dixie.core.agent.time.sleep"):
            agent._execute_tool(
                "masscan",
                {"target": "10.0.0.1", "ports": "80", "rate": 1000},
            )
        assert sandbox.run_local.call_count <= 2

    def test_identical_transient_error_exhausts_retry_budget(self) -> None:
        config = EngagementConfig(
            target="192.168.1.1",
            agent=AgentConfig(max_tool_retries=3),
        )
        tools = build_default_registry()
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        fail = ToolResult(
            tool="masscan",
            command="masscan",
            success=False,
            raw_output="",
            error="connection timed out",
        )
        sandbox.run_local.return_value = fail

        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=sandbox)
        with patch("dixie.core.agent.time.sleep"):
            agent._execute_tool(
                "masscan",
                {"target": "10.0.0.1", "ports": "80", "rate": 1000},
            )
        assert sandbox.run_local.call_count == 4


class TestRedditEnvIntParsing:
    def test_invalid_min_score_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DIXIE_INTEL_REDDIT_MIN_SCORE", "not-an-int")
        collector = RedditCollector()
        assert collector.min_score == 2


class TestPipelineExploitDbEnv:
    def test_invalid_exploitdb_max_env_does_not_abort_build_collectors(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DIXIE_INTEL_EXPLOITDB_MAX", "oops")
        collectors = build_collectors(tier=2)
        assert any(getattr(c, "name", "") == "Exploit-DB" for c in collectors)


class TestPipelineEipEnv:
    def test_eip_max_pages_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DIXIE_INTEL_EIP_MAX_PAGES", "11")
        collectors = build_collectors(tier=1)
        eip = next(
            c for c in collectors if c.name == "Exploit Intelligence Platform"
        )
        assert eip.max_pages == 11

    def test_invalid_eip_max_pages_env_falls_back(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DIXIE_INTEL_EIP_MAX_PAGES", "nope")
        collectors = build_collectors(tier=1)
        eip = next(
            c for c in collectors if c.name == "Exploit Intelligence Platform"
        )
        assert eip.max_pages == 50


class TestPipelineNvdEnv:
    def test_nvd_caps_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DIXIE_INTEL_NVD_MAX_API_PAGES", "9")
        monkeypatch.setenv("DIXIE_INTEL_NVD_MAX_ENTRIES", "1234")
        collectors = build_collectors(tier=1)
        nvd = next(c for c in collectors if c.name == "NVD CVE API")
        assert nvd.max_api_pages == 9
        assert nvd.max_entries == 1234

    def test_invalid_nvd_cap_env_falls_back(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DIXIE_INTEL_NVD_MAX_API_PAGES", "x")
        monkeypatch.setenv("DIXIE_INTEL_NVD_MAX_ENTRIES", "y")
        collectors = build_collectors(tier=1)
        nvd = next(c for c in collectors if c.name == "NVD CVE API")
        assert nvd.max_api_pages == 500
        assert nvd.max_entries == 100_000


class TestTranslateLimitEnv:
    def test_invalid_translate_limit_env_does_not_raise(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("DIXIE_INTEL_TRANSLATE_LIMIT", "not-int")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-placeholder")
        store_path = tmp_path / "intel.db"
        store = IntelStore(store_path)
        try:
            n = translate_pending(store, limit=None)
            assert isinstance(n, int)
        finally:
            store.close()


class TestExploitIntelPublishedAtRegression:
    """CVE publish dates: only rows with a parseable in-window timestamp are ingested."""

    def test_parse_iso_none_for_missing_and_invalid(self) -> None:
        assert _parse_iso(None) is None
        assert _parse_iso("") is None
        assert _parse_iso("not-a-date") is None

    def test_fetch_skips_item_when_cve_published_at_missing(self) -> None:
        def _fake_get(*_a, **_kw):
            class _Resp:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    return {
                        "items": [{
                            "cve_id": "CVE-2099-1",
                            "title": "x",
                            "cve_published_at": None,
                        }],
                    }

            return _Resp()

        with patch("dixie.intel.collectors.exploit_intel.httpx.get", _fake_get):
            entries = ExploitIntelCollector(days_back=7).fetch()
        assert entries == []

    def test_fetch_logs_count_when_skipping_missing_publish_date(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        def _fake_get(*_a, **_kw):
            class _Resp:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    return {
                        "items": [{
                            "cve_id": "CVE-2099-1",
                            "title": "x",
                            "cve_published_at": None,
                        }],
                    }

            return _Resp()

        with caplog.at_level(logging.INFO):
            with patch("dixie.intel.collectors.exploit_intel.httpx.get", _fake_get):
                ExploitIntelCollector(days_back=7).fetch()
        assert any(
            "EIP fetch skipped 1 row" in rec.message for rec in caplog.records
        )

    def test_fetch_skips_unparseable_publish_date(self) -> None:
        def _fake_get(*_a, **_kw):
            class _Resp:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    return {
                        "items": [{
                            "cve_id": "CVE-2099-2",
                            "title": "x",
                            "cve_published_at": "not-a-date",
                        }],
                    }

            return _Resp()

        with patch("dixie.intel.collectors.exploit_intel.httpx.get", _fake_get):
            entries = ExploitIntelCollector(days_back=7).fetch()
        assert entries == []

    def test_fetch_excludes_stale_cve_by_published_at(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")

        def _fake_get(*_a, **_kw):
            class _Resp:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    return {
                        "items": [{
                            "cve_id": "CVE-2099-3",
                            "title": "x",
                            "cve_published_at": old,
                        }],
                    }

            return _Resp()

        with patch("dixie.intel.collectors.exploit_intel.httpx.get", _fake_get):
            entries = ExploitIntelCollector(days_back=7).fetch()
        assert entries == []


class TestExploitIntelPaginationContract:
    def test_fetch_sends_page_and_per_page_params(self) -> None:
        captured: list[dict[str, object]] = []

        def fake_get(_url: str, params: dict | None = None, **_kw: object):
            captured.append(dict(params or {}))

            class _Resp:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    return {"items": []}

            return _Resp()

        with patch("dixie.intel.collectors.exploit_intel.httpx.get", fake_get):
            ExploitIntelCollector(days_back=7, max_pages=1).fetch()

        assert captured
        assert captured[0].get("page") == 1
        assert captured[0].get("per_page") == 100


class TestExploitIntelPaginationCap:
    def test_logs_when_max_pages_reached_with_full_pages(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        now = datetime.now(timezone.utc)
        pub = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")

        def make_items() -> list[dict]:
            return [
                {
                    "cve_id": f"CVE-2099-{i}",
                    "title": "t",
                    "cve_published_at": pub,
                }
                for i in range(100)
            ]

        def _fake_get(_url: str, params: dict | None = None, **_kw: object):
            p = (params or {}).get("page", 1)

            class _Resp:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    if p <= 2:
                        return {"items": make_items()}
                    return {"items": []}

            return _Resp()

        with caplog.at_level(logging.WARNING):
            with patch("dixie.intel.collectors.exploit_intel.httpx.get", _fake_get):
                ExploitIntelCollector(days_back=7, max_pages=2).fetch()
        assert "pagination safety cap" in caplog.text


class TestLLMCompletionErrors:
    """Review3: provider vs unexpected LiteLLM failures."""

    def test_api_error_pops_user_and_returns_error(self) -> None:
        from litellm.exceptions import AuthenticationError

        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)
        before = len(client.messages)
        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.side_effect = AuthenticationError(
                "invalid key",
                llm_provider="openai",
                model="gpt-4o",
            )
            out = client.chat("hello")
        assert out["content"] is None
        assert out["tool_calls"] == []
        assert "error" in out and "AuthenticationError" in (out["error"] or "")
        assert len(client.messages) == before

    def test_non_api_exception_still_returns_error_payload(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)
        before = len(client.messages)
        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.side_effect = RuntimeError("broken")
            out = client.chat("hello")
        assert out.get("error") and "RuntimeError" in out["error"]
        assert len(client.messages) == before


class TestDumpToolCallForMessage:
    def test_missing_function_attr_returns_stub(self, caplog: pytest.LogCaptureFixture) -> None:
        from dixie.models.llm import _dump_tool_call_for_message

        tc = SimpleNamespace(id="stub-id", type="function")
        with caplog.at_level(logging.WARNING):
            d = _dump_tool_call_for_message(tc)
        assert d["id"] == "stub-id"
        assert d["function"]["name"] == "unknown"
        assert d["function"]["arguments"] == "{}"


class TestLLMEmptyChoices:
    def test_empty_completion_choices_returns_error(self) -> None:
        tool_reg = ToolRegistry()
        tool_reg.register(NiktoTool())
        client = LLMClient(LLMConfig(), tool_reg)
        before = len(client.messages)
        with patch("dixie.models.llm.litellm") as litellm_mock:
            litellm_mock.completion.return_value = SimpleNamespace(choices=[], usage=None)
            out = client.chat("hello")
        assert out.get("error") == "empty choices from provider"
        assert len(client.messages) == before


class TestNvdTotalResultsParsing:
    def test_non_numeric_total_results_does_not_crash_fetch(self) -> None:
        class _Resp:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"vulnerabilities": [], "totalResults": None}

        with patch("dixie.intel.collectors.nvd.httpx.get", return_value=_Resp()):
            entries = NvdCollector(api_key=None, days_back=1).fetch()
        assert entries == []


class TestAgentToolJsonErrorTermination:
    def test_run_stops_with_reason_when_model_tool_json_invalid(self) -> None:
        config = EngagementConfig(
            target="127.0.0.1",
            agent=AgentConfig(max_iterations=5),
        )
        llm = MagicMock()
        llm.total_tokens = 0
        llm.total_cost = 0.0
        llm.chat.return_value = {
            "content": "thinking",
            "tool_calls": [],
            "tool_json_error": "Model emitted tool calls but none had valid JSON object arguments.",
        }
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        agent = Agent(config=config, llm=llm, tools=build_default_registry(), sandbox=sandbox)
        state = agent.run()
        assert state.termination_reason and "llm_tool_json_error" in state.termination_reason


class TestAgentExecuteToolNoAssertInvariant:
    """Review: library code should not rely on assert for control flow."""

    def test_failed_tool_returns_json_without_assertion_error(self) -> None:
        config = EngagementConfig(
            target="127.0.0.1",
            agent=AgentConfig(max_tool_retries=0),
        )
        tools = build_default_registry()
        sandbox = MagicMock()
        sandbox.ensure_image.return_value = False
        sandbox.run_local.return_value = ToolResult(
            tool="nmap_scan",
            command="nmap -sS --top-ports 1000 127.0.0.1",
            success=False,
            raw_output="",
            error="failed",
        )
        agent = Agent(config=config, llm=MagicMock(), tools=tools, sandbox=sandbox)
        body = agent._execute_tool(
            "nmap_scan",
            {"target": "127.0.0.1", "scan_type": "syn"},
        )
        assert "error" in body

    def test_execute_tool_does_not_use_assert_for_result_invariant(self) -> None:
        src = inspect.getsource(agent_module.Agent._execute_tool)
        assert "assert result is not None" not in src
