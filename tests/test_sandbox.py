"""Tests for Docker sandbox tool execution (timeout, exit codes)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from requests.exceptions import ReadTimeout

from dixie.core.config import SandboxConfig
from dixie.core.sandbox import Sandbox


def _make_sandbox_with_mock_container(mock_container: MagicMock, **cfg_kw) -> Sandbox:
    cfg = SandboxConfig(timeout=cfg_kw.pop("timeout", 300), **cfg_kw)
    sb = Sandbox(cfg)
    sb.client = MagicMock()
    sb.client.containers.run.return_value = mock_container
    return sb


class TestSandboxRunCommand:
    def test_success_zero_exit(self) -> None:
        container = MagicMock()
        container.wait.return_value = {"StatusCode": 0}
        container.logs.return_value = b"stdout here\n"
        sb = _make_sandbox_with_mock_container(container, timeout=120)

        result = sb.run_command(["echo", "hi"], "test_tool")

        assert result.success
        assert result.error is None
        assert "stdout here" in result.raw_output
        assert result.tool == "test_tool"
        sb.client.containers.run.assert_called_once()
        call_kw = sb.client.containers.run.call_args.kwargs
        assert call_kw["detach"] is True
        assert call_kw["remove"] is False
        container.wait.assert_called_once_with(timeout=120)
        container.remove.assert_called_once_with(force=True)

    def test_nonzero_exit(self) -> None:
        container = MagicMock()
        container.wait.return_value = {"StatusCode": 2}
        container.logs.return_value = b"err on stderr"
        sb = _make_sandbox_with_mock_container(container)

        result = sb.run_command(["false"], "test_tool")

        assert not result.success
        assert result.error == "exit code 2"
        assert result.raw_output == "err on stderr"
        container.remove.assert_called_once_with(force=True)

    def test_wait_timeout_kills_and_removes(self) -> None:
        container = MagicMock()
        container.wait.side_effect = ReadTimeout("timed out")
        sb = _make_sandbox_with_mock_container(container, timeout=45)

        result = sb.run_command(["sleep", "999"], "test_tool")

        assert not result.success
        assert result.error == "Timeout after 45s"
        container.kill.assert_called_once()
        container.remove.assert_called_once_with(force=True)
