"""Tests for the bounded Qwen LoRA pilot configuration helpers."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
from pathlib import Path

import pytest

from scripts.train_qwen3_coder_lora_pilot import format_conversations, validate_args

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_WORKER = _SCRIPTS / "dixie_qwen_lora_pilot_worker.sh"
_LAUNCHER = _SCRIPTS / "launch_qwen_lora_pilot.sh"


class FakeTokenizer:
    def apply_chat_template(self, conversations, **kwargs):
        assert kwargs == {"tokenize": False, "add_generation_prompt": False}
        return [f"rendered-{index}" for index, _ in enumerate(conversations)]


def _args(tmp_path, **overrides):
    values = {
        "train": tmp_path / "train.jsonl",
        "max_seq_length": 4096,
        "max_steps": 200,
        "pilot_samples": 25_000,
        "grad_accum": 8,
        "lora_rank": 16,
        "learning_rate": 2e-5,
    }
    values.update(overrides)
    values["train"].write_text('{"messages": []}\n', encoding="utf-8")
    return argparse.Namespace(**values)


def test_validate_args_accepts_bounded_pilot(tmp_path) -> None:
    validate_args(_args(tmp_path))


def test_validate_args_rejects_non_positive_values(tmp_path) -> None:
    with pytest.raises(ValueError, match="max-steps"):
        validate_args(_args(tmp_path, max_steps=0))
    with pytest.raises(ValueError, match="learning-rate"):
        validate_args(_args(tmp_path, learning_rate=0))


def test_format_conversations_uses_exact_chat_template() -> None:
    batch = {"messages": [[{"role": "user", "content": "a"}], []]}
    assert format_conversations(FakeTokenizer(), batch) == {
        "text": ["rendered-0", "rendered-1"]
    }


@pytest.mark.parametrize("script", [_WORKER, _LAUNCHER])
def test_pilot_scripts_are_executable(script: Path) -> None:
    # Regression: the worker shipped non-executable, so no launcher could run it.
    assert script.is_file(), script
    assert os.stat(script).st_mode & stat.S_IXUSR, f"{script.name} must be executable"


def test_launcher_enforces_cost_guardrails() -> None:
    # The launcher must never create a box that can outlive its budget: the
    # instance has to self-terminate on OS shutdown and carry a hard time cap.
    text = _LAUNCHER.read_text(encoding="utf-8")
    assert "--instance-initiated-shutdown-behavior terminate" in text
    assert "shutdown -h +" in text
    # It must stage the trainer the worker runs and default to the H100 box.
    assert "train_qwen3_coder_lora_pilot.py" in text
    assert "p5.4xlarge" in text


def test_launcher_rejects_non_numeric_max_hours() -> None:
    # A bad MAX_HOURS would otherwise silently yield `shutdown -h +0` in the
    # user-data time cap; the launcher must reject it before doing anything.
    result = subprocess.run(
        ["bash", str(_LAUNCHER)],
        env={**os.environ, "DIXIE_PILOT_MAX_HOURS": "6h"},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "DIXIE_PILOT_MAX_HOURS" in result.stderr
