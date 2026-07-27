"""Tests for the bounded Qwen LoRA pilot configuration helpers."""

from __future__ import annotations

import argparse

import pytest

from scripts.train_qwen3_coder_lora_pilot import format_conversations, validate_args


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
