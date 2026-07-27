"""Tests for the exact SFT token analysis helpers."""

from __future__ import annotations

import gzip
import json

import pytest

from scripts.analyze_sft_tokens import analyze_file, packing_stats, percentile


class FakeTokenizer:
    def apply_chat_template(self, conversations, **kwargs):
        del kwargs
        return {
            "input_ids": [
                list(range(sum(len(message["content"]) for message in conversation)))
                for conversation in conversations
            ]
        }


def test_percentile_uses_nearest_rank() -> None:
    values = [1, 2, 3, 4, 5]
    assert percentile(values, 50) == 3
    assert percentile(values, 99) == 5
    assert percentile([], 50) == 0


def test_packing_stats_track_truncation_and_steps() -> None:
    stats = packing_stats([1000, 1200, 3000], context=2048)
    assert stats["packed_sequences"] == 3
    assert stats["retained_tokens"] == 4248
    assert stats["truncated_samples"] == 1
    assert stats["truncated_tokens"] == 952
    assert stats["packing_efficiency"] == pytest.approx(4248 / (3 * 2048))
    assert stats["optimizer_steps_by_effective_sequence_batch"]["8"] == 1


def test_analyze_file_caches_lengths_and_reports_invalid_lines(tmp_path) -> None:
    source = tmp_path / "train.jsonl"
    source.write_text(
        "\n".join(
            [
                json.dumps({"messages": [{"role": "user", "content": "abcd"}]}),
                json.dumps(
                    {
                        "messages": [
                            {"role": "user", "content": "abc"},
                            {"role": "assistant", "content": "de"},
                        ]
                    }
                ),
                "not-json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    output.mkdir()

    result = analyze_file(source, FakeTokenizer(), batch_size=2, output_dir=output)

    assert result["samples"] == 2
    assert result["tokens"] == 9
    assert result["invalid_lines"] == 1
    assert len(result["sha256"]) == 64
    with gzip.open(result["length_cache"], "rt", encoding="utf-8") as handle:
        assert json.load(handle) == [4, 5]
