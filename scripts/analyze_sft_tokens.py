#!/usr/bin/env python3
"""Analyze HF Messages JSONL with the exact production tokenizer.

Produces a compact gzip-compressed per-sample length cache plus a JSON summary.
No model weights or GPU are required.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
import statistics
import time
from pathlib import Path
from typing import Any

from transformers import AutoTokenizer

DEFAULT_CONTEXTS = (2048, 4096, 8192, 16384)


def percentile(sorted_values: list[int], percent: float) -> int:
    if not sorted_values:
        return 0
    index = math.ceil((percent / 100) * len(sorted_values)) - 1
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


def packing_stats(lengths: list[int], context: int) -> dict[str, Any]:
    """Estimate sequential greedy packing after clipping over-length samples."""
    bins = 0
    used_in_bin = 0
    retained_tokens = 0
    truncated_tokens = 0
    truncated_samples = 0

    for original in lengths:
        length = min(original, context)
        retained_tokens += length
        if original > context:
            truncated_samples += 1
            truncated_tokens += original - context
        if used_in_bin and used_in_bin + length > context:
            bins += 1
            used_in_bin = 0
        used_in_bin += length
        if used_in_bin == context:
            bins += 1
            used_in_bin = 0
    if used_in_bin:
        bins += 1

    capacity = bins * context
    return {
        "context_length": context,
        "packed_sequences": bins,
        "packing_efficiency": retained_tokens / capacity if capacity else 0.0,
        "retained_tokens": retained_tokens,
        "truncated_samples": truncated_samples,
        "truncated_sample_rate": truncated_samples / len(lengths) if lengths else 0.0,
        "truncated_tokens": truncated_tokens,
        "token_retention_rate": (
            retained_tokens / (retained_tokens + truncated_tokens)
            if retained_tokens + truncated_tokens
            else 0.0
        ),
        "optimizer_steps_by_effective_sequence_batch": {
            str(batch): math.ceil(bins / batch) for batch in (8, 16, 32, 64)
        },
    }


def summarize(lengths: list[int], elapsed: float, digest: str) -> dict[str, Any]:
    ordered = sorted(lengths)
    total = sum(lengths)
    return {
        "samples": len(lengths),
        "tokens": total,
        "mean_tokens": statistics.fmean(lengths) if lengths else 0.0,
        "median_tokens": statistics.median(lengths) if lengths else 0.0,
        "min_tokens": ordered[0] if ordered else 0,
        "max_tokens": ordered[-1] if ordered else 0,
        "percentiles": {
            f"p{percent}": percentile(ordered, percent)
            for percent in (50, 75, 90, 95, 99, 99.5, 99.9)
        },
        "elapsed_seconds": elapsed,
        "samples_per_second": len(lengths) / elapsed if elapsed else 0.0,
        "tokens_per_second": total / elapsed if elapsed else 0.0,
        "sha256": digest,
        "packing": [packing_stats(lengths, context) for context in DEFAULT_CONTEXTS],
    }


def analyze_file(
    path: Path,
    tokenizer: Any,
    batch_size: int,
    output_dir: Path,
) -> dict[str, Any]:
    started = time.perf_counter()
    lengths: list[int] = []
    conversations: list[list[dict[str, Any]]] = []
    digest = hashlib.sha256()
    invalid_lines = 0
    processed = 0

    def flush() -> None:
        nonlocal conversations
        if not conversations:
            return
        encoded = tokenizer.apply_chat_template(
            conversations,
            tokenize=True,
            add_generation_prompt=False,
            padding=False,
            truncation=False,
        )
        lengths.extend(len(ids) for ids in encoded["input_ids"])
        conversations = []

    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            digest.update(raw_line)
            try:
                row = json.loads(raw_line)
                messages = row["messages"]
                if not isinstance(messages, list) or not messages:
                    raise ValueError("messages must be a non-empty list")
                conversations.append(messages)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                invalid_lines += 1
                continue
            if len(conversations) >= batch_size:
                flush()
            processed += 1
            if processed % 25_000 == 0:
                elapsed = time.perf_counter() - started
                rate = processed / elapsed if elapsed else 0
                print(
                    f"[{path.name}] {processed:,} samples; {rate:,.0f} samples/s; "
                    f"elapsed={elapsed / 60:.1f}m",
                    flush=True,
                )
    flush()

    elapsed = time.perf_counter() - started
    summary = summarize(lengths, elapsed, digest.hexdigest())
    summary.update(
        {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "invalid_lines": invalid_lines,
        }
    )

    cache_path = output_dir / f"{path.stem}.qwen3_coder.lengths.json.gz"
    with gzip.open(cache_path, "wt", encoding="utf-8", compresslevel=6) as handle:
        json.dump(lengths, handle, separators=(",", ":"))
    summary["length_cache"] = str(cache_path)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        default="Qwen/Qwen3-Coder-30B-A3B-Instruct",
        help="Tokenizer repository id",
    )
    parser.add_argument(
        "--input",
        action="append",
        type=Path,
        required=True,
        help="HF Messages JSONL file (repeatable)",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=512)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.batch_size < 1:
        raise ValueError("--batch-size must be positive")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "true")

    overall_started = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)
    results = [
        analyze_file(path, tokenizer, args.batch_size, args.output_dir)
        for path in args.input
    ]

    combined_lengths: list[int] = []
    for result in results:
        with gzip.open(result["length_cache"], "rt", encoding="utf-8") as handle:
            combined_lengths.extend(json.load(handle))
    combined = summarize(
        combined_lengths,
        time.perf_counter() - overall_started,
        digest="",
    )
    combined.pop("sha256", None)

    report = {
        "model": args.model,
        "tokenizer_class": type(tokenizer).__name__,
        "is_fast": tokenizer.is_fast,
        "chat_template_applied": True,
        "add_generation_prompt": False,
        "batch_size": args.batch_size,
        "splits": results,
        "combined": combined,
    }
    report_path = args.output_dir / "qwen3_coder_token_analysis.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report written to {report_path}")
    print(
        f"Combined: {combined['samples']:,} samples, {combined['tokens']:,} tokens, "
        f"mean={combined['mean_tokens']:.1f}, p95={combined['percentiles']['p95']}, "
        f"max={combined['max_tokens']}, elapsed={combined['elapsed_seconds'] / 60:.1f}m"
    )


if __name__ == "__main__":
    main()
