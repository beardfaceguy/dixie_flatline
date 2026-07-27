#!/usr/bin/env python3
"""Bounded Qwen3-Coder 30B-A3B LoRA throughput pilot.

This is intentionally a pilot, not the full production run. It trains bf16 LoRA
adapters for a fixed number of optimizer steps and emits timing/GPU metrics used
to project the one-epoch run. QLoRA is deliberately not used because current
BitsAndBytes MoE parameters do not support reliable 4-bit training.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        default="Qwen/Qwen3-Coder-30B-A3B-Instruct",
    )
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-seq-length", type=int, default=4096)
    parser.add_argument("--max-steps", type=int, default=200)
    parser.add_argument("--pilot-samples", type=int, default=25_000)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--seed", type=int, default=3407)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    for name in ("max_seq_length", "max_steps", "pilot_samples", "grad_accum", "lora_rank"):
        if getattr(args, name) < 1:
            raise ValueError(f"--{name.replace('_', '-')} must be positive")
    if args.learning_rate <= 0:
        raise ValueError("--learning-rate must be positive")
    if not args.train.is_file():
        raise FileNotFoundError(args.train)


def format_conversations(tokenizer: Any, batch: dict[str, list[Any]]) -> dict[str, list[str]]:
    """Render HF Messages rows with the model's exact chat template."""
    return {
        "text": tokenizer.apply_chat_template(
            batch["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
    }


def main() -> None:
    args = parse_args()
    validate_args(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = args.output_dir / "pilot_metrics.jsonl"
    summary_path = args.output_dir / "pilot_summary.json"

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "true")
    os.environ.setdefault("UNSLOTH_MOE_BACKEND", "grouped_mm")

    import torch
    from datasets import load_dataset
    from transformers import TrainerCallback
    from trl import SFTConfig, SFTTrainer
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import train_on_responses_only

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for this pilot")
    if not torch.cuda.is_bf16_supported():
        raise RuntimeError("bf16-capable GPU is required")

    torch.backends.cuda.matmul.allow_tf32 = True
    torch.set_float32_matmul_precision("high")
    started = time.perf_counter()
    device_name = torch.cuda.get_device_name(0)
    total_vram = torch.cuda.get_device_properties(0).total_memory

    print(
        json.dumps(
            {
                "event": "pilot_start",
                "model": args.model,
                "device": device_name,
                "vram_gib": total_vram / 2**30,
                "max_seq_length": args.max_seq_length,
                "max_steps": args.max_steps,
                "gradient_accumulation": args.grad_accum,
                "lora_rank": args.lora_rank,
                "learning_rate": args.learning_rate,
            }
        ),
        flush=True,
    )

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq_length,
        load_in_4bit=False,
        fast_inference=False,
        dtype=torch.bfloat16,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_rank,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
            "gate_up_proj",
        ],
        lora_alpha=args.lora_rank * 2,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=args.seed,
    )
    model.print_trainable_parameters()

    raw = load_dataset("json", data_files=str(args.train), split="train")
    sample_count = min(args.pilot_samples, len(raw))
    dataset = raw.shuffle(seed=args.seed).select(range(sample_count))
    dataset = dataset.map(
        lambda batch: format_conversations(tokenizer, batch),
        batched=True,
        batch_size=512,
        num_proc=min(8, os.cpu_count() or 1),
        remove_columns=dataset.column_names,
        desc="Rendering Qwen chat template",
    )

    class MetricsCallback(TrainerCallback):
        def __init__(self) -> None:
            self.started = time.perf_counter()

        def on_log(self, args_, state, control, logs=None, **kwargs):  # type: ignore[no-untyped-def]
            del args_, control, kwargs
            payload = dict(logs or {})
            elapsed = time.perf_counter() - self.started
            payload.update(
                {
                    "step": state.global_step,
                    "elapsed_seconds": elapsed,
                    "estimated_tokens_seen": (
                        state.global_step
                        * args.max_seq_length
                        * args.grad_accum
                    ),
                    "tokens_per_second": (
                        state.global_step
                        * args.max_seq_length
                        * args.grad_accum
                        / elapsed
                        if elapsed
                        else 0.0
                    ),
                    "gpu_allocated_gib": torch.cuda.max_memory_allocated() / 2**30,
                    "gpu_reserved_gib": torch.cuda.max_memory_reserved() / 2**30,
                }
            )
            with metrics_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            output_dir=str(args.output_dir / "trainer"),
            dataset_text_field="text",
            max_length=args.max_seq_length,
            packing=True,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=args.grad_accum,
            max_steps=args.max_steps,
            warmup_steps=min(10, max(1, args.max_steps // 20)),
            learning_rate=args.learning_rate,
            logging_steps=1,
            optim="adamw_8bit",
            weight_decay=0.001,
            lr_scheduler_type="cosine",
            seed=args.seed,
            bf16=True,
            fp16=False,
            report_to="none",
            save_strategy="no",
            dataloader_num_workers=4,
            dataset_num_proc=min(8, os.cpu_count() or 1),
        ),
        callbacks=[MetricsCallback()],
    )
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )

    first_batch = next(iter(trainer.get_train_dataloader()))
    supervised_tokens = int((first_batch["labels"] != -100).sum().item())
    if supervised_tokens == 0:
        raise RuntimeError("response-only masking produced zero supervised tokens")
    print(f"preflight supervised_tokens_in_first_batch={supervised_tokens}", flush=True)
    torch.cuda.reset_peak_memory_stats()

    train_result = trainer.train()
    elapsed = time.perf_counter() - started
    adapter_dir = args.output_dir / "adapter"
    trainer.model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)

    tokens_seen = args.max_steps * args.max_seq_length * args.grad_accum
    summary = {
        "model": args.model,
        "device": device_name,
        "vram_gib": total_vram / 2**30,
        "max_seq_length": args.max_seq_length,
        "max_steps": args.max_steps,
        "gradient_accumulation": args.grad_accum,
        "effective_tokens_per_step": args.max_seq_length * args.grad_accum,
        "estimated_tokens_seen": tokens_seen,
        "elapsed_seconds_total": elapsed,
        "tokens_per_second_overall": tokens_seen / elapsed,
        "train_runtime_seconds": train_result.metrics.get("train_runtime"),
        "train_samples_per_second": train_result.metrics.get("train_samples_per_second"),
        "train_steps_per_second": train_result.metrics.get("train_steps_per_second"),
        "train_loss": train_result.metrics.get("train_loss"),
        "peak_gpu_allocated_gib": torch.cuda.max_memory_allocated() / 2**30,
        "peak_gpu_reserved_gib": torch.cuda.max_memory_reserved() / 2**30,
        "pilot_samples": sample_count,
        "supervised_tokens_in_first_batch": supervised_tokens,
        "lora_rank": args.lora_rank,
        "learning_rate": args.learning_rate,
        "seed": args.seed,
        "adapter_dir": str(adapter_dir),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"event": "pilot_complete", **summary}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
