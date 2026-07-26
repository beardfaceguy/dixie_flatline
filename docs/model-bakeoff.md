# Dixie Phase 0 model bakeoff

This harness compares model endpoints through Dixie's real LiteLLM client and tool
schemas before any fine-tuning spend. The default suite uses documentation-only
TEST-NET addresses and scripted tool observations. It **does not execute scanners**
or contact the targets.

Canonical tracking: Vikunja Phase 1 task **#45** (id `1080`).  
Decision record: Phase 1 task **#44** (id `1079`).

## What is measured

Each response is retained in `bakeoff.json` and scored with deterministic checks:

- provider/API success
- parseable tool-call JSON
- registered tool names
- required tool arguments
- expected tool selection
- expected argument values
- expected response content
- multi-turn behavior after scripted tool observations/errors

The Markdown report ranks candidates by passed checks, then elapsed time. This is
not a claim of general model quality: only encoded checks contribute to the score.
Run multiple repetitions before using the ranking as a model-selection decision.

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

The manifest is `configs/model_bakeoff.yaml`. Operational model IDs and endpoint
locations live there or in environment variables—never in library code.

## Run against an OpenAI-compatible endpoint

Start one candidate endpoint (for example, vLLM) and expose `/v1`. vLLM model
flags and tool parsers change across releases, so use the candidate's official
model card and your installed vLLM documentation rather than copying an old
launch command blindly.

For a Qwen endpoint listening locally:

```bash
export OPENAI_API_KEY=EMPTY
export DIXIE_BAKEOFF_QWEN_API_BASE=http://127.0.0.1:8000/v1

dixie bakeoff configs/model_bakeoff.yaml \
  --candidate qwen3-coder-30b \
  --output-dir output/bakeoff/qwen3-coder-30b
```

Other endpoint variables are listed in the manifest:

- `DIXIE_BAKEOFF_DEVSTRAL_API_BASE`
- `DIXIE_BAKEOFF_GPT_OSS_API_BASE`
- `DIXIE_BAKEOFF_REDSAGE_API_BASE`
- `DIXIE_BAKEOFF_MISTRAL_API_BASE`

Run one candidate at a time when reusing a single GPU server. The model exposed by
the endpoint must match the candidate's configured model name (or be assigned the
same served-model alias).

## Fair-comparison rules

Keep these identical across candidates unless the report explicitly identifies an
ablation:

1. Scenario manifest/version.
2. System prompt and tool schemas.
3. Temperature and token budget.
4. Context limit (initial target: 16K or 32K).
5. Maximum turns and retry policy.
6. Hardware class when comparing throughput.
7. Concurrency and request batch.
8. Number of repetitions and random seeds where supported.

Do not compare a 256K-context run on an H100 against a 16K run on an L4 and call
the result a model-only difference.

## Result files

- `bakeoff.json`: complete machine-readable responses, checks, tokens, cost, and timing.
- `bakeoff.md`: ranking and check failures for human review.

The core score intentionally excludes GPU telemetry because LiteLLM cannot obtain
VRAM utilization from a remote server. Capture server-side telemetry separately
(`nvidia-smi`, vLLM Prometheus metrics, CloudWatch) and join it to the report using
the candidate id and run timestamp.

## AWS execution guardrail

The harness itself does not create cloud resources. Before Stage B:

- choose the candidate and precision
- get explicit approval to launch billable instances
- tag every resource with the bakeoff run id
- configure an automatic shutdown/termination path
- verify endpoint health before starting the timed run
- terminate the instance after artifacts are copied

Recommended initial hardware from the account survey:

- L4 24 GB (`g6.xlarge`): gpt-oss-20b, RedSage 8B, Mistral 7B
- L40S ~48 GB (`g6e.xlarge`/`g6e.2xlarge`): Qwen3-Coder FP8/quantized and Devstral
- H100 80 GB (`p5.4xlarge`): unquantized/high-context fallback and later LoRA/QLoRA

## Extending the suite

Add scenarios to the YAML manifest. A scenario contains one or more turns:

```yaml
- id: example
  category: recovery
  turns:
    - prompt: Use one tool call against the authorized TEST-NET host.
      expected_tools: [nmap_scan]
      expected_arguments:
        target: 192.0.2.10
      tool_results:
        nmap_scan:
          error: usage: invalid option; no scan executed
    - prompt: Correct the failed action without inventing results.
      expected_tools: [nmap_scan]
```

`tool_results` are submitted into the model conversation under the original call
id. They make failure recovery and observation-following testable without running
pentesting binaries.

Keep benchmark scenarios disjoint from fine-tuning data. Version the manifest
whenever prompts, expectations, or scoring semantics change.
