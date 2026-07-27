#!/usr/bin/env bash
# Bounded single-H100 Qwen3-Coder MoE LoRA throughput pilot.
set -Eeuo pipefail
: "${RUN_ID:?RUN_ID is required}"
: "${PREFIX:?PREFIX is required}"
: "${TRAIN_S3:?TRAIN_S3 is required}"

WORK=/opt/dixie-qwen-pilot
LOG_DIR=/var/log/dixie-qwen-pilot
mkdir -p "$WORK" "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/run.log") 2>&1

CLEANED=0
TELEMETRY_PID=""
cleanup() {
  local rc=$?
  if [[ "$CLEANED" == 1 ]]; then return; fi
  CLEANED=1
  set +e
  [[ -z "$TELEMETRY_PID" ]] || kill "$TELEMETRY_PID" 2>/dev/null || true
  printf '%s\n' "$rc" > "$LOG_DIR/exit-code.txt"
  date -u +%FT%TZ > "$LOG_DIR/finished_at.txt"
  nvidia-smi > "$LOG_DIR/nvidia-smi-final.txt" 2>&1
  aws s3 cp "$WORK/output" "$PREFIX/output" --recursive --only-show-errors || true
  aws s3 cp "$LOG_DIR" "$PREFIX/logs" --recursive --only-show-errors || true
  sync
  /sbin/shutdown -h now || true
}
trap cleanup EXIT INT TERM

phase() {
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" | tee "$LOG_DIR/phase.txt"
  aws s3 cp "$LOG_DIR/phase.txt" "$PREFIX/logs/phase.txt" --only-show-errors || true
}

phase start
date -u +%FT%TZ > "$LOG_DIR/started_at.txt"
nvidia-smi > "$LOG_DIR/nvidia-smi-start.txt"
nvidia-smi --query-gpu=timestamp,index,name,memory.used,memory.total,utilization.gpu,power.draw \
  --format=csv -l 5 > "$LOG_DIR/gpu-telemetry.csv" 2>&1 &
TELEMETRY_PID=$!

cd "$WORK"
phase source-and-data
aws s3 cp "$PREFIX/source.tar.gz" source.tar.gz --only-show-errors
tar -xzf source.tar.gz
mkdir -p data/dixie_pentest output
aws s3 cp "$TRAIN_S3" data/dixie_pentest/train.jsonl --only-show-errors
wc -l data/dixie_pentest/train.jsonl

phase dependencies
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl jq ninja-build build-essential git
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
uv python install 3.12
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python --torch-backend=cu128 "unsloth==2026.7.5"
uv pip freeze --python .venv/bin/python > "$LOG_DIR/pip-freeze.txt"
.venv/bin/python - <<'PY'
import torch, transformers, trl, unsloth
print("torch", torch.__version__, "cuda", torch.version.cuda)
print("transformers", transformers.__version__, "trl", trl.__version__)
print("unsloth", getattr(unsloth, "__version__", "unknown"))
print("gpu", torch.cuda.get_device_name(0), "bf16", torch.cuda.is_bf16_supported())
assert torch.cuda.is_available() and torch.cuda.is_bf16_supported()
PY

phase training
export HF_HOME="$WORK/hf-cache"
export TOKENIZERS_PARALLELISM=true
export UNSLOTH_MOE_BACKEND=grouped_mm
export PYTHONUNBUFFERED=1
.venv/bin/python scripts/train_qwen3_coder_lora_pilot.py \
  --train data/dixie_pentest/train.jsonl \
  --output-dir output/qwen3-coder-lora-pilot \
  --max-seq-length 4096 \
  --max-steps 200 \
  --pilot-samples 25000 \
  --grad-accum 8 \
  --lora-rank 16 \
  --learning-rate 2e-5 \
  --seed 3407

phase complete
