#!/usr/bin/env bash
set -Eeuo pipefail
: "${RUN_ID:?RUN_ID is required}"
: "${PREFIX:?PREFIX is required}"

WORK=/opt/dixie-bakeoff
LOG_DIR=/var/log/dixie-bakeoff
VLLM_LOG=/var/log/vllm-qwen.log
mkdir -p "$WORK" "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/run.log") 2>&1

CLEANED=0
TELEMETRY_PID=""
cleanup() {
  local rc=$?
  if [[ "$CLEANED" == 1 ]]; then return; fi
  CLEANED=1
  set +e
  if [[ -n "$TELEMETRY_PID" ]]; then kill "$TELEMETRY_PID" 2>/dev/null || true; fi
  printf '%s\n' "$rc" > "$LOG_DIR/exit-code.txt"
  date -u +%FT%TZ > "$LOG_DIR/finished_at.txt"
  nvidia-smi > "$LOG_DIR/nvidia-smi-final.txt" 2>&1
  aws s3 cp "$WORK/output" "$PREFIX/output" --recursive --only-show-errors || true
  aws s3 cp "$LOG_DIR" "$PREFIX/logs" --recursive --only-show-errors || true
  aws s3 cp "$VLLM_LOG" "$PREFIX/logs/vllm-qwen.log" --only-show-errors || true
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
phase source-download
aws s3 cp "$PREFIX/source.tar.gz" source.tar.gz --only-show-errors
tar -xzf source.tar.gz

phase system-dependencies
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl jq ninja-build build-essential
command -v ninja

phase python-environment
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
uv python install 3.12
uv venv --python 3.12 .venv
uv pip install -e '.[dev]' --python .venv/bin/python
uv pip install -U vllm ninja --python .venv/bin/python
uv pip freeze --python .venv/bin/python > "$LOG_DIR/pip-freeze.txt"
.venv/bin/python -c 'import torch, vllm; print(torch.__version__, vllm.__version__)' 

phase model-server-start
export HF_HOME="$WORK/hf-cache"
export VLLM_CACHE_ROOT="$WORK/vllm-cache"
export PYTHONUNBUFFERED=1
MODEL_WEIGHTS='Qwen/Qwen3-Coder-30B-A3B-Instruct-FP8'
SERVED_MODEL='Qwen/Qwen3-Coder-30B-A3B-Instruct'
nohup .venv/bin/vllm serve "$MODEL_WEIGHTS" \
  --served-model-name "$SERVED_MODEL" \
  --host 127.0.0.1 --port 8000 \
  --max-model-len 16384 \
  --gpu-memory-utilization 0.90 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  > "$VLLM_LOG" 2>&1 &
VLLM_PID=$!
printf '%s\n' "$VLLM_PID" > "$LOG_DIR/vllm.pid"

ready=0
for _ in $(seq 1 270); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null; then ready=1; break; fi
  if ! kill -0 "$VLLM_PID" 2>/dev/null; then
    echo 'vLLM exited before becoming ready' >&2
    tail -200 "$VLLM_LOG" >&2
    exit 1
  fi
  sleep 10
done
[[ "$ready" == 1 ]] || { echo 'vLLM readiness timeout' >&2; exit 1; }
curl -fsS http://127.0.0.1:8000/v1/models | jq . > "$LOG_DIR/models.json"

phase tool-call-smoke
curl -fsS http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d @- > "$LOG_DIR/tool-call-smoke.json" <<JSON
{"model":"$SERVED_MODEL","messages":[{"role":"user","content":"For the explicitly authorized TEST-NET host 192.0.2.10, begin service enumeration with one tool call. Do not invent results."}],"temperature":0.2,"max_tokens":512,"tools":[{"type":"function","function":{"name":"nmap_scan","description":"Enumerate services on an authorized target","parameters":{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}}}]}
JSON
jq -e '.choices[0].message.tool_calls | length > 0' "$LOG_DIR/tool-call-smoke.json"

phase bakeoff
export OPENAI_API_KEY=EMPTY
export DIXIE_BAKEOFF_QWEN_API_BASE=http://127.0.0.1:8000/v1
mkdir -p output
for repetition in 1 2 3; do
  .venv/bin/dixie bakeoff configs/model_bakeoff.yaml \
    --candidate qwen3-coder-30b \
    --output-dir "output/qwen3-coder-30b/run-${repetition}"
done

phase complete
