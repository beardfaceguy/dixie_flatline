#!/bin/bash
#
# Dixie Flatline — remote SFT training driver (EC2 / DLAMI-style host).
#
# All org- and account-specific S3 locations MUST come from the environment.
# Nothing under s3://… is hardcoded in this repo.
#
# ─ Required ─────────────────────────────────────────────────────────────
#   DIXIE_SFT_S3_ROOT
#       S3 prefix for Titan-style layout, without a trailing slash.
#       Example: s3://your-bucket/your-org/titan
#
#   DIXIE_SFT_BASE_CKPT_S3
#       Full S3 URI of the base checkpoint to fine-tune from.
#       Example: s3://your-bucket/.../ckpt_sft_step_5000.pt
#
#   DIXIE_SFT_AWS_REGION
#       AWS region for CLI/S3 access (e.g. us-east-1). No default — must be set explicitly.
#
# ─ Optional overrides (default = under DIXIE_SFT_S3_ROOT) ────────────────
#   DIXIE_SFT_CODE_BUNDLE_S3   (default: ${ROOT}/code_bundles/titanProject_bundle.tar.gz)
#   DIXIE_SFT_TRAIN_S3         (default: ${ROOT}/data/dixie_pentest/train.jsonl)
#   DIXIE_SFT_VAL_S3           (default: ${ROOT}/data/dixie_pentest/val.jsonl)
#   DIXIE_SFT_TOKENIZER_S3     (default: ${ROOT}/tokenizers/new_bpe_50k/bpe_50k_fw_stack.model)
#
#   DIXIE_SFT_CODE_DIR         (default: ${HOME}/wintermute) — extract target for code bundle
#   DIXIE_SFT_DATA_ROOT        (default: /opt/dlami/nvme if mounted, else /mnt/data)
#   STOP_INSTANCE_ON_EXIT      (default: 1) — set 0 to skip EC2 stop
#
set -euo pipefail

: "${DIXIE_SFT_S3_ROOT:?Set DIXIE_SFT_S3_ROOT (e.g. s3://bucket/prefix/titan — no trailing slash)}"
: "${DIXIE_SFT_BASE_CKPT_S3:?Set DIXIE_SFT_BASE_CKPT_S3 to full s3 URI of base .pt checkpoint}"
: "${DIXIE_SFT_AWS_REGION:?Set DIXIE_SFT_AWS_REGION (e.g. us-east-1)}"

ROOT="${DIXIE_SFT_S3_ROOT%/}"

DATA_ROOT="${DIXIE_SFT_DATA_ROOT:-}"
if [[ -z "${DATA_ROOT}" ]]; then
  DATA_ROOT=/opt/dlami/nvme
  if ! mountpoint -q /opt/dlami/nvme 2>/dev/null; then
    DATA_ROOT=/mnt/data
    mkdir -p /mnt/data
  fi
fi

CODE_DIR="${DIXIE_SFT_CODE_DIR:-${HOME}/wintermute}"
REGION="${DIXIE_SFT_AWS_REGION}"
STOP_INSTANCE_ON_EXIT="${STOP_INSTANCE_ON_EXIT:-1}"

RUN_ID="dixie_pentest_sft_$(date +%Y%m%d%H%M%S)"
CKPT_DIR="${DATA_ROOT}/checkpoints/${RUN_ID}"
S3_PREFIX="${ROOT}/checkpoints/${RUN_ID}/"

CODE_BUNDLE_URI="${DIXIE_SFT_CODE_BUNDLE_S3:-${ROOT}/code_bundles/titanProject_bundle.tar.gz}"
CODE_BUNDLE_LOCAL="/tmp/titanProject_bundle.tar.gz"

TRAIN_S3="${DIXIE_SFT_TRAIN_S3:-${ROOT}/data/dixie_pentest/train.jsonl}"
VAL_S3="${DIXIE_SFT_VAL_S3:-${ROOT}/data/dixie_pentest/val.jsonl}"
TRAIN_DATA="${DATA_ROOT}/data/dixie_pentest/train.jsonl"
VAL_DATA="${DATA_ROOT}/data/dixie_pentest/val.jsonl"

TOKENIZER_S3="${DIXIE_SFT_TOKENIZER_S3:-${ROOT}/tokenizers/new_bpe_50k/bpe_50k_fw_stack.model}"
TOKENIZER="${DATA_ROOT}/tokenizers/bpe_50k_fw_stack.model"
BASE_CKPT="${CKPT_DIR}/ckpt_sft_step_5000.pt"

CFG="/tmp/dixie_sft_config.yaml"
TRAIN_LOG="${DATA_ROOT}/ssm_runs/${RUN_ID}/train.log"

export RUN_ID CKPT_DIR S3_PREFIX TRAIN_LOG REGION STOP_INSTANCE_ON_EXIT AWS_DEFAULT_REGION="${REGION}"

mkdir -p "${CKPT_DIR}" "${DATA_ROOT}/data/dixie_pentest" "${DATA_ROOT}/tokenizers" "$(dirname "${TRAIN_LOG}")"

echo "=== host ==="
date -Iseconds
uname -a
echo "=== disk ==="
df -h / "${DATA_ROOT}" 2>/dev/null || df -h
echo "=== gpu ==="
nvidia-smi 2>/dev/null || echo "[warn] nvidia-smi unavailable"
echo "=== RUN_ID=${RUN_ID} ==="
echo "=== S3_ROOT=${ROOT} ==="

echo "=== code bundle ==="
rm -rf "${CODE_DIR}/model_training/titanProject"
mkdir -p "$(dirname "${CODE_DIR}/model_training/titanProject")"
aws s3 cp "${CODE_BUNDLE_URI}" "${CODE_BUNDLE_LOCAL}" --only-show-errors --region "${REGION}"
tar -xzf "${CODE_BUNDLE_LOCAL}" -C "${CODE_DIR}"
rm -f "${CODE_BUNDLE_LOCAL}"

echo "=== pip install ==="
python3 -m pip install -q --no-cache-dir numpy==1.26.4
python3 -m pip install -q --upgrade --no-cache-dir \
  torch==2.5.1+cu121 torchvision==0.20.1+cu121 torchaudio==2.5.1+cu121 \
  --extra-index-url https://download.pytorch.org/whl/cu121
python3 -m pip install -q --no-cache-dir sentencepiece boto3 pyarrow
python3 -m pip install -q --no-cache-dir titans-pytorch==0.5.3 --no-deps
python3 -m pip install -q --no-cache-dir \
  einops==0.8.2 einx==0.4.2 hyper-connections==0.4.9 axial-positional-embedding==0.3.12 \
  assoc-scan==0.0.4 ema-pytorch==0.7.9 tqdm fire loguru orjson tensordict==0.11.0 \
  x-transformers==2.17.7 rotary-embedding-torch==0.8.9 ninja pyvers cloudpickle frozendict --no-deps
python3 -m pip install -q --no-cache-dir datasets huggingface_hub pyyaml
echo "=== pip install done ==="

python3 -c "import torch; print('torch', torch.__version__, 'cuda_available', torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'no cuda')"

echo "=== downloading pentest training data ==="
aws s3 cp "${TRAIN_S3}" "${TRAIN_DATA}" --only-show-errors --region "${REGION}"
aws s3 cp "${VAL_S3}" "${VAL_DATA}" --only-show-errors --region "${REGION}"

echo "=== downloading base checkpoint ==="
aws s3 cp "${DIXIE_SFT_BASE_CKPT_S3}" "${BASE_CKPT}" --only-show-errors --region "${REGION}"

echo "=== downloading tokenizer ==="
aws s3 cp "${TOKENIZER_S3}" "${TOKENIZER}" --only-show-errors --region "${REGION}"

echo "=== writing config ==="
cat > "${CFG}" <<YAML
model:
  variant: gpt
  vocab_size: 50000
  dim: 1024
  depth: 24
  heads: 16
  ff_mult: 4
  max_seq_len: 2048

train:
  seq_len: 1024
  batch_size: 2
  grad_accum_steps: 8
  lr: 0.00003
  lr_min: 0.000003
  weight_decay: 0.01
  warmup_steps: 300
  max_steps: 5000
  grad_clip: 1.0
  betas: [0.9, 0.98]
  eps: 1.0e-8
  cosine_decay: true
  save_every: 1000
  eval_every: 500

data:
  train_path: ${TRAIN_DATA}
  val_path: ${VAL_DATA}
  tokenizer_path: ${TOKENIZER}
  shuffle_buffer: 100000
YAML

echo "=== verifying data ==="
wc -l "${TRAIN_DATA}" "${VAL_DATA}"
ls -lh "${BASE_CKPT}" "${TOKENIZER}"

echo "=== starting Dixie Flatline SFT training ==="
echo "  Base checkpoint: general SFT step 5000"
echo "  Domain data: 352K pentest samples (85% domain / 15% general)"
echo "  Steps: 5000, LR: 3e-5 -> 3e-6 cosine"
echo "  Effective batch: 2 * 8 = 16"

cd "${CODE_DIR}"
PYTHONUNBUFFERED=1 python3 model_training/titanProject/finetune_sft.py \
  --config "${CFG}" \
  --ckpt "${BASE_CKPT}" \
  --device cuda \
  --steps 5000 \
  --log-every 20 \
  --eval-every 500 \
  --eval-batches 20 \
  --save-every 1000 \
  --checkpoint-dir "${CKPT_DIR}" \
  --s3-checkpoint-uri "${S3_PREFIX}" \
  --min-free-gb 5 \
  --aws-bin aws 2>&1 | tee -a "${TRAIN_LOG}"

echo "=== training complete ==="
aws s3 sync "${CKPT_DIR}" "${S3_PREFIX}" --exclude "*" --include "ckpt_sft_step_*.pt" --only-show-errors --region "${REGION}"
aws s3 cp "${TRAIN_LOG}" "${S3_PREFIX}train.log" --only-show-errors --region "${REGION}"
echo "=== checkpoints synced to ${S3_PREFIX} ==="

get_instance_id() {
  local token
  token="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' 2>/dev/null || true)"
  if [[ -n "${token}" ]]; then
    curl -fsS -H "X-aws-ec2-metadata-token: ${token}" \
      http://169.254.169.254/latest/meta-data/instance-id
  else
    curl -fsS http://169.254.169.254/latest/meta-data/instance-id
  fi
}

if [[ "${STOP_INSTANCE_ON_EXIT}" == "1" ]]; then
  INST_ID="$(get_instance_id 2>/dev/null || true)"
  if [[ -n "${INST_ID}" ]]; then
    echo "[self-stop] stopping instance ${INST_ID}"
    aws ec2 stop-instances --instance-ids "${INST_ID}" --region "${REGION}" --output json 2>&1 || \
      echo "[self-stop] FAILED"
  fi
fi
