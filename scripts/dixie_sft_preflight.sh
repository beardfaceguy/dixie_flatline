#!/usr/bin/env bash
#
# Dixie SFT — controller-side preflight before launching p4d / SSM.
#
# Runs the same checks documented in Vikunja (Phase 1) for attempt #4:
#   1. Optional: AWS caller identity + S3 head fetch smoke (needs aws CLI + credentials)
#   2. Required: smoke_sft_data.py against train.jsonl (local path or s3://)
#
# Usage:
#   ./scripts/dixie_sft_preflight.sh
#   DIXIE_SFT_TRAIN_URI=s3://bucket/... ./scripts/dixie_sft_preflight.sh
#   DIXIE_SFT_TRAIN_URI=/path/to/train.jsonl ./scripts/dixie_sft_preflight.sh
#
# Optional env:
#   WINTERMUTE_ROOT      (default: sibling ../wintermute from repo root)
#   DIXIE_SFT_TRAIN_URI  (default: staging path from postmortem)
#   HF_TOKEN             (default: from WINTERMUTE_HF_ENV if unset)
#   WINTERMUTE_HF_ENV    (default: $WINTERMUTE_ROOT/model_training/hf.env)
#   SMOKE_PYTHON         (default: $WINTERMUTE_ROOT/.venv/bin/python)
#   AWS_PROFILE          (default: experimental-admin — Alix SSO profile for staging S3)
#
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-experimental-admin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WINTERMUTE_ROOT="${WINTERMUTE_ROOT:-$(cd "${REPO_ROOT}/../wintermute" && pwd)}"
SMOKE_PY="${WINTERMUTE_ROOT}/model_training/titanProject/scripts/smoke_sft_data.py"
SMOKE_PYTHON="${SMOKE_PYTHON:-${WINTERMUTE_ROOT}/.venv/bin/python}"
HF_ENV="${WINTERMUTE_HF_ENV:-${WINTERMUTE_ROOT}/model_training/hf.env}"

DEFAULT_TRAIN_S3="s3://alix-ai-ml-staging-data/titan/data/dixie_pentest/train.jsonl"
DIXIE_SFT_TRAIN_URI="${DIXIE_SFT_TRAIN_URI:-${DEFAULT_TRAIN_S3}}"

die() { echo "preflight: ERROR: $*" >&2; exit 2; }

[[ -x "${SMOKE_PYTHON}" ]] || die "Python not found: ${SMOKE_PYTHON} (set WINTERMUTE_ROOT or SMOKE_PYTHON)"
[[ -f "${SMOKE_PY}" ]] || die "smoke script missing: ${SMOKE_PY}"

if [[ -z "${HF_TOKEN:-}" && -z "${HUGGINGFACE_HUB_TOKEN:-}" ]]; then
  if [[ -f "${HF_ENV}" ]]; then
    # hf.env uses accessToken= (do not echo value)
    HF_TOKEN="$(grep '^accessToken=' "${HF_ENV}" | cut -d= -f2-)"
    export HF_TOKEN
  fi
fi
if [[ -z "${HF_TOKEN:-}" && -z "${HUGGINGFACE_HUB_TOKEN:-}" ]]; then
  die "HF_TOKEN unset and no accessToken in ${HF_ENV}"
fi

echo "preflight: Wintermute root: ${WINTERMUTE_ROOT}"
echo "preflight: smoke script: ${SMOKE_PY}"
echo "preflight: train URI: ${DIXIE_SFT_TRAIN_URI}"

if command -v aws >/dev/null 2>&1; then
  if aws sts get-caller-identity >/dev/null 2>&1; then
    echo "preflight: AWS credentials OK"
  else
    echo "preflight: WARN: aws STS failed — s3:// smoke will fail until credentials are configured"
  fi
else
  echo "preflight: WARN: aws CLI not found — use a local --data path or install AWS CLI"
fi

echo "preflight: running smoke_sft_data (seq_len=2048, 5000-line head for s3, Mistral tokenizer)..."
exec "${SMOKE_PYTHON}" "${SMOKE_PY}" \
  --data "${DIXIE_SFT_TRAIN_URI}" \
  --hf-model mistralai/Mistral-7B-Instruct-v0.3 \
  --seq-len 2048 \
  --max-lines 5000 \
  --min-keep-rate 0.90
