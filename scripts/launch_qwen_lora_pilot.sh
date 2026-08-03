#!/usr/bin/env bash
#
# Dixie Flatline — controller/launcher for the bounded Qwen3-Coder MoE LoRA
# throughput pilot (Vikunja #1106).
#
# This is the missing piece between scripts/train_qwen3_coder_lora_pilot.py
# (the trainer) and scripts/dixie_qwen_lora_pilot_worker.sh (the on-box runner).
# It packages the trainer, stages it + the worker in S3, and launches a single
# GPU instance whose user-data bootstraps the worker. The worker self-terminates
# on completion or failure.
#
# SAFE BY DEFAULT: with no flags this only packages the source bundle locally
# and PRINTS the exact S3 uploads + `aws ec2 run-instances` it WOULD run. It
# performs NO AWS calls and needs NO credentials. Pass --launch to actually
# stage to S3 and create the instance.
#
# Everything account/region/AMI-specific comes from the environment; nothing
# under s3://… or any AMI/subnet id is hardcoded in this repo.
#
# ─ Required (only enforced with --launch) ────────────────────────────────
#   DIXIE_PILOT_S3_PREFIX       Base S3 prefix (no trailing slash). A per-run
#                               dir ${PREFIX}/${RUN_ID} is created beneath it.
#                               e.g. s3://your-bucket/your-org/titan/pilots/qwen-lora
#   DIXIE_PILOT_TRAIN_S3        Full S3 URI of train.jsonl (HF Messages JSONL).
#                               e.g. s3://your-bucket/.../dixie_pentest/train.jsonl
#   DIXIE_PILOT_AWS_REGION      AWS region (e.g. us-east-1). No default.
#   DIXIE_PILOT_AMI_ID          CUDA/Deep-Learning AMI id for the GPU host.
#   DIXIE_PILOT_INSTANCE_PROFILE  IAM instance profile NAME with read/write on
#                               DIXIE_PILOT_S3_PREFIX and the train object.
#
# ─ Optional ──────────────────────────────────────────────────────────────
#   DIXIE_PILOT_INSTANCE_TYPE   default p5.4xlarge (1x H100 80GB)
#   DIXIE_PILOT_MAX_HOURS       default 6  — hard OS shutdown cap on the box
#   DIXIE_PILOT_ROOT_VOLUME_GB  default 512 — root EBS (model weights + HF cache)
#   DIXIE_PILOT_SUBNET_ID       optional subnet
#   DIXIE_PILOT_SG_IDS          optional security groups (space-separated)
#   DIXIE_PILOT_KEY_NAME        optional EC2 key pair (for SSH debugging)
#   DIXIE_PILOT_SOURCE_FILES    default "scripts/train_qwen3_coder_lora_pilot.py"
#                               — files (repo-relative) packed into source.tar.gz
#
# Usage:
#   scripts/launch_qwen_lora_pilot.sh            # dry-run: package + print plan
#   scripts/launch_qwen_lora_pilot.sh --launch   # stage to S3 + run-instances
#
set -Eeuo pipefail

LAUNCH=0
for arg in "$@"; do
  case "$arg" in
    --launch) LAUNCH=1 ;;
    --dry-run) LAUNCH=0 ;;
    -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
WORKER_REL="scripts/dixie_qwen_lora_pilot_worker.sh"
WORKER="${REPO_ROOT}/${WORKER_REL}"
[[ -f "$WORKER" ]] || { echo "missing worker: $WORKER" >&2; exit 1; }

read -ra SOURCE_FILES <<< "${DIXIE_PILOT_SOURCE_FILES:-scripts/train_qwen3_coder_lora_pilot.py}"
for rel in "${SOURCE_FILES[@]}"; do
  [[ -f "${REPO_ROOT}/${rel}" ]] || { echo "missing source file: ${rel}" >&2; exit 1; }
done

INSTANCE_TYPE="${DIXIE_PILOT_INSTANCE_TYPE:-p5.4xlarge}"
MAX_HOURS="${DIXIE_PILOT_MAX_HOURS:-6}"
ROOT_VOLUME_GB="${DIXIE_PILOT_ROOT_VOLUME_GB:-512}"
RUN_ID="dixie_qwen_lora_pilot_$(date -u +%Y%m%d%H%M%S)"

# Numeric overrides must be positive integers. MAX_HOURS especially: it is
# expanded into the user-data time cap, and a bad value would silently yield
# `shutdown -h +0` (immediate) or an unbounded box — so fail fast here.
for pair in "DIXIE_PILOT_MAX_HOURS=${MAX_HOURS}" "DIXIE_PILOT_ROOT_VOLUME_GB=${ROOT_VOLUME_GB}"; do
  if ! [[ "${pair#*=}" =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid ${pair%%=*}: '${pair#*=}' (must be a positive integer)" >&2
    exit 2
  fi
done

# PREFIX / TRAIN_S3 are only strictly required to launch; in dry-run we still
# render the plan with placeholders so the script is runnable without config.
S3_BASE="${DIXIE_PILOT_S3_PREFIX:-<set DIXIE_PILOT_S3_PREFIX>}"
PREFIX="${S3_BASE%/}/${RUN_ID}"
TRAIN_S3="${DIXIE_PILOT_TRAIN_S3:-<set DIXIE_PILOT_TRAIN_S3>}"
REGION="${DIXIE_PILOT_AWS_REGION:-<set DIXIE_PILOT_AWS_REGION>}"

# ── Package source.tar.gz (local, no creds needed) ───────────────────────
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
BUNDLE="${STAGE}/source.tar.gz"
tar -czf "$BUNDLE" -C "$REPO_ROOT" "${SOURCE_FILES[@]}"
BUNDLE_SIZE="$(du -h "$BUNDLE" | cut -f1)"

# ── Build the user-data bootstrap ────────────────────────────────────────
USERDATA="${STAGE}/user-data.sh"
cat > "$USERDATA" <<BOOT
#!/usr/bin/env bash
set -Eeuo pipefail
export AWS_DEFAULT_REGION="${REGION}"
export RUN_ID="${RUN_ID}"
export PREFIX="${PREFIX}"
export TRAIN_S3="${TRAIN_S3}"
# Hard cap: terminate the box after ${MAX_HOURS}h even if the run hangs
# (run-instances sets shutdown-behavior=terminate, so this halts -> terminate).
shutdown -h +$(( MAX_HOURS * 60 )) || true
aws s3 cp "${PREFIX}/worker.sh" /root/worker.sh --only-show-errors
chmod +x /root/worker.sh
exec /root/worker.sh
BOOT

# ── Assemble run-instances args ──────────────────────────────────────────
RUN_ARGS=(
  ec2 run-instances
  --region "$REGION"
  --image-id "${DIXIE_PILOT_AMI_ID:-<set DIXIE_PILOT_AMI_ID>}"
  --instance-type "$INSTANCE_TYPE"
  --count 1
  --instance-initiated-shutdown-behavior terminate
  --iam-instance-profile "Name=${DIXIE_PILOT_INSTANCE_PROFILE:-<set DIXIE_PILOT_INSTANCE_PROFILE>}"
  --block-device-mappings
  "DeviceName=/dev/sda1,Ebs={VolumeSize=${ROOT_VOLUME_GB},VolumeType=gp3,DeleteOnTermination=true}"
  --user-data "file://${USERDATA}"
  --tag-specifications
  "ResourceType=instance,Tags=[{Key=Name,Value=${RUN_ID}},{Key=project,Value=dixie-flatline},{Key=pilot,Value=qwen3-coder-lora}]"
)
[[ -n "${DIXIE_PILOT_SUBNET_ID:-}" ]] && RUN_ARGS+=(--subnet-id "$DIXIE_PILOT_SUBNET_ID")
[[ -n "${DIXIE_PILOT_KEY_NAME:-}" ]] && RUN_ARGS+=(--key-name "$DIXIE_PILOT_KEY_NAME")
if [[ -n "${DIXIE_PILOT_SG_IDS:-}" ]]; then
  read -ra _sg_ids <<< "$DIXIE_PILOT_SG_IDS"
  RUN_ARGS+=(--security-group-ids "${_sg_ids[@]}")
fi

echo "=== Qwen3-Coder LoRA pilot launcher ==="
echo "RUN_ID            ${RUN_ID}"
echo "instance          ${INSTANCE_TYPE}  (hard cap ${MAX_HOURS}h, root ${ROOT_VOLUME_GB}GB gp3)"
echo "S3 run prefix     ${PREFIX}"
echo "train data        ${TRAIN_S3}"
echo "source bundle     ${BUNDLE}  (${BUNDLE_SIZE}) -> ${PREFIX}/source.tar.gz"
echo "worker            ${WORKER_REL} -> ${PREFIX}/worker.sh"
echo

if [[ "$LAUNCH" != 1 ]]; then
  echo "[dry-run] no AWS calls made. Would stage:"
  echo "  aws s3 cp <bundle>    ${PREFIX}/source.tar.gz"
  echo "  aws s3 cp ${WORKER_REL}  ${PREFIX}/worker.sh"
  echo "[dry-run] would then run:"
  printf '  aws'; printf ' %q' "${RUN_ARGS[@]}"; printf '\n'
  echo
  echo "Re-run with --launch to stage to S3 and create the instance."
  echo "Required env for --launch: DIXIE_PILOT_S3_PREFIX, DIXIE_PILOT_TRAIN_S3,"
  echo "  DIXIE_PILOT_AWS_REGION, DIXIE_PILOT_AMI_ID, DIXIE_PILOT_INSTANCE_PROFILE."
  exit 0
fi

# ── Launch path (requires real config + credentials) ─────────────────────
missing=0
for var in DIXIE_PILOT_S3_PREFIX DIXIE_PILOT_TRAIN_S3 DIXIE_PILOT_AWS_REGION \
           DIXIE_PILOT_AMI_ID DIXIE_PILOT_INSTANCE_PROFILE; do
  if [[ -z "${!var:-}" ]]; then echo "missing required env: ${var}" >&2; missing=1; fi
done
[[ "$missing" == 0 ]] || exit 1

echo "[launch] staging source + worker to S3…"
aws s3 cp "$BUNDLE" "${PREFIX}/source.tar.gz" --region "$REGION" --only-show-errors
aws s3 cp "$WORKER" "${PREFIX}/worker.sh" --region "$REGION" --only-show-errors

echo "[launch] creating ${INSTANCE_TYPE}…"
INSTANCE_ID="$(aws "${RUN_ARGS[@]}" --query 'Instances[0].InstanceId' --output text)"
echo "[launch] instance ${INSTANCE_ID} starting."
echo "[launch] tail progress:  aws s3 cp ${PREFIX}/logs/run.log - --region ${REGION}"
echo "[launch] results land at: ${PREFIX}/output/  (pilot_summary.json, pilot_metrics.jsonl, adapter/)"
