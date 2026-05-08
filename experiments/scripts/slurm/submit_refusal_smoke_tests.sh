#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON="${PYTHON:-/users/azibaeir/miniconda/envs/llmserver/bin/python}"
LOG_DIR="$PROJECT_ROOT/results/logs/slurm"
mkdir -p "$LOG_DIR" results/refusal_taxonomy/smoke results/safety_bench/xstest/smoke

COMMON_ENV="cd $PROJECT_ROOT && export HF_HOME=/scratch/azibaeir/cache/huggingface HF_HUB_CACHE=/scratch/azibaeir/cache/huggingface/hub TRANSFORMERS_CACHE=/scratch/azibaeir/cache/huggingface/hub PYTHONPATH=$PROJECT_ROOT/src"

submit_smoke() {
    local model="$1"
    local node="$2"
    local gres="$3"
    local mem="$4"
    local max_new_tokens="$5"
    local job_name="smoke_${model}"
    sbatch \
        --partition=Nebula_GPU \
        --nodelist="$node" \
        --gres="$gres" \
        --cpus-per-task=4 \
        --mem="$mem" \
        --time=02:00:00 \
        --job-name="$job_name" \
        --output="$LOG_DIR/${job_name}_%j.out" \
        --error="$LOG_DIR/${job_name}_%j.err" \
        --wrap="$COMMON_ENV && nvidia-smi && $PYTHON experiments/scripts/refusal_taxonomy_rerun.py --model $model --dataset-scope all_vulnerable --framing neutral --num-samples 1 --seed 42 --max-new-tokens $max_new_tokens --output-dir results/refusal_taxonomy/smoke --overwrite && $PYTHON experiments/scripts/safety_bench_rerun.py --model $model --benchmark xstest --split prompts --num-samples 1 --max-new-tokens $max_new_tokens --output-dir results/safety_bench/xstest/smoke --overwrite"
}

submit_smoke llama "${LLAMA_NODE:-str-gpu22}" gpu:L40S:1 100G 512
submit_smoke deepseek "${DEEPSEEK_NODE:-str-gpu27}" gpu:L40S:1 100G 512
submit_smoke qwen3_coder str-gpu11 gpu:A100:1 120G 80
