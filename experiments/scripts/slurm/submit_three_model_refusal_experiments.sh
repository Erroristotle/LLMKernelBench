#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON="${PYTHON:-/users/azibaeir/miniconda/envs/llmserver/bin/python}"
LOG_DIR="$PROJECT_ROOT/results/logs/slurm"
mkdir -p "$LOG_DIR" results/refusal_taxonomy/raw results/safety_bench/xstest/raw

COMMON_ENV="cd $PROJECT_ROOT && export HF_HOME=/scratch/azibaeir/cache/huggingface HF_HUB_CACHE=/scratch/azibaeir/cache/huggingface/hub TRANSFORMERS_CACHE=/scratch/azibaeir/cache/huggingface/hub PYTHONPATH=$PROJECT_ROOT/src"

submit_l40s() {
    local node="$1"
    local job_name="$2"
    local command="$3"
    sbatch \
        --partition=Nebula_GPU \
        --nodelist="$node" \
        --gres=gpu:L40S:1 \
        --cpus-per-task=4 \
        --mem=100G \
        --time=06:00:00 \
        --job-name="$job_name" \
        --output="$LOG_DIR/${job_name}_%j.out" \
        --error="$LOG_DIR/${job_name}_%j.err" \
        --wrap="$COMMON_ENV && nvidia-smi && $command"
}

submit_a100_array() {
    local array_spec="$1"
    local job_name="$2"
    local command="$3"
    sbatch \
        --partition=Nebula_GPU \
        --nodelist=str-gpu11 \
        --gres=gpu:A100:1 \
        --cpus-per-task=4 \
        --mem=120G \
        --time=16:00:00 \
        --array="$array_spec" \
        --job-name="$job_name" \
        --output="$LOG_DIR/${job_name}_%A_%a.out" \
        --error="$LOG_DIR/${job_name}_%A_%a.err" \
        --wrap="$COMMON_ENV && nvidia-smi && $command"
}

echo "[submit] Llama/DeepSeek prompt-framing jobs"
read -r -a nodes <<< "${L40S_NODES:-str-gpu22 str-gpu27 str-gpu28 str-gpu29}"
i=0
for model in llama deepseek; do
    for framing in neutral defensive adversarial; do
        node="${nodes[$((i % ${#nodes[@]}))]}"
        submit_l40s "$node" "rt_${model}_${framing}" \
            "$PYTHON experiments/scripts/refusal_taxonomy_rerun.py --model $model --dataset-scope all_vulnerable --framing $framing --seed 42 --max-new-tokens 512 --output-dir results/refusal_taxonomy/raw"
        i=$((i + 1))
    done
done

echo "[submit] Llama/DeepSeek XSTest jobs"
submit_l40s "${nodes[$((i % ${#nodes[@]}))]}" "xstest_llama" \
    "$PYTHON experiments/scripts/safety_bench_rerun.py --model llama --benchmark xstest --split prompts --max-new-tokens 512 --output-dir results/safety_bench/xstest/raw"
i=$((i + 1))
submit_l40s "${nodes[$((i % ${#nodes[@]}))]}" "xstest_deepseek" \
    "$PYTHON experiments/scripts/safety_bench_rerun.py --model deepseek --benchmark xstest --split prompts --max-new-tokens 512 --output-dir results/safety_bench/xstest/raw"

echo "[submit] Qwen3-Coder sharded prompt-framing jobs on str-gpu11"
for framing in neutral defensive adversarial; do
    submit_a100_array "0-11%2" "rt_qwen_${framing}" \
        "$PYTHON experiments/scripts/refusal_taxonomy_rerun.py --model qwen3_coder --dataset-scope all_vulnerable --framing $framing --seed 42 --shard-index \${SLURM_ARRAY_TASK_ID} --num-shards 12 --max-new-tokens 80 --output-dir results/refusal_taxonomy/raw"
done

echo "[submit] Qwen3-Coder sharded XSTest jobs on str-gpu11"
submit_a100_array "0-12%2" "xstest_qwen" \
    "$PYTHON experiments/scripts/safety_bench_rerun.py --model qwen3_coder --benchmark xstest --split prompts --shard-index \${SLURM_ARRAY_TASK_ID} --num-shards 13 --max-new-tokens 80 --output-dir results/safety_bench/xstest/raw"

cat <<'EOF'

[next] After the jobs finish, run:
  experiments/scripts/run_refusal_postprocessing.sh

[monitor]
  squeue -u "$USER" -p Nebula_GPU
  tail -f results/logs/slurm/<job>.out
EOF
