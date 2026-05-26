#!/bin/bash
#SBATCH --partition=Nebula_GPU
#SBATCH --gres=gpu:A100:2
#SBATCH --mem=160G
#SBATCH --cpus-per-task=4
#SBATCH --time=06:00:00
#SBATCH --job-name=cwe_qwen3_coder
#SBATCH --output=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/cwe_qwen3_coder_%j.out
#SBATCH --error=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/cwe_qwen3_coder_%j.err
#SBATCH --nodelist=str-gpu11

set -euo pipefail
cd /users/azibaeir/Research/LLMKernelBench

echo "Job ID:        $SLURM_JOB_ID"
echo "Node:          $SLURM_JOB_NODELIST"
echo "CUDA devices:  ${CUDA_VISIBLE_DEVICES:-unset}"
echo "Started:       $(date)"
nvidia-smi || true
echo

export HF_HOME=/scratch/azibaeir/cache/huggingface
export HF_HUB_CACHE=/scratch/azibaeir/cache/huggingface/hub
export TRANSFORMERS_CACHE=/scratch/azibaeir/cache/huggingface/hub
PYTHON=/users/azibaeir/miniconda/envs/llmserver/bin/python
MODEL=qwen3_coder

# Two more T=0.1 repeats, CWE detection only
declare -a CONDITIONS=(
    "0.1 new_results_temp0.1_run4"
    "0.1 new_results_temp0.1_run5"
)

for spec in "${CONDITIONS[@]}"; do
    TEMP=$(echo "$spec" | cut -d' ' -f1)
    OUTDIR=$(echo "$spec" | cut -d' ' -f2)
    export LLMKB_TEMPERATURE=$TEMP
    export LLMKB_OUTPUT_DIR=/users/azibaeir/Research/LLMKernelBench/results/output/$OUTDIR
    for DB in database database_leakagefree; do
        echo
        echo "=================== ${MODEL}  T=${TEMP}  $DB  (rank_cwe only) ==================="
        echo "Started: $(date)"
        PYTHONPATH=/users/azibaeir/Research/LLMKernelBench/src $PYTHON \
            src/main.py evaluate $MODEL \
            --database $DB \
            --no-scheduler \
            --max-workers 1 \
            --tasks rank_cwe
        echo "Finished: $(date)"
    done
done

echo
echo "All CWE runs done: $(date)"
