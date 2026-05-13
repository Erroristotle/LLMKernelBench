#!/bin/bash
#SBATCH --partition=GPU
#SBATCH --gres=gpu:H200:1
#SBATCH --mem=120G
#SBATCH --cpus-per-task=4
#SBATCH --time=12:00:00
#SBATCH --job-name=t0full_qwen3_coder
#SBATCH --output=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/t0full_qwen3_coder_%j.out
#SBATCH --error=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/t0full_qwen3_coder_%j.err
#SBATCH --nodelist=str-gpu31

set -euo pipefail

cd /users/azibaeir/Research/LLMKernelBench

echo "Job ID:        $SLURM_JOB_ID"
echo "Node:          $SLURM_JOB_NODELIST"
echo "CUDA devices:  ${CUDA_VISIBLE_DEVICES:-unset}"
echo "Started:       $(date)"
nvidia-smi || true
echo

export HF_HOME="/scratch/azibaeir/cache/huggingface"
export HF_HUB_CACHE="/scratch/azibaeir/cache/huggingface/hub"
export TRANSFORMERS_CACHE="/scratch/azibaeir/cache/huggingface/hub"
export LLMKB_OUTPUT_DIR="/users/azibaeir/Research/LLMKernelBench/results/output/new_results"

PYTHON=/users/azibaeir/miniconda/envs/llmserver/bin/python

for DB in database database_leakagefree; do
    echo
    echo "=================== qwen3_coder  /  $DB ==================="
    echo "Started: $(date)"
    PYTHONPATH=/users/azibaeir/Research/LLMKernelBench/src $PYTHON \
        src/main.py evaluate qwen3_coder \
        --database $DB \
        --no-scheduler \
        --max-workers 1 \
        --tasks is_vulnerable_vuln is_vulnerable_patch is_vulnerable_vuln_cve_cwe is_vulnerable_patch_cve_cwe rank_cwe
    echo "Finished $DB: $(date)"
done

echo
echo "All databases done: $(date)"
