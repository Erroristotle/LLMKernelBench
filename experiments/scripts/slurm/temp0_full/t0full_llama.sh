#!/bin/bash
#SBATCH --partition=Nebula_GPU
#SBATCH --gres=gpu:L40S:1
#SBATCH --mem=32G
#SBATCH --cpus-per-task=4
#SBATCH --time=12:00:00
#SBATCH --job-name=t0full_llama
#SBATCH --output=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/t0full_llama_%j.out
#SBATCH --error=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/t0full_llama_%j.err

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
    echo "=================== llama  /  $DB ==================="
    echo "Started: $(date)"
    PYTHONPATH=/users/azibaeir/Research/LLMKernelBench/src $PYTHON \
        src/main.py evaluate llama \
        --database $DB \
        --no-scheduler \
        --max-workers 1 \
        --tasks is_vulnerable_vuln is_vulnerable_patch is_vulnerable_vuln_cve_cwe is_vulnerable_patch_cve_cwe rank_cwe
    echo "Finished $DB: $(date)"
done

echo
echo "All databases done: $(date)"
