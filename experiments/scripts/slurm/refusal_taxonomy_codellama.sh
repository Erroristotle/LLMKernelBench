#!/bin/bash
#SBATCH --partition=Nebula_GPU
#SBATCH --gres=gpu:L40S:1
#SBATCH --mem=32G
#SBATCH --cpus-per-task=4
#SBATCH --time=06:00:00
#SBATCH --job-name=refusal_codellama
#SBATCH --output=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/refusal_codellama_%j.out
#SBATCH --error=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/refusal_codellama_%j.err

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

PYTHONPATH="/users/azibaeir/Research/LLMKernelBench/src" \
/users/azibaeir/miniconda/envs/llmserver/bin/python \
    experiments/scripts/refusal_taxonomy_rerun.py \
    --model codellama \
    --num-samples 30 \
    --seed 42 \
    --max-new-tokens 256

echo
echo "Finished:      $(date)"
