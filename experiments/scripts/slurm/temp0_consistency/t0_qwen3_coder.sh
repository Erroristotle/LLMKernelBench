#!/bin/bash
#SBATCH --partition=Nebula_GPU
#SBATCH --gres=gpu:A100:2
#SBATCH --mem=120G
#SBATCH --cpus-per-task=4
#SBATCH --time=02:00:00
#SBATCH --job-name=t0_qwen3_coder
#SBATCH --output=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/t0_qwen3_coder_%j.out
#SBATCH --error=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/t0_qwen3_coder_%j.err

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

for RUN in 1 2 3; do
    echo
    echo "=================== RUN ${RUN} ==================="
    echo "Started run ${RUN}: $(date)"
    PYTHONPATH="/users/azibaeir/Research/LLMKernelBench/src" \
    /users/azibaeir/miniconda/envs/llmserver/bin/python \
        experiments/scripts/refusal_taxonomy_rerun.py \
        --model qwen3_coder \
        --framing neutral \
        --dataset-scope pbd_vulnerable \
        --num-samples 10 \
        --seed 42 \
        --shuffle \
        --greedy \
        --max-new-tokens 256 \
        --output-dir results/refusal_taxonomy/temp0_consistency/run${RUN} \
        --overwrite
    echo "Finished run ${RUN}: $(date)"
done

echo
echo "All runs finished: $(date)"
