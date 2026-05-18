#!/bin/bash
#SBATCH --partition=Nebula_GPU
#SBATCH --gres=gpu:L40S:1
#SBATCH --mem=32G
#SBATCH --cpus-per-task=4
#SBATCH --time=30:00:00
#SBATCH --job-name=tsweep_deepseek
#SBATCH --output=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/tsweep_deepseek_%j.out
#SBATCH --error=/users/azibaeir/Research/LLMKernelBench/results/logs/slurm/tsweep_deepseek_%j.err

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
MODEL=deepseek

# (temperature, output-dir-name) per condition
declare -a CONDITIONS=(
    "0.1 new_results_temp0.1_run2"
    "0.1 new_results_temp0.1_run3"
    "1.0 new_results_temp1.0"
)

for spec in "${CONDITIONS[@]}"; do
    TEMP=$(echo "$spec" | cut -d' ' -f1)
    OUTDIR=$(echo "$spec" | cut -d' ' -f2)
    export LLMKB_TEMPERATURE=$TEMP
    export LLMKB_OUTPUT_DIR=/users/azibaeir/Research/LLMKernelBench/results/output/$OUTDIR
    for DB in database database_leakagefree; do
        echo
        echo "=================== ${MODEL}  T=${TEMP}  $DB ==================="
        echo "Started: $(date)"
        PYTHONPATH=/users/azibaeir/Research/LLMKernelBench/src $PYTHON \
            src/main.py evaluate $MODEL \
            --database $DB \
            --no-scheduler \
            --max-workers 1 \
            --tasks is_vulnerable_vuln is_vulnerable_patch is_vulnerable_vuln_cve_cwe is_vulnerable_patch_cve_cwe rank_cwe
        echo "Finished: $(date)"
    done
done

echo
echo "All conditions done: $(date)"
