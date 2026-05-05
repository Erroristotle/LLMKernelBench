#!/bin/bash
#SBATCH --job-name=megavul_eval
#SBATCH --partition=Nebula_GPU
#SBATCH --nodelist=str-gpu11
#SBATCH --gres=gpu:1
#SBATCH --ntasks=4
#SBATCH --mem=100G
#SBATCH --time=48:00:00
#SBATCH --output=megavul_eval_%j.out
#SBATCH --error=megavul_eval_%j.err

# Activate conda environment
source "$HOME/miniconda/etc/profile.d/conda.sh"
conda activate llmserver

# Change to project directory
PROJECT_ROOT="$( cd "$(dirname "$0")/../.." && pwd )"
cd "$PROJECT_ROOT"

# Install required dependencies if not already present
pip install -q pandas langchain langchain-core langchain-community google-generativeai scikit-learn scipy 2>&1 | grep -v "Requirement already satisfied" || true

# Enable CUDA debugging for better error messages
export CUDA_LAUNCH_BLOCKING=1
export TORCH_USE_CUDA_DSA=1

# Run evaluation on both databases with SVD2-6 tasks
python src/main.py evaluate megavul --both-databases --tasks rank_cwe is_vulnerable_vuln is_vulnerable_patch is_vulnerable_vuln_cve_cwe is_vulnerable_patch_cve_cwe

echo "Evaluation completed!"