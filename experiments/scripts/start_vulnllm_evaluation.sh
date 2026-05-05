#!/bin/bash

# Smart job submission script that handles cleanup, resume, and runs all models on both databases
# Usage: ./start_vulnllm_evaluation.sh [model_list] [extra_slurm_args]
#
# Examples:
#   ./start_vulnllm_evaluation.sh                          # Run all models
#   ./start_vulnllm_evaluation.sh "deepseek,gemini"        # Run specific models
#   ./start_vulnllm_evaluation.sh all "--time=72:00:00"    # Run all models with custom time limit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Parse arguments
MODEL_LIST=${1:-"all"}
EXTRA_SLURM_ARGS=${2:-""}

echo "=================================================="
echo "VulnLLMEval Smart Job Submission"
echo "=================================================="
echo "Models to run: $MODEL_LIST"
echo "Extra SLURM args: $EXTRA_SLURM_ARGS"
echo "Project directory: $SCRIPT_DIR"
echo "=================================================="

# Step 1: Cleanup any existing processes
echo "Step 1: Cleaning up existing processes..."
"$SCRIPT_DIR/cleanup_processes.sh"

# Step 2: Check for incomplete jobs and auto-resume if needed
echo ""
echo "Step 2: Checking for incomplete jobs..."
python src/main.py auto-resume --dry-run

read -p "Do you want to auto-resume incomplete jobs before starting new evaluation? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Auto-resuming incomplete jobs..."
    python src/main.py auto-resume
    echo "Auto-resume completed."
fi

# Step 3: Force commit all databases to ensure data persistence
echo ""
echo "Step 3: Ensuring database persistence..."
PYTHONPATH="$PROJECT_ROOT/src" python -c "
from scheduler.job_scheduler import JobScheduler
scheduler = JobScheduler()
scheduler.force_commit_all_databases()
print('All databases committed.')
"

# Step 4: Submit the SLURM job
echo ""
echo "Step 4: Submitting SLURM job..."

# Build the sbatch command
SBATCH_CMD="sbatch --partition=Nebula_GPU --nodelist=str-gpu26 --gres=gpu:2 --time=48:00:00 --mem=100G"

# Add extra SLURM arguments if provided
if [ ! -z "$EXTRA_SLURM_ARGS" ]; then
    SBATCH_CMD="$SBATCH_CMD $EXTRA_SLURM_ARGS"
fi

# Add the submit script and model list
SBATCH_CMD="$SBATCH_CMD submit_job.sh $MODEL_LIST"

echo "Executing: $SBATCH_CMD"
echo ""

# Submit the job
JOB_ID=$($SBATCH_CMD | grep -oP 'Submitted batch job \K\d+')

if [ ! -z "$JOB_ID" ]; then
    echo "✓ Job submitted successfully!"
    echo "  Job ID: $JOB_ID"
    echo "  Models: $MODEL_LIST"
    echo ""
    echo "Monitor job with:"
    echo "  squeue -j $JOB_ID"
    echo "  tail -f results/logs/slurm/${JOB_ID}.out"
    echo "  tail -f results/logs/slurm/${JOB_ID}.err"
    echo ""
    echo "Check job status:"
    echo "  python main.py list-jobs"
    echo "  python main.py status <job_id>"
    echo ""
    echo "If job fails, resume with:"
    echo "  python src/main.py auto-resume"
else
    echo "✗ Failed to submit job!"
    exit 1
fi

echo "=================================================="
echo "Job submission completed successfully!"
echo "=================================================="
