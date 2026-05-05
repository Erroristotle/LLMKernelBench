#!/bin/bash

# Cleanup script to kill all VulnLLMEval related processes
# Usage: ./cleanup_processes.sh

echo "=== VulnLLMEval Process Cleanup ==="
echo "$(date): Starting cleanup of all related processes..."

# Kill Python processes related to this project
echo "Killing Python processes..."
pkill -f "python.*main.py" || true
pkill -f "python.*vulnllm" || true
pkill -f "python.*VulnLLMEval" || true

# Kill any SLURM job processes
echo "Checking for SLURM jobs..."
if command -v squeue &> /dev/null; then
    # Get job IDs for vulnllmeval jobs
    SLURM_JOBS=$(squeue -u $(whoami) -n vulnllmeval -h -o "%i" 2>/dev/null || true)
    if [ ! -z "$SLURM_JOBS" ]; then
        echo "Found SLURM jobs: $SLURM_JOBS"
        for job_id in $SLURM_JOBS; do
            echo "Cancelling SLURM job: $job_id"
            scancel $job_id || true
        done
    else
        echo "No vulnllmeval SLURM jobs found"
    fi
else
    echo "SLURM not available, skipping SLURM job cleanup"
fi

# Kill any remaining processes using the project directory
PROJECT_DIR="$( cd "$(dirname "$0")/../.." && pwd )"
echo "Killing processes using project directory: $PROJECT_DIR"
pgrep -f "$PROJECT_DIR" | xargs kill -TERM 2>/dev/null || true

# Wait a few seconds for graceful shutdown
echo "Waiting for graceful shutdown..."
sleep 3

# Force kill any remaining processes
echo "Force killing any remaining processes..."
pgrep -f "$PROJECT_DIR" | xargs kill -KILL 2>/dev/null || true
pkill -9 -f "python.*main.py" 2>/dev/null || true
pkill -9 -f "python.*vulnllm" 2>/dev/null || true

# Clean up any lock files or temporary files
echo "Cleaning up temporary files..."
find "$PROJECT_DIR" -name "*.lock" -delete 2>/dev/null || true
find "$PROJECT_DIR" -name "*.tmp" -delete 2>/dev/null || true

# Show remaining processes (for verification)
echo ""
echo "=== Verification: Remaining related processes ==="
ps aux | grep -E "(python.*main.py|python.*vulnllm|VulnLLMEval)" | grep -v grep || echo "No related processes found"

echo ""
echo "=== Cleanup completed at $(date) ==="
echo "You can now safely start new jobs with:"
echo "  sbatch --partition=Nebula_GPU --nodelist=str-gpu26 --gres=gpu:2 --time=48:00:00 --mem=100G submit_job.sh"
