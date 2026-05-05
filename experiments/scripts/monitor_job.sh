#!/bin/bash
# Quick job monitoring script

if [ -z "$1" ]; then
    echo "Usage: ./monitor_job.sh JOB_ID"
    echo "Example: ./monitor_job.sh 13891916"
    exit 1
fi

JOB_ID=$1

echo "=========================================="
echo "Monitoring Job: $JOB_ID"
echo "=========================================="

# Check job status
echo -e "\n📊 Job Status:"
squeue -j $JOB_ID || echo "Job completed or not found"

# Show last 20 lines of SLURM output
echo -e "\n📝 Last 20 lines of output:"
tail -n 20 slurm-${JOB_ID}.out 2>/dev/null || echo "Log file not found yet"

# Check for scheduler logs
echo -e "\n📂 Detailed scheduler logs:"
find output/scheduler/logs/ -name "*${JOB_ID}*" -o -newer slurm-${JOB_ID}.out 2>/dev/null | tail -3

echo -e "\n=========================================="
echo "To follow logs in real-time:"
echo "  tail -f slurm-${JOB_ID}.out"
echo "=========================================="
