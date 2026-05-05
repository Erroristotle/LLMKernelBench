#!/bin/bash
#SBATCH --job-name=vulnllmeval
#SBATCH --output=results/logs/slurm/%j.out
#SBATCH --error=results/logs/slurm/%j.err

# Enhanced SL# Get list of models to run
if [ "$MODEL_LIST" = "all" ]; then
    # Use hardcoded list of all models (excluding gemini for now)
    MODELS="deepseek qwen llama starcoder mistral gemma"
    
    # Fallback: try to extract from config if the hardcoded list fails
    if ! echo "$MODELS" | grep -q "[a-zA-Z]"; then
        echo "Fallback: extracting models from config..."
        MODELS=$(python -c "
import json
try:
    with open('src/configs/models_config.json', 'r') as f:
        config = json.load(f)
    llms = list(config.get('llms', {}).keys())
    baselines = list(config.get('baselines', {}).keys())
    all_models = llms + baselines
    print(' '.join(all_models))
except Exception as e:
    print('deepseek qwen', end='')  # minimal fallback
")
    fi
else
    # Use provided comma-separated list
    MODELS=$(echo "$MODEL_LIST" | tr ',' ' ')
fi

echo "Models to evaluate: $MODELS"
echo "==============================================="

# Main execution loop
TOTAL_EXIT_CODE=0
COMPLETED_MODELS=()
FAILED_MODELS=()

for model in $MODELS; do
    echo ""
    echo "==============================================="
    echo "$(date): Starting evaluation for $model"
    echo "==============================================="
    
    if run_model_evaluation "$model"; then
        COMPLETED_MODELS+=("$model")
        echo "✓ $(date): $model completed successfully"
    else
        FAILED_MODELS+=("$model")
        TOTAL_EXIT_CODE=1
        echo "✗ $(date): $model failed"
        # Continue with next model instead of exiting
    fi
    
    echo "==============================================="
done

# Final summary
echo ""
echo "==============================================="
echo "FINAL EVALUATION SUMMARY"
echo "==============================================="
echo "Completed models (${#COMPLETED_MODELS[@]}): ${COMPLETED_MODELS[*]}"
echo "Failed models (${#FAILED_MODELS[@]}): ${FAILED_MODELS[*]}"
echo ""

if [ ${#FAILED_MODELS[@]} -eq 0 ]; then
    echo "🎉 ALL MODELS COMPLETED SUCCESSFULLY!"
    echo "Results are stored in the respective model databases in data/ directory"
else
    echo "⚠️  Some models failed. Check logs and resume failed jobs:"
    echo "   python src/main.py list-jobs"
    echo "   python src/main.py resume <job_id>"
fi

echo "==============================================="
echo "Job finished at: $(date)"
echo "==============================================="

exit $TOTAL_EXIT_CODE
