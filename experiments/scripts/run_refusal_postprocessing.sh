#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON="${PYTHON:-/users/azibaeir/miniconda/envs/llmserver/bin/python}"
export PYTHONPATH="$PROJECT_ROOT/src"

"$PYTHON" experiments/scripts/refusal_taxonomy_classify.py \
    --input-dir results/refusal_taxonomy/raw \
    --output-dir results/refusal_taxonomy

"$PYTHON" experiments/analysis/correlate_refusal.py \
    --llmk-summary results/refusal_taxonomy/summary.csv \
    --xstest-input-dir results/safety_bench/xstest/raw \
    --output-dir results/safety_bench/xstest

"$PYTHON" experiments/analysis/validate_refusal_outputs.py \
    --summary results/refusal_taxonomy/summary.csv \
    --llmk-input-dir results/refusal_taxonomy/raw \
    --xstest-input-dir results/safety_bench/xstest/raw
