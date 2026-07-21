# LLMKernelBench

A benchmark framework for evaluating large language models on software vulnerability detection tasks.

## Overview

LLMKernelBench evaluates LLMs and baseline models on a curated dataset of real-world vulnerabilities (CVEs) from the Linux kernel. It supports multiple evaluation tasks, dual-database testing (standard and leakage-free), CWE classification, refusal/abstention analysis, and cluster-ready job scheduling with resume capability.

This repository is the artifact release: source code, experiment scripts, dataset, and the evaluation results reported in the paper.

## Project Structure

```
LLMKernelBench/
├── src/
│   ├── main.py                 # CLI entry point
│   ├── configs/
│   │   └── models_config.json  # Model configurations
│   ├── data/
│   │   ├── raw/                # Source databases and CWE hierarchy
│   │   └── processed/
│   ├── models/                 # LLM and baseline model managers
│   ├── evaluation/             # Evaluation framework and metrics
│   ├── scheduler/               # Job scheduling with resume support
│   ├── utils/                  # Config, database, and logging
│   └── dataset/                # Dataset building tools
├── experiments/
│   ├── scripts/                # SLURM and cluster submission scripts
│   ├── analysis/               # Analysis and diagnostic scripts
│   └── notebooks/              # Jupyter notebooks
├── results/                    # Evaluation outputs (see below)
├── tests/                      # Unit tests
├── data -> src/data/raw        # Symlink to the source dataset
└── setup.py / requirements.txt
```

## Results

`results/` contains the model outputs and derived metrics used in the paper:

- `output/new_results_temp*/raw_responses/` — raw per-model completions (standard + leakage-free databases) at temperature 0, 0.1 (3 repeated runs), and 1.0
- `output/hps_scores/`, `output/hps_validation/` — hierarchical prediction score results and validation
- `output/cost_latency/` — token/cost/latency accounting per model
- `abstention_audit/` — abstention/refusal rate audits
- `refusal_taxonomy/` — refusal taxonomy classification, including the temp-0 consistency runs
- `safety_bench/xstest/` — XSTest safety-refusal correlation analysis
- `format_compliance_control/` — parser/format compliance control study

Raw SLURM job logs, scheduler resume-state, and intermediate per-run SQLite caches are not tracked in git (they regenerate automatically when a run is executed via `src/main.py` or the scheduler) — see `.gitignore`.

## Setup

**1. Install dependencies:**
```bash
pip install -r requirements.txt
pip install -e .
```

**2. Configure models:**
Edit `src/configs/models_config.json` with your model settings.

**3. Set API keys:**
Create `src/utils/.config` (not tracked in git):
```
gemini_api_key=your_key_here
openai_api_key=your_key_here
```

## Usage

```bash
# Evaluate a single model
python src/main.py evaluate <model_name> --database database

# Evaluate on both databases (standard + leakage-free)
python src/main.py evaluate <model_name> --both-databases

# List available models
python src/main.py models --type llms
python src/main.py models --type baselines

# Job management
python src/main.py list-jobs
python src/main.py resume <job_id>
```

## Supported Models

**LLMs:** Gemini, DeepSeek, Qwen3-Coder, Llama, StarCoder2, Mistral, GPT

**Baselines:** CodeBERT, VulBERTa, UnixCoder, GraphCodeBERT

## Cluster (SLURM)

```bash
sbatch --partition=Nebula_GPU --gres=gpu:2 --time=48:00:00 --mem=100G \
  --wrap="source ~/miniconda/etc/profile.d/conda.sh && conda activate llmserver && \
  cd $(pwd) && python src/main.py evaluate <model_name> --both-databases"

# Monitor
tail -f results/logs/slurm/slurm-<JOB_ID>.out
```

See `experiments/scripts/` for ready-made submission scripts.

## License

See [LICENSE](LICENSE).
