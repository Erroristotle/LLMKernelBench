# LLMKernelBench

A benchmark framework for evaluating large language models on software vulnerability detection tasks.

## Overview

LLMKernelBench evaluates LLMs and baseline models on a curated dataset of real-world vulnerabilities (CVEs) from the Linux kernel. It supports multiple evaluation tasks, dual-database testing (standard and leakage-free), and cluster-ready job scheduling with resume capability.

## Project Structure

```
LLMKernelBench/
├── src/
│   ├── main.py                 # CLI entry point
│   ├── configs/
│   │   └── models_config.json  # Model configurations and API keys
│   ├── data/
│   │   ├── raw/                # Source databases and CWE hierarchy
│   │   └── processed/
│   ├── models/                 # LLM and baseline model managers
│   ├── evaluation/             # Evaluation framework and metrics
│   ├── scheduler/              # Job scheduling with resume support
│   ├── utils/                  # Config, database, and logging
│   └── dataset/                # Dataset building tools
├── experiments/
│   ├── scripts/                # SLURM and cluster scripts
│   ├── analysis/               # Analysis and diagnostic scripts
│   ├── finetuning/             # LoRA fine-tuning pipeline
│   └── notebooks/              # Jupyter notebooks
├── results/                    # Evaluation outputs and databases
│   └── logs/slurm/
└── paper/                      # LaTeX source
```

## Setup

**1. Install dependencies:**
```bash
pip install -r requirements.txt
pip install -e .
```

**2. Configure models:**  
Edit `src/configs/models_config.json` with your model settings and API keys.

**3. Set API keys:**  
Create `src/utils/.config`:
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

**Fine-tuned (LoRA):** Qwen3-4B adapters trained on Devign, VDisc, PrimeVul, MegaVul

## Cluster (SLURM)

```bash
sbatch --partition=Nebula_GPU --gres=gpu:2 --time=48:00:00 --mem=100G \
  --wrap="source ~/miniconda/etc/profile.d/conda.sh && conda activate llmserver && \
  cd $(pwd) && python src/main.py evaluate <model_name> --both-databases"

# Monitor
tail -f results/logs/slurm/slurm-<JOB_ID>.out
```

See `experiments/scripts/` for ready-made submission scripts.

## Fine-tuning

See `experiments/finetuning/` for the LoRA training pipeline.  
To use a local adapter, set `"adapter_path": "experiments/finetuning/megavul_adapter"` in `models_config.json`.

## License

See [LICENSE](LICENSE).
