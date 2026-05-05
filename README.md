## DeepEval (Confident AI) Integration

This project can optionally run [DeepEval by Confident AI](https://www.deepeval.com/) to evaluate model outputs post-run.

### Install

DeepEval is included in `requirements.txt`.

```bash
pip install -r requirements.txt
```

### Authenticate

1. Create a Confident AI account and get your API key.
2. Login via CLI:

```bash
deepeval login
```

If using OpenAI for metric models, set:

```bash
export OPENAI_API_KEY=your_key
```

### Run after evaluation

Add the `--deepeval` flag to the evaluate command:

```bash
python src/main.py evaluate <model_name> --database database --deepeval
```

This will read from `<cwd>/<database>.sqlite` and create a DeepEval run. You can also run the runner directly:

```bash
python -m evaluation.deepeval_runner
```

Set `DEEPEVAL_DB_PATH` to point to a specific SQLite file when invoking directly.

# VulnLLMEval-SANER

Advanced LLM evaluation framework for vulnerability detection and repair tasks.

## Features

- **Multiple LLM Support**: Gemini 2.5 Pro, DeepSeek-R1 8B, Qwen3-Coder 30B, GPT-OSS, StarCoder2 7B
- **Baseline Models**: CodeBERT, VulBERTa, UnixCoder, GraphCodeBERT
- **Dual Database Testing**: Standard and leakage-free datasets
- **GPU Optimization**: Automatic memory management and device mapping
- **Job Scheduling**: Cluster-ready with resume capability
- **LangChain Integration**: Advanced output parsing and filtering

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure models:**
   Edit `src/configs/models_config.json` with your API keys and model preferences.

3. **Set up API keys:**
   Create `src/utils/.config` with your API keys:
   ```
   gemini_api_key=your_gemini_key_here
   openai_api_key=your_openai_key_here
   ```

4. **Run evaluation:**
   ```bash
   # Test a baseline model
   python src/main.py evaluate codebert --database database
   
   # Test an LLM
   python src/main.py evaluate gemini --database database
   
   # Test on both databases
   python src/main.py evaluate starcoder --both-databases
   
   # Test a fine-tuned model with LoRA adapter
   python src/main.py evaluate devign_ft --both-databases
   ```

## Available Models

### LLMs
- `gemini`: Google Gemini 2.5 Pro
- `deepseek`: DeepSeek-R1 8B 
- `qwen`: Qwen2.5-Coder 32B
- `qwen3_4b`: Qwen3 4B Instruct
- `gpt`: GPT-4o Mini
- `starcoder`: StarCoder2 7B

### Fine-tuned Models (LoRA Adapters)
- `devign_ft`: Qwen3 4B + Devign LoRA (binary vulnerability detection)
- `vdisc_ft`: Qwen3 4B + VDisc LoRA (vulnerability detection)
- `primevul_ft`: Qwen3 4B + PrimeVul LoRA (vulnerability detection)
- `megavul`: Qwen3 4B + MegaVul LoRA (vulnerability detection)

### Baselines
- `codebert`: CodeBERT (BigVul)
- `vulberta`: VulBERTa (VulDeePecker)
- `unixcoder`: UnixCoder (BigVul+PrimeVul)
- `codebert-multi`: CodeBERT (BigVul+PrimeVul)
- `graphcodebert`: GraphCodeBERT (CWE-enriched)

## Using Fine-tuned Models with LoRA Adapters

### Configuration

To use a fine-tuned model with LoRA adapters, configure it in `models_config.json`:

```json
{
  "llms": {
    "your_model_name": {
      "type": "huggingface",
      "model_name": "Qwen/Qwen3-4B-Instruct-2507",
      "adapter_path": "YourHuggingFaceUsername/your-lora-adapter",
      "use_peft": true,
      "description": "Your fine-tuned model description",
      "category": "code-llm",
      "context_length": 8192
    }
  }
}
```

**Important**: Use `adapter_path` (not `adapter_repo`) and set `use_peft: true`.

### How It Works

When you run a model with LoRA configuration:

1. **Base Model Loading**: The framework loads the base model (e.g., `Qwen/Qwen3-4B-Instruct-2507`)
2. **LoRA Adapter Loading**: PEFT loads the LoRA adapter from HuggingFace Hub
3. **Inference**: The model runs with base + LoRA weights (fine-tuned behavior)

### Local vs. Remote Adapters

```json
// Remote adapter (from HuggingFace Hub)
"adapter_path": "Arastoorad/devign_Qwen3_LoRA"

// Local adapter (from filesystem)
"adapter_path": "experiment/finetuning/megavul_adapter"
```

### Example: Running a Fine-tuned Model

```bash
# Evaluate with fine-tuned model
python src/main.py evaluate devign_ft --both-databases

# On SLURM cluster
sbatch --partition=Nebula_GPU --nodelist=str-gpu26 --gres=gpu:2 --time=48:00:00 --mem=100G \
  --wrap="source ~/miniconda/etc/profile.d/conda.sh && conda activate llmserver && \
  cd $(pwd) && python src/main.py evaluate devign_ft --both-databases"
```

## Commands

```bash
# List available models
python src/main.py models --type llms
python src/main.py models --type baselines

# Evaluate specific model
python src/main.py evaluate MODEL_NAME --database DATABASE

# Evaluate on both databases (recommended)
python src/main.py evaluate MODEL_NAME --both-databases

# Job management
python src/main.py list-jobs
python src/main.py status JOB_ID
python src/main.py resume JOB_ID
```

## Cluster Usage

### Using SLURM (Recommended Method)

Submit jobs using the direct wrap method:

```bash
# Single model evaluation
cd /path/to/VulnLLMEval-SANER
sbatch --partition=Nebula_GPU --nodelist=str-gpu26 --gres=gpu:2 --time=48:00:00 --mem=100G \
  --wrap="source /path/to/miniconda/etc/profile.d/conda.sh && conda activate llmserver && \
  cd /path/to/VulnLLMEval-SANER && python src/main.py evaluate MODEL_NAME --both-databases"

# Example: Run devign_ft fine-tuned model
sbatch --partition=Nebula_GPU --nodelist=str-gpu26 --gres=gpu:2 --time=48:00:00 --mem=100G \
  --wrap="source ~/miniconda/etc/profile.d/conda.sh && conda activate llmserver && \
  cd $(pwd) && python src/main.py evaluate devign_ft --both-databases"

# Example: Run qwen3_4b base model
sbatch --partition=Nebula_GPU --nodelist=str-gpu26 --gres=gpu:2 --time=48:00:00 --mem=100G \
  --wrap="source ~/miniconda/etc/profile.d/conda.sh && conda activate llmserver && \
  cd $(pwd) && python src/main.py evaluate qwen3_4b --both-databases"
```

### Monitor Jobs

```bash
# Check job status
squeue -j JOB_ID

# View logs in real-time
tail -f logs/slurm/slurm-JOB_ID.out

# View last 50 lines
tail -n 50 logs/slurm/slurm-JOB_ID.out
```

## Project Structure

```
LLMKernelBench/
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── src/                        # All source code
│   ├── main.py                 # Main CLI entry point
│   ├── configs/
│   │   └── models_config.json  # Model and API configurations
│   ├── data/
│   │   ├── raw/                # Immutable source databases + CWE hierarchy
│   │   └── processed/          # Derived datasets
│   ├── models/                 # LLM and baseline model managers
│   ├── evaluation/             # Evaluation framework
│   ├── scheduler/              # Job scheduling and resume logic
│   ├── utils/                  # Config, database, and logging utilities
│   ├── dataset/                # Dataset building tools
│   └── tests/                  # Unit tests
├── experiments/
│   ├── notebooks/              # Jupyter notebooks for analysis
│   ├── scripts/                # SLURM and shell scripts for cluster runs
│   ├── analysis/               # Standalone analysis and diagnostic scripts
│   └── finetuning/             # LoRA fine-tuning pipeline
├── results/                    # Evaluation outputs and model databases
│   └── logs/slurm/             # SLURM job output logs
└── paper/                      # LaTeX paper source and figures
```

## Requirements

- Python 3.9+
- CUDA-capable GPU (recommended)
- 16GB+ RAM for large models
- API keys for proprietary models

## Troubleshooting

### Common Issues

**1. Model not loading LoRA adapter**
- Ensure `adapter_path` (not `adapter_repo`) is specified in config
- Verify `use_peft: true` is set
- Check that the adapter exists on HuggingFace Hub or local filesystem

**2. SQLite threading errors**
- Use the scheduler (default behavior) instead of `--no-scheduler`
- The scheduler properly handles database connections across tasks

**3. CUDA out of memory**
- Reduce batch size or use a smaller model
- Ensure other processes aren't using GPU memory
- Check GPU allocation with `nvidia-smi`

**4. Job finishes immediately**
- Check SLURM output logs: `tail -f slurm-JOBID.out`
- Verify conda environment activation in job script
- Ensure working directory is set correctly

**5. SLURM job logs location**
- Standard output: `slurm-JOBID.out` (in project root)
- Detailed logs: `results/scheduler/logs/MODEL_DATABASE_TIMESTAMP.log`

### Verifying LoRA Loading

The framework loads LoRA adapters automatically when configured. To verify:

```bash
# Check configuration
python3 -c "
import json
with open('models_config.json') as f:
    config = json.load(f)
    model = config['llms']['YOUR_MODEL_NAME']
    print(f\"use_peft: {model.get('use_peft')}\")
    print(f\"adapter_path: {model.get('adapter_path')}\")
"

# The model loading sequence:
# 1. Loads base model (e.g., Qwen/Qwen3-4B-Instruct-2507)
# 2. Applies LoRA adapter via PEFT
# 3. Runs inference with base + LoRA weights
```

## License

See LICENSE file for details.