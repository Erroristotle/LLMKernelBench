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
python main.py evaluate <model_name> --database database --deepeval
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
   Edit `models_config.json` with your API keys and model preferences.

3. **Set up API keys:**
   Create `utils/.config` with your API keys:
   ```
   gemini_api_key=your_gemini_key_here
   openai_api_key=your_openai_key_here
   ```

4. **Run evaluation:**
   ```bash
   # Test a baseline model
   python main.py evaluate codebert --database database
   
   # Test an LLM
   python main.py evaluate gemini --database database
   
   # Test on both databases
   python main.py evaluate starcoder --both-databases
   ```

## Available Models

### LLMs
- `gemini`: Google Gemini 2.5 Pro
- `deepseek`: DeepSeek-R1 8B 
- `qwen`: Qwen2.5-Coder 32B
- `gpt`: GPT-4o Mini
- `starcoder`: StarCoder2 7B

### Baselines
- `codebert`: CodeBERT (BigVul)
- `vulberta`: VulBERTa (VulDeePecker)
- `unixcoder`: UnixCoder (BigVul+PrimeVul)
- `codebert-multi`: CodeBERT (BigVul+PrimeVul)
- `graphcodebert`: GraphCodeBERT (CWE-enriched)

## Commands

```bash
# List available models
python main.py models --type llms
python main.py models --type baselines

# Evaluate specific model
python main.py evaluate MODEL_NAME --database DATABASE

# Job management
python main.py list-jobs
python main.py status JOB_ID
python main.py resume JOB_ID
```

## Cluster Usage

Submit jobs to SLURM:
```bash
sbatch submit_job.sh MODEL_NAME DATABASE
```

## Project Structure

```
VulnLLMEval-SANER/
├── main.py                 # Main CLI interface
├── models_config.json      # Model configurations
├── requirements.txt        # Python dependencies
├── setup.py               # Package setup
├── submit_job.sh          # SLURM job script
├── data/                  # Databases
│   ├── database.sqlite
│   └── database_leakagefree.sqlite
├── dataset/               # Dataset building tools
├── evaluation/            # Evaluation framework
├── models/                # Model managers
├── scheduler/             # Job scheduling
└── utils/                 # Utilities and configuration
```

## Requirements

- Python 3.9+
- CUDA-capable GPU (recommended)
- 16GB+ RAM for large models
- API keys for proprietary models

## License

See LICENSE file for details.