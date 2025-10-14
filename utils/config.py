"""Configuration settings for the VulnLLMEval project."""

import os
from pathlib import Path
from typing import Dict, Any
import json

# Base paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"
MODELS_DIR = PROJECT_ROOT / "models"
REPO_PATH = os.environ.get("LINUX_KERNEL_PATH", "")

# Database settings
DB_PATH = DATA_DIR / "database_leakagefree.sqlite"
CSV_PATH = DATA_DIR / "linux_100.csv"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

# LLM configurations
LLM_CONFIGS = {
    "codellama-7b-instruct": {"command": "ollama run codellama:7b-instruct", "api_param": "codellama:7b-instruct"},
    "codellama-13b-instruct": {"command": "ollama run codellama:13b-instruct", "api_param": "codellama:13b-instruct"},
    "llama3.1-8b": {"command": "ollama run llama3.1", "api_param": "llama3.1"},
    "llama3.1-70b": {"command": "ollama run llama3.1:70b", "api_param": "llama3.1:70b"},
    "llama3-8b-instruct": {"command": "ollama run llama3:instruct", "api_param": "llama3:instruct"},
    "llama3-70b-instruct": {"command": "ollama run llama3:70b-instruct", "api_param": "llama3:70b-instruct"},
    "gemma2-9b": {"command": "ollama run gemma2:9b", "api_param": "gemma2:9b"},
    "gemma2-27b": {"command": "ollama run gemma2:27b", "api_param": "gemma2:27b"},
    "mistral-7b-instruct": {"command": "ollama run mistral:instruct", "api_param": "mistral:instruct"},
    "mixtral-8M7b-instruct": {"command": "ollama run mixtral:instruct", "api_param": "mixtral:instruct"}
}

# API settings
API_URL = "http://localhost:11434/api/generate"

def get_model_db_path(model_name: str) -> Path:
    """Get the database path for a specific model."""
    return OUTPUT_DIR / f"database_{model_name}.sqlite"

def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from a JSON file if provided, otherwise use defaults."""
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {
        "db_path": str(DB_PATH),
        "csv_path": str(CSV_PATH),
        "output_dir": str(OUTPUT_DIR),
        "repo_path": REPO_PATH,
        "api_url": API_URL,
    }

def update_config(config: Dict[str, Any], config_path: str) -> None:
    """Update and save configuration to a JSON file."""
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4) 