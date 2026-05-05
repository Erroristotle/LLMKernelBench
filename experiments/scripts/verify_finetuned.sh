#!/bin/bash
# Verify if a model is configured to use fine-tuned LoRA adapter

if [ -z "$1" ]; then
    echo "Usage: ./verify_finetuned.sh MODEL_NAME"
    echo "Example: ./verify_finetuned.sh vdisc_ft"
    echo ""
    echo "Available models:"
    python3 -c "import json; config=json.load(open('src/configs/models_config.json')); print('\n'.join(config['llms'].keys()))"
    exit 1
fi

MODEL_NAME=$1

python3 << PYTHON_EOF
import json
import sys

with open('src/configs/models_config.json', 'r') as f:
    config = json.load(f)

if '$MODEL_NAME' not in config['llms']:
    print(f"❌ ERROR: Model '$MODEL_NAME' not found in configuration")
    sys.exit(1)

model_config = config['llms']['$MODEL_NAME']

print("="*70)
print(f"Model: $MODEL_NAME")
print("="*70)
print(f"Base Model:    {model_config.get('model_name', 'N/A')}")
print(f"Adapter Path:  {model_config.get('adapter_path', 'NOT SET')}")
print(f"Use PEFT:      {model_config.get('use_peft', False)}")
print(f"Description:   {model_config.get('description', 'N/A')}")
print("="*70)

if model_config.get('use_peft') and model_config.get('adapter_path'):
    print("\n✅ FINE-TUNED MODEL")
    print("   This model uses LoRA adapter for fine-tuned behavior")
    print(f"   Base:    {model_config['model_name']}")
    print(f"   Adapter: {model_config['adapter_path']}")
elif model_config.get('adapter_path'):
    print("\n⚠️  WARNING: adapter_path set but use_peft=False")
    print("   The adapter will NOT be loaded!")
else:
    print("\n📝 BASE MODEL")
    print("   This model runs without fine-tuning")
print("="*70)
PYTHON_EOF
