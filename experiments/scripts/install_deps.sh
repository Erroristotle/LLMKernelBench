#!/bin/bash
# Quick dependency installer for VulnLLMEval-SANER
# Focuses on fixing common missing dependencies

echo "🔧 Installing missing dependencies for VulnLLMEval-SANER..."

# Check if we're in the right environment
if [[ "$CONDA_DEFAULT_ENV" != "llmserver" ]]; then
    echo "⚠️  Warning: Not in 'llmserver' conda environment"
    echo "   Consider running: conda activate llmserver"
fi

# Install sentencepiece and protobuf (common issues with Mistral/Llama models)
echo "📦 Installing sentencepiece and protobuf..."
pip install sentencepiece>=0.1.99 protobuf>=3.20.0

# Install or upgrade transformers for better model support
echo "📦 Upgrading transformers..."
pip install --upgrade transformers>=4.30.0

# Install accelerate for GPU optimization
echo "📦 Installing accelerate..."
pip install --upgrade accelerate>=0.20.0

# Verify installations
echo "✅ Verifying installations..."
python -c "import sentencepiece; print(f'sentencepiece: {sentencepiece.__version__}')" 2>/dev/null || echo "❌ sentencepiece failed"
python -c "import transformers; print(f'transformers: {transformers.__version__}')" 2>/dev/null || echo "❌ transformers failed"
python -c "import accelerate; print(f'accelerate: {accelerate.__version__}')" 2>/dev/null || echo "❌ accelerate failed"

echo ""
echo "🎉 Installation complete!"
echo "📋 Now you can run:"
echo "   python main.py evaluate mistral --both-databases"
echo "   or"
echo "   sbatch --partition=GPU --nodelist=str-gpu31 --gres=gpu:1 --time=48:00:00 --mem=100G --wrap=\"source ~/.bashrc && conda activate llmserver && python main.py evaluate mistral --both-databases\""