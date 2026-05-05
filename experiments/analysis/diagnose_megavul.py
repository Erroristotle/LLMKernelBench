#!/usr/bin/env python3
"""Diagnose Megavul LoRA adapter compatibility issues."""

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

base_model_name = "Qwen/Qwen3-4B-Instruct-2507"
adapter_path = "finetuning/megavul_adapter"

logger.info("Loading base model...")
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_name,
    torch_dtype=torch.bfloat16,
    device_map="auto",
    trust_remote_code=True,
)

logger.info("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(
    base_model_name,
    trust_remote_code=True,
)

# Configure tokenizer
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "left"

# Check sizes BEFORE loading adapter
base_vocab_size = base_model.get_input_embeddings().num_embeddings
tokenizer_vocab_size = len(tokenizer)
logger.info(f"Base model vocab size: {base_vocab_size}")
logger.info(f"Tokenizer vocab size: {tokenizer_vocab_size}")
logger.info(f"Tokenizer eos_token_id: {tokenizer.eos_token_id}")
logger.info(f"Tokenizer pad_token_id: {tokenizer.pad_token_id}")
logger.info(f"Tokenizer bos_token_id: {tokenizer.bos_token_id}")

logger.info(f"\nLoading PEFT adapter from: {adapter_path}")
model = PeftModel.from_pretrained(base_model, adapter_path)

# Check sizes AFTER loading adapter
adapter_vocab_size = model.get_base_model().get_input_embeddings().num_embeddings
logger.info(f"Model vocab size after adapter: {adapter_vocab_size}")

# Test tokenization
test_prompt = "Is this code vulnerable? YES or NO"
logger.info(f"\nTest prompt: {test_prompt}")

tokenized = tokenizer(
    test_prompt,
    return_tensors='pt',
    padding=True,
    truncation=True,
    max_length=512,
    return_attention_mask=True
)

input_ids = tokenized['input_ids']
logger.info(f"Input IDs: {input_ids}")
logger.info(f"Input IDs shape: {input_ids.shape}")
logger.info(f"Min token ID: {input_ids.min().item()}")
logger.info(f"Max token ID: {input_ids.max().item()}")

# Check if any token IDs exceed vocab size
if input_ids.max().item() >= adapter_vocab_size:
    logger.error(f"TOKEN ID EXCEEDS VOCAB SIZE! Max token {input_ids.max().item()} >= vocab size {adapter_vocab_size}")
else:
    logger.info(f"Token IDs are valid (max {input_ids.max().item()} < vocab {adapter_vocab_size})")

# Try generation with debugging
logger.info("\nAttempting generation...")
model.eval()
input_ids = input_ids.to(model.device)
attention_mask = tokenized['attention_mask'].to(model.device)

try:
    with torch.no_grad():
        outputs = model.generate(
            input_ids,
            attention_mask=attention_mask,
            max_new_tokens=10,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
            do_sample=False,  # Greedy decoding for testing
        )

    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    logger.info(f"SUCCESS! Generated: {generated_text}")

except Exception as e:
    logger.error(f"Generation failed: {e}")
    import traceback
    traceback.print_exc()
