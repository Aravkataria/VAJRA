# scripts/colab_one_click_quantize.py
"""
1-Click Google Colab / Kaggle Free Quantization Script.
Copy & paste this into a free Google Colab notebook (T4 GPU runtime).
Takes ~4 minutes total. 100% Free. Uses 0 MB of your home internet data.
"""

COLAB_INSTRUCTIONS = """
# ==============================================================================
# 🚀 1-CLICK VAJRA GGUF QUANTIZATION IN GOOGLE COLAB (FREE T4 GPU)
# ==============================================================================
# Instructions:
# 1. Open https://colab.research.google.com/
# 2. Click "New notebook".
# 3. Go to "Runtime" -> "Change runtime type" -> Select "T4 GPU" (Free).
# 4. Copy and paste the cell below, then press Shift + Enter:
# ==============================================================================

!pip install -q transformers peft torch accelerate huggingface_hub

import os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# Step 1: Define models
BASE_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
LORA_MODEL = "AravKataria/vajra-lora"
MERGED_DIR = "./vajra_merged_7b"

print("🔒 Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
tokenizer.save_pretrained(MERGED_DIR)

print("🔒 Loading base model in float16...")
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    torch_dtype=torch.float16,
    device_map="auto",
    low_cpu_mem_usage=True,
    trust_remote_code=True
)

print("🔒 Merging fine-tuned LoRA weights...")
model = PeftModel.from_pretrained(base_model, LORA_MODEL)
merged = model.merge_and_unload()
merged.save_pretrained(MERGED_DIR)
print("✅ LoRA weights successfully merged!")

# Free memory before llama.cpp build
del base_model, model, merged
import gc; gc.collect(); torch.cuda.empty_cache()

# Step 2: Build llama.cpp
print("⚙️ Building llama.cpp tools...")
!git clone https://github.com/ggerganov/llama.cpp.git
!cd llama.cpp && cmake -B build && cmake --build build --config Release -j4

# Step 3: Convert to unquantized GGUF
print("📦 Converting to GGUF format...")
!python llama.cpp/convert_hf_to_gguf.py {MERGED_DIR} --outtype f16 --outfile vajra-7b-f16.gguf

# Step 4: Quantize to Q4_K_M (4.3 GB)
print("⚡ Quantizing to Q4_K_M (4.3 GB — Best Quality/Speed)...")
!./llama.cpp/build/bin/llama-quantize vajra-7b-f16.gguf vajra-coder-7b-Q4_K_M.gguf Q4_K_M

# Step 5: (Optional) Upload to Hugging Face Hub directly
print("🎉 Quantization Complete! Files ready in Colab:")
!ls -lh vajra-coder-7b-Q4_K_M.gguf
"""

if __name__ == "__main__":
    print(COLAB_INSTRUCTIONS)
